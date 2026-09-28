# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""BrainFlow adapter (WP-026): synthetic, playback-file and streaming boards.

- Phase A: ``SYNTHETIC_BOARD`` — no hardware at all.
- Phase B: ``PLAYBACK_FILE_BOARD`` — replays a file written by
  :func:`record_to_file` (BrainFlow CSV), for deterministic replays.
- Phase C: ``STREAMING_BOARD`` — receives what another BrainFlow session
  streams via multicast (``add_streamer``).

Data become :class:`SampleBlock` objects: BrainFlow's timestamp channel
(Unix seconds) becomes integer nanoseconds. The package counter (0-255,
wrapping) gives a transport-independent dropped-sample count. Channels with
an unknown physical scale are kept dimensionless (``1``) rather than
guessing units.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import numpy as np
from brainflow.board_shim import BoardIds, BoardShim, BrainFlowInputParams, BrainFlowPresets
from brainflow.data_filter import DataFilter
from numpy.typing import NDArray

from esp.adapters.physio.stream import ChannelSpec, SampleBlock
from esp.observation.model import DeviceMetadata, Modality

#: (BoardShim getter, modality, unit, prefix). First getter wins for shared rows.
_KINDS = (
    ("get_eeg_channels", Modality.EEG, "uV", "eeg"),
    ("get_accel_channels", Modality.MOTION, "g0", "accel"),
    ("get_gyro_channels", Modality.MOTION, "1", "gyro"),
    ("get_eda_channels", Modality.EDA, "1", "eda"),
    ("get_ppg_channels", Modality.PPG, "1", "ppg"),
    ("get_temperature_channels", Modality.TEMPERATURE, "degC", "temp"),
)


def _rows(board_id: int, getter: str, preset: int) -> list[int]:
    try:
        rows: list[int] = getattr(BoardShim, getter)(board_id, preset)
    except Exception:
        return []
    return rows


@dataclass(frozen=True, slots=True)
class BoardLayout:
    board_id: int
    rate_hz: float
    rows: tuple[int, ...]
    channels: tuple[ChannelSpec, ...]
    timestamp_row: int
    package_row: int
    marker_row: int | None


def layout(board_id: int, preset: int = BrainFlowPresets.DEFAULT_PRESET) -> BoardLayout:
    BoardShim.disable_board_logger()
    used: set[int] = set()
    rows, specs = [], []
    for getter, modality, unit, prefix in _KINDS:
        for k, r in enumerate(_rows(board_id, getter, preset)):
            if r in used:
                continue
            used.add(r)
            rows.append(r)
            specs.append(ChannelSpec(f"{prefix}{k + 1}", modality, unit))
    try:
        marker: int | None = BoardShim.get_marker_channel(board_id, preset)
    except Exception:
        marker = None
    return BoardLayout(
        board_id=board_id,
        rate_hz=float(BoardShim.get_sampling_rate(board_id, preset)),
        rows=tuple(rows),
        channels=tuple(specs),
        timestamp_row=BoardShim.get_timestamp_channel(board_id, preset),
        package_row=BoardShim.get_package_num_channel(board_id, preset),
        marker_row=marker,
    )


def dropped_from_counter(counter: NDArray[np.float64], modulo: int = 256) -> int:
    """Samples missing according to a wrapping package counter."""
    if counter.size < 2:
        return 0
    steps = np.mod(np.diff(counter.astype(np.int64)), modulo)
    return int(np.sum(np.where(steps == 0, modulo, steps) - 1))


class BrainFlowSource:
    """Pull-based BrainFlow session producing sample blocks."""

    def __init__(
        self,
        board_id: int = BoardIds.SYNTHETIC_BOARD,
        params: BrainFlowInputParams | None = None,
        *,
        layout_board: int | None = None,
        device_id: str = "brainflow-1",
    ) -> None:
        self._params = params or BrainFlowInputParams()
        self._board = BoardShim(board_id, self._params)
        # playback/streaming boards describe their data with the master board's layout
        self.layout = layout(layout_board if layout_board is not None else board_id)
        self._device = DeviceMetadata(
            device_id=device_id,
            kind=f"brainflow-board-{board_id}",
            sampling_rate_hz=self.layout.rate_hz,
            synthetic=board_id == BoardIds.SYNTHETIC_BOARD,
        )
        self.dropped = 0
        self._last_counter: float | None = None
        self.markers: list[tuple[int, float]] = []

    def start(self, buffer_samples: int = 45000) -> None:
        self._board.prepare_session()
        self._board.start_stream(buffer_samples)

    def add_streamer(self, url: str) -> None:
        """Phase C source side: e.g. ``streaming_board://225.1.1.1:6677``."""
        self._board.add_streamer(url)

    def insert_marker(self, value: float) -> None:
        self._board.insert_marker(value)

    def poll(self) -> SampleBlock | None:
        block, _ = self.poll_with_raw()
        return block

    def poll_with_raw(self) -> tuple[SampleBlock | None, NDArray[np.float64]]:
        """Also return the raw board matrix (rows x samples), e.g. for :func:`record_to_file`."""
        data = self._board.get_board_data()
        if data.shape[1] == 0:
            return None, data
        return self._to_block(data), data

    def stop(self) -> None:
        if self._board.is_prepared():
            self._board.stop_stream()
            self._board.release_session()

    def _to_block(self, data: NDArray[np.float64]) -> SampleBlock:
        lay = self.layout
        counter = data[lay.package_row]
        if self._last_counter is not None:
            counter = np.concatenate([[self._last_counter], counter])
        self.dropped += dropped_from_counter(counter)
        self._last_counter = float(data[lay.package_row, -1])
        ts = np.round(data[lay.timestamp_row] * 1e9).astype(np.int64)
        if lay.marker_row is not None:
            m = data[lay.marker_row]
            self.markers.extend((int(ts[i]), float(m[i])) for i in np.nonzero(m)[0])
        return SampleBlock(
            stream=f"brainflow-{lay.board_id}",
            channels=lay.channels,
            timestamps_ns=ts,
            values=np.ascontiguousarray(data[list(lay.rows)].T),
            device=self._device,
            clock_domain="unix",
            nominal_rate_hz=lay.rate_hz,
        )


def record_to_file(data: NDArray[np.float64], path: Path) -> None:
    """Write raw board data (rows x samples) as a BrainFlow playback file."""
    DataFilter.write_file(np.ascontiguousarray(data), str(path), "w")


def playback_params(
    path: Path, master_board: int = BoardIds.SYNTHETIC_BOARD
) -> BrainFlowInputParams:
    p = BrainFlowInputParams()
    p.file = str(path)
    p.master_board = master_board
    return p


def streaming_params(
    ip: str = "225.1.1.1", port: int = 6677, master_board: int = BoardIds.SYNTHETIC_BOARD
) -> BrainFlowInputParams:
    p = BrainFlowInputParams()
    p.ip_address = ip
    p.ip_port = port
    p.master_board = master_board
    return p
