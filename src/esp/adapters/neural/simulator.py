# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Simulator for the neural adapter contract (WP-045).

:class:`SimulatedNeuralAdapter` emits deterministic, EEG-like synthetic
voltages (background noise plus a 10 Hz rhythm) on the regular integer
nanosecond grid. :class:`SimulatorDecoder` is a fixed random projection that
stands in for a vendor ``f_decode``. Neither is a model of any brain. They only
exercise the interfaces.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from typing import Final

import numpy as np
from numpy.typing import NDArray

from esp.adapters.neural.interface import NeuralAdapterInfo, NeuralFeatures, NeuralLevel
from esp.adapters.physio.stream import ChannelSpec, SampleBlock, regular_timestamps
from esp.core.provenance import Provenance, SourceKind
from esp.core.taoss_types import L1_DIMS, TaossType
from esp.features.physio import welch_psd
from esp.observation.model import DeviceMetadata, Modality

BANDS: Final = {
    "delta": (1.0, 4.0),
    "theta": (4.0, 8.0),
    "alpha": (8.0, 13.0),
    "beta": (13.0, 30.0),
}
_CHANNELS: Final = ("fz", "cz", "pz", "oz", "f3", "f4", "p3", "p4", "c3", "c4", "o1", "o2")


class SimulatedNeuralAdapter:
    """Deterministic synthetic non-invasive (L3) neural source."""

    def __init__(
        self,
        seed: int = 0,
        *,
        n_channels: int = 8,
        rate_hz: float = 256.0,
        total_samples: int | None = None,
        start_ns: int = 0,
    ) -> None:
        if not 1 <= n_channels <= len(_CHANNELS):
            msg = f"n_channels must be 1..{len(_CHANNELS)}"
            raise ValueError(msg)
        self._seed = seed
        self._rate = rate_hz
        self._total = total_samples
        self._start_ns = start_ns
        self._info = NeuralAdapterInfo(
            adapter_id=f"esp-neural-sim-{seed}",
            device=DeviceMetadata(
                device_id=f"sim-neural-{seed}",
                kind="neural-simulator",
                sampling_rate_hz=rate_hz,
                synthetic=True,
            ),
            channels=tuple(ChannelSpec(c, Modality.EEG, "uV") for c in _CHANNELS[:n_channels]),
            nominal_rate_hz=rate_hz,
            level=NeuralLevel.L3_NON_INVASIVE,
            clock_domain=f"sim-neural-{seed}:mono",
        )
        rng = np.random.default_rng(seed)
        self._phase = rng.uniform(0, 2 * np.pi, n_channels)
        self._amp = rng.uniform(5.0, 15.0, n_channels)
        self._rng = rng
        self._pos = 0
        self._running = False

    @property
    def info(self) -> NeuralAdapterInfo:
        return self._info

    def start(self) -> None:
        self._running = True

    def stop(self) -> None:
        self._running = False

    def read(self, max_samples: int) -> SampleBlock | None:
        if not self._running:
            msg = "adapter not started"
            raise RuntimeError(msg)
        n = max_samples if self._total is None else min(max_samples, self._total - self._pos)
        if n <= 0:
            return None
        idx = np.arange(self._pos, self._pos + n, dtype=np.float64)
        t = idx / self._rate
        rhythm = self._amp[None, :] * np.sin(2 * np.pi * 10.0 * t[:, None] + self._phase[None, :])
        noise = self._rng.standard_normal((n, len(self._phase))) * 4.0
        block = SampleBlock(
            stream=self._info.adapter_id,
            channels=self._info.channels,
            timestamps_ns=regular_timestamps(
                self._start_ns + round(self._pos * 1e9 / self._rate), n, self._rate
            ),
            values=rhythm + noise,
            device=self._info.device,
            clock_domain=self._info.clock_domain,
            nominal_rate_hz=self._rate,
        )
        self._pos += n
        return block


def band_features(
    block: SampleBlock, bands: Mapping[str, tuple[float, float]] = BANDS
) -> NeuralFeatures:
    """Log band powers per channel: neutral features named ``<channel>.<band>``."""
    if not block.nominal_rate_hz:
        msg = "band features need a nominal rate"
        raise ValueError(msg)
    fs = block.nominal_rate_hz
    names: list[str] = []
    values: list[float] = []
    for i, c in enumerate(block.channels):
        freqs, psd = welch_psd(block.values[:, i], fs)
        for band, (lo, hi) in bands.items():
            sel = (freqs >= lo) & (freqs < hi)
            power = float(np.trapezoid(psd[sel], freqs[sel])) if sel.sum() > 1 else 0.0
            names.append(f"{c.name}.{band}")
            values.append(float(np.log10(power + 1e-12)))
    ts = block.timestamps_ns
    return NeuralFeatures(
        names=tuple(names),
        values=np.array(values),
        window_start_ns=int(ts[0]),
        window_end_ns=int(ts[-1]) + round(1e9 / fs),
        provenance=Provenance(
            source_kind=SourceKind.DERIVED,
            producer_id="esp-neural-band-features",
            producer_version="0.1.0",
            source_refs=(f"stream:{block.stream}:{int(ts[0])}-{int(ts[-1])}",),
        ),
    )


class SimulatorDecoder:
    """A fixed random projection standing in for a vendor ``f_decode``.

    It declares SEN and TEM by default. Declaring EMO or INT is possible for
    contract tests, but consent decides what is ever requested
    (:func:`~esp.adapters.neural.interface.decode_boundary`).
    """

    decoder_id = "esp-neural-sim-projection@0.1.0"

    def __init__(
        self,
        n_features: int,
        output_types: Sequence[TaossType] = (TaossType.SEN, TaossType.TEM),
        seed: int = 0,
    ) -> None:
        self._types = frozenset(output_types)
        self._w: dict[TaossType, NDArray[np.float64]] = {}
        for t in sorted(self._types):
            s = int.from_bytes(
                hashlib.blake2b(f"{seed}:{t.name}".encode(), digest_size=8).digest(), "big"
            )
            self._w[t] = np.random.default_rng(s).standard_normal(
                (L1_DIMS[t], n_features)
            ) / np.sqrt(n_features)

    @property
    def output_types(self) -> frozenset[TaossType]:
        return self._types

    def decode(
        self, features: NeuralFeatures, types: frozenset[TaossType]
    ) -> dict[TaossType, NDArray[np.float64]]:
        x = features.values - features.values.mean()
        return {t: np.tanh(self._w[t] @ x) for t in types if t in self._types}
