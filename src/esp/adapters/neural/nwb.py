# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""NWB (Neurodata Without Borders) replay adapters (M18, WP-087).

A recorded NWB session, local or streamed from DANDI over HTTP range
requests, becomes a :class:`~esp.adapters.neural.interface.NeuralAdapter` that
satisfies exactly the contract a live device would:

- :func:`electrical_series_adapter`: ``ElectricalSeries`` (ECoG, sEEG, LFP).
  Samples are ``data * conversion + offset`` in the series unit, converted to
  the requested voltage unit. The electrodes table becomes
  :class:`~esp.adapters.neural.model.ElectrodeSpec` entries (location, group,
  coordinates, bad flag).
- :func:`timeseries_adapter`: any ``TimeSeries``, for example FALCON H2's
  pre-binned spike counts, FALCON H1 kinematics, or AJILE12 pose.
- :func:`units_binned_adapter`: sorted units or threshold crossings from the
  ``Units`` table, binned into spike counts. Bins are labelled by their **end**
  time and are half-open ``[end - width, end)``; the last bin is closed. This is
  the ``np.histogram`` convention of the FALCON benchmark loaders. Counts depend
  only on the absolute bin index, so chunking never changes the stream.
- :func:`read_events`: trials, epochs and intervals as an
  :class:`~esp.adapters.physio.stream.EventBlock`.

Timestamps are session-relative nanoseconds in one clock domain per file.
Spikes, kinematics and events of the same session therefore line up.

Invasive modalities are declared under ``L4-REPLAY``. The replay declaration is
built from the dataset's ``MANIFEST.json`` (written by
``scripts/fetch_dandi.py``) or passed explicitly for streamed assets.

Dataset quirks are handled explicitly, never guessed. FALCON H1 (DANDI 000954)
stores its 20 ms bin *width* in the NWB ``rate`` field, so
:data:`DATASET_PROFILES` marks that dataset with ``rate_is_period``.
"""

from __future__ import annotations

import urllib.request
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

import numpy as np

from esp.adapters.neural.interface import NeuralAdapterInfo, NeuralLevel
from esp.adapters.neural.model import (
    AUXILIARY,
    INVASIVE,
    NON_INVASIVE,
    ElectrodeSpec,
    ElectrodeStatus,
    NeuralDeviceDescriptor,
    ProcessingStep,
    ReplayDeclaration,
)
from esp.adapters.neural.replay import (
    F64,
    I64,
    ReplayError,
    WindowReplay,
    declaration_from_manifest,
    find_manifest,
    pseudonymous_id,
    seconds_to_ns,
    unit_scale,
)
from esp.adapters.physio.stream import ChannelSpec, EventBlock, normalize_channel
from esp.observation.model import DeviceMetadata, Modality

#: NWB unit strings -> ESP unit registry symbols (anything else is refused).
NWB_UNITS: Final = {
    "volts": "V",
    "volt": "V",
    "v": "V",
    "mv": "mV",
    "millivolts": "mV",
    "uv": "uV",
    "microvolts": "uV",
    "µv": "uV",
    "arbitrary": "1",
    "a.u.": "1",
    "n.a.": "1",
    "no unit": "1",
    "bool": "1",
    "int": "count",
    "count": "count",
    "counts": "count",
    "spikes": "count",
    "pixels": "px",
    "px": "px",
    "m": "m",
    "meters": "m",
    "mm": "mm",
    "s": "s",
    "seconds": "s",
}
API: Final = "https://api.dandiarchive.org/api"


@dataclass(frozen=True, slots=True)
class DatasetProfile:
    dandiset: str
    device_kind: str
    rate_is_period: bool = False
    """The file's ``rate`` field holds the sample *period* (dataset quirk)."""


DATASET_PROFILES: Final = {
    "000954": DatasetProfile("000954", "intracortical-arrays-recording", rate_is_period=True),
    "000950": DatasetProfile("000950", "intracortical-arrays-recording"),
    "000019": DatasetProfile("000019", "ecog-grid-recording"),
    "000055": DatasetProfile("000055", "ecog-recording"),
}


def nwb_unit(raw: str) -> str:
    try:
        return NWB_UNITS[raw.strip().lower()]
    except KeyError:
        msg = f"unsupported NWB unit {raw!r}"
        raise ReplayError(msg) from None


def dandi_asset_url(asset_id: str) -> str:
    """Resolve a DANDI asset to its direct storage URL (for HTTP range streaming)."""
    url = f"{API}/assets/{asset_id}/download/"
    req = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "esp-taoss/1"})  # noqa: S310
    with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 - fixed https API
        final: str = r.geturl()
    if not final.startswith("https://"):
        msg = "asset did not resolve to an https URL"
        raise ReplayError(msg)
    return final


class NwbFile:
    """An open NWB file, local or streamed. Close it (or stop the adapter) when done."""

    def __init__(self, source: Path | str, *, dandiset: str | None = None) -> None:
        import h5py  # noqa: PLC0415 - optional dependency (extra "neural")
        import pynwb  # noqa: PLC0415

        self.source = str(source)
        self._h5: Any = None
        self._remote: Any = None
        if isinstance(source, str) and source.startswith("https://"):
            import remfile  # noqa: PLC0415

            self._remote = remfile.File(source)
            self._h5 = h5py.File(self._remote, "r")
            self._io = pynwb.NWBHDF5IO(file=self._h5, mode="r", load_namespaces=True)
            self.path: Path | None = None
        elif isinstance(source, str) and "://" in source:
            msg = "only https sources can be streamed"
            raise ReplayError(msg)
        else:
            self.path = Path(source)
            if self.path.suffix == ".part" or not self.path.is_file():
                msg = f"not a complete NWB file: {self.path}"
                raise ReplayError(msg)
            self._io = pynwb.NWBHDF5IO(str(self.path), mode="r", load_namespaces=True)
        self.nwb: Any = self._io.read()
        manifest = find_manifest(self.path) if self.path is not None else None
        self.replay: ReplayDeclaration | None = (
            declaration_from_manifest(manifest) if manifest is not None else None
        )
        tag = dandiset or (self.replay.dataset_id.split(":")[-1] if self.replay else None)
        self.profile = DATASET_PROFILES.get(tag or "")
        self.dataset_tag = tag or "nwb"
        self.session_key = pseudonymous_id(self.dataset_tag, str(self.nwb.identifier))
        self.clock_domain = f"replay:{self.dataset_tag}:{self.session_key}"

    def close(self) -> None:
        self._io.close()
        if self._h5 is not None:
            self._h5.close()
        if self._remote is not None:
            self._remote.close()

    def __enter__(self) -> NwbFile:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def series(self, name: str) -> Any:  # noqa: ANN401 - pynwb object
        """``acquisition`` name, or ``module/interface[/series]`` in ``processing``."""
        if name in self.nwb.acquisition:
            return self.nwb.acquisition[name]
        parts = name.split("/")
        if len(parts) >= 2 and parts[0] in self.nwb.processing:
            obj: Any = self.nwb.processing[parts[0]][parts[1]]
            for p in parts[2:]:
                obj = obj[p]
            return obj
        msg = f"no series {name!r}"
        raise ReplayError(msg)


# --- time axes -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class TimeAxis:
    """Sample times of one series, kept in the producer's own float definition.

    Bin edges and spike assignment use :meth:`seconds` exactly as the file (or
    its reference loader) defines them. A spike that lies on a boundary is then
    assigned to the same bin as in the reference pipeline. Only the emitted
    timestamps are rounded to integer nanoseconds.
    """

    n: int
    start_s: float
    rate_hz: float
    times_s: F64 | None = None
    """Explicit per-sample timestamps (seconds) from the file."""
    period_s: float | None = None
    """Set when the file defines the grid by a period (``start + i * period``)."""

    def seconds(self) -> F64:
        if self.times_s is not None:
            return self.times_s
        i = np.arange(self.n, dtype=np.float64)
        if self.period_s is not None:
            out: F64 = self.start_s + i * self.period_s
            return out
        grid: F64 = self.start_s + i / self.rate_hz  # pynwb TimeSeries.get_timestamps()
        return grid

    def ns(self, lo: int, hi: int) -> I64:
        if self.times_s is not None:
            return seconds_to_ns(self.times_s[lo:hi])
        grid: I64 = round(self.start_s * 1e9) + np.round(
            np.arange(lo, hi, dtype=np.float64) * (1e9 / self.rate_hz)
        ).astype(np.int64)
        return grid


def time_axis(f: NwbFile, ts: Any) -> TimeAxis:  # noqa: ANN401 - pynwb object
    n = int(ts.data.shape[0])
    if ts.timestamps is not None:
        t = np.asarray(ts.timestamps[:], dtype=np.float64)
        if t.shape != (n,):
            msg = "timestamps do not match the data length"
            raise ReplayError(msg)
        t_ns = seconds_to_ns(t)
        if n > 1 and bool((np.diff(t_ns) <= 0).any()):
            msg = "timestamps are not strictly increasing"
            raise ReplayError(msg)
        rate = 1.0 / float(np.median(np.diff(t))) if n > 1 else 1.0
        return TimeAxis(n, float(t[0]) if n else 0.0, rate, times_s=t)
    rate = float(ts.rate or 0.0)
    start = float(ts.starting_time or 0.0)
    if f.profile is not None and f.profile.rate_is_period and 0 < rate < 1:
        return TimeAxis(n, start, 1.0 / rate, period_s=rate)
    if not rate > 0:
        msg = f"series {ts.name!r} has no usable rate"
        raise ReplayError(msg)
    return TimeAxis(n, start, rate)


# --- adapters ------------------------------------------------------------------------------------


def _level_and_replay(
    modality: Modality, replay: ReplayDeclaration | None
) -> tuple[NeuralLevel, ReplayDeclaration | None]:
    if modality in NON_INVASIVE:
        return NeuralLevel.L3_NON_INVASIVE, None
    if modality in INVASIVE | AUXILIARY:
        return NeuralLevel.L4_INVASIVE, replay
    msg = f"{modality} is not a neural or auxiliary modality"
    raise ReplayError(msg)


def _info(
    f: NwbFile,
    *,
    adapter_id: str,
    stream: str,
    modality: Modality,
    unit: str,
    channels: Sequence[str],
    electrodes: Sequence[ElectrodeSpec],
    axis: TimeAxis,
    binned: bool,
    replay: ReplayDeclaration | None,
    processing: Sequence[ProcessingStep] = (),
) -> NeuralAdapterInfo:
    level, decl = _level_and_replay(modality, replay if replay is not None else f.replay)
    device_id = f"replay-{f.dataset_tag}-{pseudonymous_id(f.session_key, stream)}"
    kind = f.profile.device_kind if f.profile is not None else "nwb-recording"
    specs = tuple(ChannelSpec(c, modality, unit) for c in channels)
    descriptor = NeuralDeviceDescriptor(
        manufacturer="unspecified (recording)",
        model=kind,
        firmware="n/a (replay)",
        device_id=device_id,
        modalities=frozenset({modality}),
        electrodes=tuple(electrodes),
        unit=unit,
        clock_domain=f.clock_domain,
        sampling_rate_hz=None if binned else axis.rate_hz,
        bin_width_s=(1.0 / axis.rate_hz) if binned else None,
        processing=tuple(processing),
    )
    return NeuralAdapterInfo(
        adapter_id=adapter_id,
        device=DeviceMetadata(device_id=device_id, kind=kind, sampling_rate_hz=axis.rate_hz),
        channels=specs,
        nominal_rate_hz=axis.rate_hz,
        level=level,
        clock_domain=f.clock_domain,
        descriptor=descriptor,
        replay=decl,
    )


def _unique(names: Sequence[str]) -> list[str]:
    seen: dict[str, int] = {}
    out = []
    for n in names:
        k = seen.get(n, 0)
        seen[n] = k + 1
        out.append(n if k == 0 else f"{n}_{k}")
    return out


class SeriesReplay(WindowReplay):
    """Lazy replay of a 1-D or 2-D NWB series (optionally a channel subset)."""

    def __init__(
        self,
        info: NeuralAdapterInfo,
        stream: str,
        data: Any,  # noqa: ANN401 - h5py dataset
        axis: TimeAxis,
        *,
        columns: Sequence[int] | None,
        conversion: float,
        offset: float,
        unit_factor: float,
        on_stop: Any = None,  # noqa: ANN401
    ) -> None:
        super().__init__(info, stream, axis.n, on_stop)
        self._data, self._axis = data, axis
        self._conversion, self._offset, self._unit_factor = conversion, offset, unit_factor
        self._columns = None if columns is None else list(columns)

    def _values(self, lo: int, hi: int) -> F64:
        """NWB semantics ``data * conversion + offset`` (series unit), then the unit factor."""
        raw = self._data[lo:hi] if self._columns is None else self._data[lo:hi, self._columns]
        arr = np.asarray(raw, dtype=np.float64)
        if arr.ndim == 1:
            arr = arr[:, None]
        out: F64 = (arr * self._conversion + self._offset) * self._unit_factor
        return out

    def _timestamps(self, lo: int, hi: int) -> I64:
        return self._axis.ns(lo, hi)


def _electrode_specs(es: Any, rows: Sequence[int]) -> list[ElectrodeSpec]:  # noqa: ANN401
    table = es.electrodes.table
    cols = set(table.colnames)
    ids = np.asarray(table.id[:])
    out = []
    for r in rows:
        label = str(table["label"][r]) if "label" in cols else f"e{int(ids[r]):03d}"

        def num(col: str, r: int = r) -> float | None:
            if col not in cols:
                return None
            v = float(table[col][r])
            return None if np.isnan(v) else v

        bad = bool(table["bad"][r]) if "bad" in cols else None
        out.append(
            ElectrodeSpec(
                name=normalize_channel(label),
                group=str(table["group_name"][r]) if "group_name" in cols else "",
                location=str(table["location"][r]) if "location" in cols else "",
                x_mm=num("x"),
                y_mm=num("y"),
                z_mm=num("z"),
                status=ElectrodeStatus.UNKNOWN
                if bad is None
                else (ElectrodeStatus.BAD if bad else ElectrodeStatus.GOOD),
            )
        )
    return out


def electrical_series_adapter(
    f: NwbFile,
    name: str = "ElectricalSeries",
    *,
    modality: Modality = Modality.ECOG,
    unit: str = "uV",
    channels: Sequence[int] | None = None,
    replay: ReplayDeclaration | None = None,
    close_on_stop: bool = False,
) -> SeriesReplay:
    """ECoG/sEEG/LFP voltages in ``unit`` (``data * conversion + offset``, then unit scale)."""
    es = f.series(name)
    if es.data.ndim != 2:
        msg = "an ElectricalSeries must be (samples, channels)"
        raise ReplayError(msg)
    n_ch = int(es.data.shape[1])
    cols = list(range(n_ch)) if channels is None else sorted(set(channels))
    if not cols or cols[0] < 0 or cols[-1] >= n_ch:
        msg = "channel selection out of range"
        raise ReplayError(msg)
    rows = [int(i) for i in np.asarray(es.electrodes.data[:])[cols]]
    electrodes = _electrode_specs(es, rows)
    names = _unique([e.name for e in electrodes])
    electrodes = [
        ElectrodeSpec(n, e.group, e.location, e.x_mm, e.y_mm, e.z_mm, e.status)
        for n, e in zip(names, electrodes, strict=True)
    ]
    factor = unit_scale(nwb_unit(str(es.unit)), unit)
    axis = time_axis(f, es)
    info = _info(
        f,
        adapter_id=f"nwb:{name}",
        stream=name,
        modality=modality,
        unit=unit,
        channels=names,
        electrodes=electrodes,
        axis=axis,
        binned=False,
        replay=replay,
        processing=(ProcessingStep("conversion", (("factor", repr(float(es.conversion))),)),),
    )
    return SeriesReplay(
        info,
        name,
        es.data,
        axis,
        columns=None if channels is None else cols,
        conversion=float(es.conversion),
        offset=float(getattr(es, "offset", 0.0) or 0.0),
        unit_factor=factor,
        on_stop=f.close if close_on_stop else None,
    )


def timeseries_adapter(
    f: NwbFile,
    name: str,
    *,
    modality: Modality,
    unit: str | None = None,
    channel_prefix: str | None = None,
    replay: ReplayDeclaration | None = None,
    close_on_stop: bool = False,
) -> SeriesReplay:
    """Any ``TimeSeries`` (pre-binned spike counts, kinematics, pose, masks)."""
    ts = f.series(name)
    if ts.data.ndim not in (1, 2):
        msg = "only 1-D or 2-D series are supported"
        raise ReplayError(msg)
    n_ch = 1 if ts.data.ndim == 1 else int(ts.data.shape[1])
    src_unit = nwb_unit(str(ts.unit))
    dst_unit = unit or src_unit
    factor = unit_scale(src_unit, dst_unit)
    prefix = normalize_channel(channel_prefix or name.rsplit("/", 1)[-1])
    names = [prefix] if n_ch == 1 else [f"{prefix}.{i:03d}" for i in range(n_ch)]
    binned = modality is Modality.SPIKE_COUNTS
    axis = time_axis(f, ts)
    info = _info(
        f,
        adapter_id=f"nwb:{name}",
        stream=name,
        modality=modality,
        unit=dst_unit,
        channels=names,
        electrodes=[ElectrodeSpec(c) for c in names],
        axis=axis,
        binned=binned,
        replay=replay,
    )
    return SeriesReplay(
        info,
        name,
        ts.data,
        axis,
        columns=None,
        conversion=float(ts.conversion),
        offset=float(getattr(ts, "offset", 0.0) or 0.0),
        unit_factor=factor,
        on_stop=f.close if close_on_stop else None,
    )


class BinnedUnitsReplay(WindowReplay):
    """Spike counts per bin computed lazily from sorted spike times (np.histogram convention)."""

    def __init__(
        self,
        info: NeuralAdapterInfo,
        stream: str,
        spikes: Sequence[F64],
        *,
        ends_s: F64,
        bin_width_s: float,
        on_stop: Any = None,  # noqa: ANN401
    ) -> None:
        super().__init__(info, stream, int(ends_s.size), on_stop)
        self._spikes = [np.sort(np.asarray(s, dtype=np.float64)) for s in spikes]
        self._edges = np.concatenate([[ends_s[0] - bin_width_s], ends_s])
        self._ts = seconds_to_ns(ends_s)

    def _values(self, lo: int, hi: int) -> F64:
        e = self._edges[lo : hi + 1]
        out = np.empty((hi - lo, len(self._spikes)), dtype=np.float64)
        last = hi == self.n_samples
        for j, sp in enumerate(self._spikes):
            idx = np.searchsorted(sp, e, side="left")
            if last:  # the final bin is closed on the right, like np.histogram
                idx[-1] = np.searchsorted(sp, e[-1], side="right")
            out[:, j] = np.diff(idx)
        return out

    def _timestamps(self, lo: int, hi: int) -> I64:
        out: I64 = np.array(self._ts[lo:hi], dtype=np.int64)
        return out


def units_binned_adapter(
    f: NwbFile,
    *,
    bin_width_s: float,
    grid_from: str | None = None,
    start_s: float = 0.0,
    replay: ReplayDeclaration | None = None,
    close_on_stop: bool = False,
) -> BinnedUnitsReplay:
    """Bin the ``Units`` table into spike counts.

    ``grid_from`` names a series whose sample times are the bin **end** times
    (e.g. FALCON H1 kinematics). Otherwise bins end at ``start_s + k * width``
    for ``k = 1 … ceil((t_max - start_s) / width)``.
    """
    units = f.nwb.units
    if units is None or len(units) == 0:
        msg = "the file has no Units table"
        raise ReplayError(msg)
    if not bin_width_s > 0:
        msg = "bin width must be positive"
        raise ReplayError(msg)
    spikes = [np.asarray(units["spike_times"][i], dtype=np.float64) for i in range(len(units))]
    ids = [int(i) for i in np.asarray(units.id[:])]
    if grid_from is not None:
        axis = time_axis(f, f.series(grid_from))
        ends = axis.seconds()
        if axis.n > 1 and not np.isclose(1.0 / axis.rate_hz, bin_width_s, rtol=1e-3):
            msg = "the grid spacing does not match the declared bin width"
            raise ReplayError(msg)
    else:
        t_max = max((float(s.max()) for s in spikes if s.size), default=start_s)
        n = max(1, int(np.ceil((t_max - start_s) / bin_width_s)))
        ends = start_s + bin_width_s * np.arange(1, n + 1, dtype=np.float64)
    names = [f"u{i:03d}" for i in ids]
    axis_info = TimeAxis(int(ends.size), float(ends[0]), 1.0 / bin_width_s, times_s=ends)
    info = _info(
        f,
        adapter_id="nwb:units",
        stream="units",
        modality=Modality.SPIKE_COUNTS,
        unit="count",
        channels=names,
        electrodes=[ElectrodeSpec(n) for n in names],
        axis=axis_info,
        binned=True,
        replay=replay,
        processing=(ProcessingStep("binning", (("width_s", repr(bin_width_s)),)),),
    )
    return BinnedUnitsReplay(
        info,
        "units",
        spikes,
        ends_s=ends,
        bin_width_s=bin_width_s,
        on_stop=f.close if close_on_stop else None,
    )


def _label(v: object) -> str:
    """Scalar or ragged cell (e.g. epoch ``tags``) as text."""
    if isinstance(v, str | bytes):
        return v.decode() if isinstance(v, bytes) else v
    if isinstance(v, list | tuple | np.ndarray):
        return "|".join(_label(x) for x in np.asarray(v, dtype=object).ravel())
    return str(v)


def read_events(
    f: NwbFile, table: str = "trials", *, label_column: str | None = None
) -> EventBlock:
    """A trials/epochs/intervals table as events at ``start_time`` (sorted)."""
    tables = dict(f.nwb.intervals or {})
    if f.nwb.trials is not None:
        tables.setdefault("trials", f.nwb.trials)
    if table not in tables:
        msg = f"no interval table {table!r}"
        raise ReplayError(msg)
    t = tables[table]
    starts = np.asarray(t["start_time"][:], dtype=np.float64)
    if label_column is None:
        labels = [f"{table}.{i}" for i in range(len(starts))]
    else:
        labels = [_label(v) for v in t[label_column][:]]
    order = np.argsort(starts, kind="stable")
    ns = seconds_to_ns(starts[order])
    return EventBlock(
        stream=table,
        timestamps_ns=tuple(int(x) for x in ns),
        labels=tuple(labels[i] for i in order),
        clock_domain=f.clock_domain,
    )
