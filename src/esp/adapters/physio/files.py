# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Recorded-data readers for replay without hardware (M6, WP-083 datasets).

- EDF/EDF+ and BDF/BDF+ (own reader: 16-/24-bit little-endian, digital to
  physical scaling, EDF+ annotations, ``n_records = -1`` inferred from the
  file size);
- BrainVision (``.vhdr``/``.eeg``/``.vmrk``; INT_16 or IEEE_FLOAT_32, multiplexed);
- Empatica E4 CSV (PhysioNet wearable stress: BVP, EDA, TEMP, HR, ACC, tags);
- WFDB (PhysioNet; via ``wfdb``);
- XDF (Lab Streaming Layer recordings; via ``pyxdf``).

Every reader returns a :class:`Recording` of neutral sample blocks. Readers
validate headers and refuse malformed files instead of guessing.
"""

from __future__ import annotations

import calendar
import configparser
import dataclasses
import datetime as dt
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from numpy.typing import NDArray

from esp.adapters.physio.stream import (
    ChannelSpec,
    EventBlock,
    Recording,
    SampleBlock,
    normalize_channel,
    normalize_unit,
    regular_timestamps,
)
from esp.observation.model import DeviceMetadata, Modality


class RecordingFormatError(ValueError):
    """A recording file is malformed or unsupported."""


def _device(kind: str, rate: float | None) -> DeviceMetadata:
    return DeviceMetadata(
        device_id=f"replay-{normalize_channel(kind)}", kind=kind, sampling_rate_hz=rate
    )


def _unique(names: Sequence[str]) -> list[str]:
    seen: dict[str, int] = {}
    out = []
    for n in names:
        k = seen.get(n, 0)
        seen[n] = k + 1
        out.append(n if k == 0 else f"{n}_{k}")
    return out


# --- EDF / BDF ------------------------------------------------------------------------------


def _field(raw: bytes, start: int, size: int) -> str:
    return raw[start : start + size].decode("ascii", errors="replace").strip()


@dataclass(frozen=True, slots=True)
class _EdfHeader:
    bdf: bool
    header_bytes: int
    n_records: int
    record_s: float
    labels: list[str]
    units: list[str]
    pmin: NDArray[np.float64]
    pmax: NDArray[np.float64]
    dmin: NDArray[np.float64]
    dmax: NDArray[np.float64]
    spr: NDArray[np.int64]
    t0_ns: int

    @property
    def width(self) -> int:
        return 3 if self.bdf else 2

    @property
    def record_bytes(self) -> int:
        return int(self.spr.sum()) * self.width


def _edf_header(data: bytes) -> _EdfHeader:
    if len(data) < 256:
        raise RecordingFormatError("file too short for an EDF/BDF header")
    bdf = data[0] == 0xFF and data[1:8] == b"BIOSEMI"
    if not bdf and data[:8] != b"0       ":
        raise RecordingFormatError("not an EDF or BDF file")
    try:
        header_bytes = int(_field(data, 184, 8))
        n_records = int(_field(data, 236, 8))
        record_s = float(_field(data, 244, 8))
        ns = int(_field(data, 252, 4))
        start = dt.datetime.strptime(
            _field(data, 168, 8) + " " + _field(data, 176, 8), "%d.%m.%y %H.%M.%S"
        )
        if ns < 1 or header_bytes != 256 * (ns + 1) or record_s <= 0:
            raise RecordingFormatError("inconsistent EDF header sizes")
        h = data[256:header_bytes]

        def col(offset: int, size: int) -> list[str]:
            return [_field(h, offset * ns + i * size, size) for i in range(ns)]

        def num(offset: int) -> NDArray[np.float64]:
            return np.array([float(x) for x in col(offset, 8)])

        header = _EdfHeader(
            bdf=bdf,
            header_bytes=header_bytes,
            n_records=n_records,
            record_s=record_s,
            labels=col(0, 16),
            units=col(96, 8),
            pmin=num(104),
            pmax=num(112),
            dmin=num(120),
            dmax=num(128),
            spr=np.array([int(x) for x in col(216, 8)], dtype=np.int64),
            t0_ns=calendar.timegm(start.timetuple()) * 1_000_000_000,
        )
    except ValueError as exc:
        if isinstance(exc, RecordingFormatError):
            raise
        raise RecordingFormatError(f"malformed EDF header: {exc}") from None
    if np.any(header.spr < 1) or np.any(header.dmax <= header.dmin):
        raise RecordingFormatError("invalid samples-per-record or digital range")
    available = (len(data) - header_bytes) // header.record_bytes
    if n_records == -1:  # recording not closed properly: infer from the file size
        header = dataclasses.replace(header, n_records=available)
    if header.n_records < 0 or available < header.n_records:
        raise RecordingFormatError("file shorter than the declared number of records")
    return header


def _edf_records(data: bytes, h: _EdfHeader) -> NDArray[np.int32]:
    body = np.frombuffer(
        data, dtype=np.uint8, count=h.n_records * h.record_bytes, offset=h.header_bytes
    )
    if h.bdf:
        b = body.reshape(-1, 3).astype(np.int32)
        ints = b[:, 0] | (b[:, 1] << 8) | (b[:, 2] << 16)
        ints = np.where(ints >= 1 << 23, ints - (1 << 24), ints)
    else:
        ints = body.view("<i2").astype(np.int32)
    return ints.reshape(h.n_records, int(h.spr.sum()))


def read_edf(path: Path, *, modality: Modality = Modality.EEG) -> Recording:
    data = path.read_bytes()
    h = _edf_header(data)
    records = _edf_records(data, h)
    offsets = np.concatenate([[0], np.cumsum(h.spr)])
    annotation = {
        i for i, lab in enumerate(h.labels) if lab in {"EDF Annotations", "BDF Annotations"}
    }
    groups: dict[int, list[int]] = {}
    for i in range(len(h.labels)):
        if i not in annotation:
            groups.setdefault(int(h.spr[i]), []).append(i)
    blocks = []
    for per_record, idx in sorted(groups.items(), reverse=True):
        rate = per_record / h.record_s
        cols = []
        for i in idx:
            dig = records[:, offsets[i] : offsets[i + 1]].reshape(-1).astype(np.float64)
            gain = (h.pmax[i] - h.pmin[i]) / (h.dmax[i] - h.dmin[i])
            cols.append((dig - h.dmin[i]) * gain + h.pmin[i])
        names = _unique([normalize_channel(h.labels[i]) for i in idx])
        specs = tuple(
            ChannelSpec(n, modality, normalize_unit(h.units[i]))
            for n, i in zip(names, idx, strict=True)
        )
        values = np.stack(cols, axis=1)
        blocks.append(
            SampleBlock(
                stream=f"{path.stem}@{rate:g}Hz",
                channels=specs,
                timestamps_ns=regular_timestamps(h.t0_ns, values.shape[0], rate),
                values=values,
                device=_device("bdf" if h.bdf else "edf", rate),
                clock_domain=f"file:{path.name}",
                nominal_rate_hz=rate,
            )
        )
    events = []
    for i in sorted(annotation):
        lo, hi = int(offsets[i]) * h.width, int(offsets[i + 1]) * h.width
        base = h.header_bytes
        payload = b"".join(
            data[base + r * h.record_bytes + lo : base + r * h.record_bytes + hi]
            for r in range(h.n_records)
        )
        events.append(_parse_tal(payload, h.t0_ns, path.name))
    return Recording(
        source=path.name, blocks=tuple(blocks), events=tuple(e for e in events if e.labels)
    )


_TAL = re.compile(rb"([+-]\d+(?:\.\d+)?)(?:\x15(\d+(?:\.\d+)?))?\x14([^\x00]*?)\x14", re.S)


def _parse_tal(payload: bytes, t0: int, name: str) -> EventBlock:
    ts: list[int] = []
    labels: list[str] = []
    for onset, _duration, texts in _TAL.findall(payload):
        for text in texts.split(b"\x14"):
            if text:
                ts.append(t0 + round(float(onset) * 1e9))
                labels.append(text.decode("utf-8", errors="replace"))
    return EventBlock(
        stream=f"{name}:annotations",
        timestamps_ns=tuple(ts),
        labels=tuple(labels),
        clock_domain=f"file:{name}",
    )


# --- BrainVision ----------------------------------------------------------------------------


def read_brainvision(
    vhdr: Path, *, modality: Modality = Modality.EEG, unknown_units: str = "refuse"
) -> Recording:
    """``unknown_units="dimensionless"`` maps unknown unit labels to ``1`` and notes it."""
    text = vhdr.read_text(encoding="utf-8", errors="replace")
    lines = text.splitlines()
    if not lines or not lines[0].startswith("Brain Vision Data Exchange Header File"):
        raise RecordingFormatError("not a BrainVision header")
    cp = configparser.ConfigParser(interpolation=None, comment_prefixes=(";",), strict=False)
    cp.optionxform = str  # type: ignore[assignment,method-assign]
    ini = []
    for line in lines[1:]:
        if line.strip().lower() == "[comment]":
            break  # free-text amplifier report, not INI
        ini.append(line)
    cp.read_string("\n".join(ini))
    common = cp["Common Infos"]
    if common.get("DataOrientation", "MULTIPLEXED").upper() != "MULTIPLEXED":
        raise RecordingFormatError("only MULTIPLEXED BrainVision data is supported")
    fmt = cp["Binary Infos"].get("BinaryFormat", "INT_16").upper()
    dtype = {"INT_16": "<i2", "IEEE_FLOAT_32": "<f4"}.get(fmt)
    if dtype is None:
        raise RecordingFormatError(f"unsupported BinaryFormat {fmt}")
    n = int(common["NumberOfChannels"])
    rate = 1e6 / float(common["SamplingInterval"])
    names, res, units = [], [], []
    for i in range(1, n + 1):
        parts = cp["Channel Infos"][f"Ch{i}"].split(",")
        names.append(parts[0].replace("\\1", ","))
        res.append(float(parts[2]) if len(parts) > 2 and parts[2] else 1.0)
        units.append(parts[3] if len(parts) > 3 and parts[3] else "µV")
    raw = np.fromfile(vhdr.with_name(common["DataFile"]), dtype=dtype)
    if raw.size % n:
        raise RecordingFormatError("data file size is not a multiple of the channel count")
    values = raw.reshape(-1, n).astype(np.float64) * np.array(res)
    specs_list, notes = [], []
    for c, u in zip(_unique([normalize_channel(x) for x in names]), units, strict=True):
        try:
            unit = normalize_unit(u)
        except ValueError:
            if unknown_units != "dimensionless":
                raise
            unit = "1"
            notes.append(f"channel {c}: unknown unit {u!r} read as dimensionless")
        specs_list.append(ChannelSpec(c, modality, unit))
    specs = tuple(specs_list)
    block = SampleBlock(
        stream=vhdr.stem,
        channels=specs,
        timestamps_ns=regular_timestamps(0, values.shape[0], rate),
        values=values,
        device=_device("brainvision", rate),
        clock_domain=f"file:{vhdr.name}",
        nominal_rate_hz=rate,
    )
    marker = common.get("MarkerFile")
    events: tuple[EventBlock, ...] = ()
    if marker and vhdr.with_name(marker).exists():
        events = (_bv_markers(vhdr.with_name(marker), rate, vhdr),)
    return Recording(source=vhdr.name, blocks=(block,), events=events, notes=tuple(notes))


def _bv_markers(vmrk: Path, rate: float, vhdr: Path) -> EventBlock:
    ts, labels = [], []
    for line in vmrk.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^Mk\d+=([^,]*),([^,]*),(\d+),", line)
        if m:
            ts.append(round((int(m.group(3)) - 1) * 1e9 / rate))
            labels.append(f"{m.group(1)}:{m.group(2)}".strip(":"))
    return EventBlock(f"{vhdr.stem}:markers", tuple(ts), tuple(labels), f"file:{vhdr.name}")


# --- Empatica E4 CSV (PhysioNet wearable stress) ---------------------------------------------

_E4 = {
    "BVP": (Modality.PPG, "bvp", "1"),
    "EDA": (Modality.EDA, "eda", "uS"),
    "TEMP": (Modality.TEMPERATURE, "skin_temp", "degC"),
    "HR": (Modality.PPG, "hr", "bpm"),
    "ACC": (Modality.MOTION, "acc", "g0"),
}


def _e4_start(line: str) -> int:
    first = line.split(",", maxsplit=1)[0].strip()
    try:
        return round(float(first) * 1e9)  # classic E4 export: unix seconds
    except ValueError:
        stamp = dt.datetime.strptime(first, "%Y-%m-%d %H:%M:%S")  # PhysioNet variant (UTC)
        return calendar.timegm(stamp.timetuple()) * 1_000_000_000


def read_empatica(directory: Path) -> Recording:
    blocks = []
    for name, (modality, channel, unit) in _E4.items():
        f = directory / f"{name}.csv"
        if not f.exists():
            continue
        lines = f.read_text(encoding="utf-8").splitlines()
        if len(lines) < 3:
            raise RecordingFormatError(f"{f.name}: missing start time or rate")
        start = _e4_start(lines[0])
        rate = float(lines[1].split(",")[0])
        rows = np.array([[float(x) for x in ln.split(",")] for ln in lines[2:] if ln.strip()])
        if name == "ACC":
            rows = rows / 64.0  # E4 accelerometer: 1/64 g
            specs = tuple(ChannelSpec(f"acc_{a}", modality, unit) for a in "xyz")
        else:
            specs = (ChannelSpec(channel, modality, unit),)
        blocks.append(
            SampleBlock(
                stream=name.lower(),
                channels=specs,
                timestamps_ns=regular_timestamps(start, rows.shape[0], rate),
                values=rows.reshape(rows.shape[0], len(specs)),
                device=_device("empatica-e4", rate),
                clock_domain="unix",
                nominal_rate_hz=rate,
            )
        )
    tags = directory / "tags.csv"
    events: tuple[EventBlock, ...] = ()
    if tags.exists():
        ts = [_e4_start(x) for x in tags.read_text(encoding="utf-8").splitlines() if x.strip()]
        events = (EventBlock("tags", tuple(ts), tuple("tag" for _ in ts), "unix"),)
    if not blocks:
        raise RecordingFormatError(f"no Empatica CSV files in {directory}")
    return Recording(source=directory.name, blocks=tuple(blocks), events=events)


# --- WFDB ----------------------------------------------------------------------------------------

_WFDB_MODALITY = {
    "ax": Modality.MOTION,
    "ay": Modality.MOTION,
    "az": Modality.MOTION,
    "temp": Modality.TEMPERATURE,
    "eda": Modality.EDA,
    "spo2": Modality.PPG,
    "hr": Modality.PPG,
}


def read_wfdb(record: Path) -> Recording:
    import wfdb  # noqa: PLC0415 - optional dependency (physio extra)

    rec = wfdb.rdrecord(str(record))
    sig = np.asarray(rec.p_signal, dtype=np.float64)
    names = [normalize_channel(n) for n in rec.sig_name]
    specs = tuple(
        ChannelSpec(n, _WFDB_MODALITY.get(n, Modality.BEHAVIOR), normalize_unit(u))
        for n, u in zip(names, rec.units, strict=True)
    )
    base = 0
    if rec.base_date is not None and rec.base_time is not None:
        base = (
            calendar.timegm(dt.datetime.combine(rec.base_date, rec.base_time).timetuple()) * 10**9
        )
    rate = float(rec.fs)
    block = SampleBlock(
        stream=record.name,
        channels=specs,
        timestamps_ns=regular_timestamps(base, sig.shape[0], rate),
        values=sig,
        device=_device("wfdb", rate),
        clock_domain=f"file:{record.name}",
        nominal_rate_hz=rate,
    )
    events: tuple[EventBlock, ...] = ()
    if record.with_suffix(".atr").exists():
        ann = wfdb.rdann(str(record), "atr")
        ts = tuple(base + round(int(s) * 1e9 / rate) for s in ann.sample)
        labels = tuple(
            str(a).strip() or str(s) for a, s in zip(ann.aux_note, ann.symbol, strict=True)
        )
        events = (EventBlock(f"{record.name}:atr", ts, labels, f"file:{record.name}"),)
    return Recording(source=record.name, blocks=(block,), events=events)


# --- XDF --------------------------------------------------------------------------------


def read_xdf(path: Path, *, modality_by_type: dict[str, Modality] | None = None) -> Recording:
    """LSL recordings. Timestamps are LSL clock seconds after pyxdf clock synchronization."""
    import pyxdf  # noqa: PLC0415 - optional dependency (physio extra)

    types = {"eeg": Modality.EEG, "ecg": Modality.ECG, "eda": Modality.EDA, "gaze": Modality.EYE}
    types |= modality_by_type or {}
    streams: list[dict[str, Any]]
    streams, _ = pyxdf.load_xdf(str(path))
    blocks, events = [], []
    for s in streams:
        info = s["info"]
        name = normalize_channel(info["name"][0])
        stype = info["type"][0].lower()
        ts = np.round(np.asarray(s["time_stamps"], dtype=np.float64) * 1e9).astype(np.int64)
        domain = f"lsl:{info.get('hostname', ['?'])[0]}"
        if info["channel_format"][0] == "string":
            events.append(
                EventBlock(
                    name,
                    tuple(int(t) for t in ts),
                    tuple(str(x[0]) for x in s["time_series"]),
                    domain,
                )
            )
            continue
        values = np.asarray(s["time_series"], dtype=np.float64)
        if values.ndim == 1:
            values = values[:, None]
        rate = float(info["nominal_srate"][0]) or None
        modality = types.get(stype, Modality.BEHAVIOR)
        specs = tuple(ChannelSpec(f"{name}_{i}", modality, "1") for i in range(values.shape[1]))
        blocks.append(
            SampleBlock(
                stream=name,
                channels=specs,
                timestamps_ns=ts,
                values=values,
                device=_device(f"lsl-{stype}", rate),
                clock_domain=domain,
                nominal_rate_hz=rate,
            )
        )
    return Recording(source=path.name, blocks=tuple(blocks), events=tuple(events))
