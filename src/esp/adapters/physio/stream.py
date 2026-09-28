# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sample blocks, stream analysis and deterministic replay (M6).

A :class:`SampleBlock` is a multichannel, regularly or irregularly sampled
signal with integer nanosecond timestamps in one clock domain. ``NaN``
marks a dropout. Blocks convert lazily into semantically neutral
:class:`~esp.observation.model.Observation` objects — never into emotions.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from collections.abc import Iterator, Sequence
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

from esp.core.clock import ClockStamp
from esp.observation.model import DeviceMetadata, Modality, Observation, SignalQuality
from esp.observation.units import UNITS

_UNIT_ALIASES = {
    "µv": "uV",
    "uv": "uV",
    "μv": "uV",
    "mv": "mV",
    "v": "V",
    "us": "uS",
    "µs": "uS",
    "microsiemens": "uS",
    "degc": "degC",
    "°c": "degC",
    "c": "degC",
    "%": "percent",
    "bpm": "bpm",
    "hz": "Hz",
    "g": "g0",
    "nu": "1",
    "": "1",
    "a.u.": "1",
    "au": "1",
    "boolean": "1",
}


def normalize_unit(raw: str) -> str:
    """Map a file's unit label to an ESP unit symbol (unknown labels are refused)."""
    s = raw.strip()
    if s in UNITS:
        return s
    mapped = _UNIT_ALIASES.get(s.lower())
    if mapped is None:
        msg = f"unknown unit label {raw!r}"
        raise ValueError(msg)
    return mapped


def normalize_channel(raw: str) -> str:
    """Channel names as ESP channel ids: lower case, ``[a-z0-9_.-]``, no trailing dots."""
    s = re.sub(r"[^a-z0-9_.\-]+", "_", raw.strip().lower()).strip("._-")
    return s or "ch"


@dataclass(frozen=True, slots=True)
class ChannelSpec:
    name: str
    modality: Modality
    unit: str


@dataclass(frozen=True, slots=True)
class SampleBlock:
    stream: str
    channels: tuple[ChannelSpec, ...]
    timestamps_ns: NDArray[np.int64]
    values: NDArray[np.float64]
    """Shape ``(n_samples, n_channels)``; ``NaN`` = dropout."""
    device: DeviceMetadata
    clock_domain: str
    nominal_rate_hz: float | None = None

    def __post_init__(self) -> None:
        if self.values.ndim != 2 or self.values.shape[1] != len(self.channels):
            msg = "values must have shape (n_samples, n_channels)"
            raise ValueError(msg)
        if self.timestamps_ns.shape != (self.values.shape[0],):
            msg = "one timestamp per sample"
            raise ValueError(msg)
        if np.isinf(self.values).any():
            msg = "infinite samples are not allowed (use NaN for dropouts)"
            raise ValueError(msg)
        names = [c.name for c in self.channels]
        if len(set(names)) != len(names):
            msg = "channel names must be unique within a block"
            raise ValueError(msg)
        self.timestamps_ns.flags.writeable = False
        self.values.flags.writeable = False

    @property
    def n_samples(self) -> int:
        return int(self.values.shape[0])

    def channel(self, name: str) -> NDArray[np.float64]:
        for i, c in enumerate(self.channels):
            if c.name == name:
                return self.values[:, i]
        msg = f"no channel {name!r}"
        raise KeyError(msg)

    def digest(self) -> str:
        """Content digest for replay determinism (timestamps, values, channel specs)."""
        h = hashlib.sha256()
        h.update(repr([(c.name, c.modality.value, c.unit) for c in self.channels]).encode())
        h.update(np.ascontiguousarray(self.timestamps_ns, dtype="<i8").tobytes())
        h.update(np.ascontiguousarray(self.values, dtype="<f8").tobytes())
        return h.hexdigest()

    def observations(self, start: int = 0, stop: int | None = None) -> Iterator[Observation]:
        """Lazily convert samples ``[start, stop)`` into neutral observations."""
        stop = self.n_samples if stop is None else min(stop, self.n_samples)
        for i in range(start, stop):
            t = int(self.timestamps_ns[i])
            stamp = ClockStamp(
                source_ns=t, monotonic_ns=t, clock_domain=self.clock_domain, sequence=i
            )
            for j, c in enumerate(self.channels):
                v = float(self.values[i, j])
                dropout = bool(np.isnan(v))
                yield Observation(
                    id=uuid.uuid4(),
                    modality=c.modality,
                    channel=c.name,
                    value=None if dropout else v,
                    unit=c.unit,
                    device=self.device,
                    timestamp=stamp,
                    quality=SignalQuality(dropout=dropout),
                )


@dataclass(frozen=True, slots=True)
class EventBlock:
    stream: str
    timestamps_ns: tuple[int, ...]
    labels: tuple[str, ...]
    clock_domain: str

    def __post_init__(self) -> None:
        if len(self.timestamps_ns) != len(self.labels):
            msg = "one label per event timestamp"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class Recording:
    source: str
    blocks: tuple[SampleBlock, ...]
    events: tuple[EventBlock, ...] = ()
    notes: tuple[str, ...] = ()
    """Explicit reinterpretations made while reading (e.g. unknown units)."""

    def block(self, stream: str) -> SampleBlock:
        for b in self.blocks:
            if b.stream == stream:
                return b
        msg = f"no stream {stream!r} in {self.source}"
        raise KeyError(msg)

    def digest(self) -> str:
        h = hashlib.sha256(self.source.encode())
        for b in self.blocks:
            h.update(b.digest().encode())
        for e in self.events:
            h.update(repr((e.stream, e.timestamps_ns, e.labels)).encode())
        return h.hexdigest()


@dataclass(frozen=True, slots=True)
class StreamReport:
    n_samples: int
    duration_s: float
    effective_rate_hz: float
    non_monotonic: int
    """Timestamp steps that go backwards (or repeat)."""
    gaps: int
    """Inter-sample intervals longer than 1.5 nominal periods."""
    dropped_estimate: int
    """Samples missing according to the nominal rate."""
    dropout_samples: int
    """Samples present but flagged NaN in at least one channel."""


def analyze(block: SampleBlock) -> StreamReport:
    ts = block.timestamps_ns.astype(np.int64)
    n = block.n_samples
    d = np.diff(ts)
    duration = (int(ts[-1]) - int(ts[0])) / 1e9 if n > 1 else 0.0
    gaps = dropped = 0
    if block.nominal_rate_hz and n > 1:
        period = 1e9 / block.nominal_rate_hz
        long = d[d > 1.5 * period]
        gaps = int(long.size)
        dropped = int(np.round(long / period).sum() - long.size)
    return StreamReport(
        n_samples=n,
        duration_s=duration,
        effective_rate_hz=(n - 1) / duration if duration > 0 else 0.0,
        non_monotonic=int((d <= 0).sum()),
        gaps=gaps,
        dropped_estimate=dropped,
        dropout_samples=int(np.isnan(block.values).any(axis=1).sum()),
    )


def regular_timestamps(start_ns: int, n: int, rate_hz: float) -> NDArray[np.int64]:
    """``start + round(i * 1e9 / rate)`` — exact integer grid without float drift."""
    return start_ns + np.round(np.arange(n, dtype=np.float64) * (1e9 / rate_hz)).astype(np.int64)


def replay_chunks(block: SampleBlock, chunk: int) -> Iterator[SampleBlock]:
    """Deterministic replay in fixed-size chunks (same input -> same chunks -> same digest)."""
    if chunk < 1:
        msg = "chunk size must be positive"
        raise ValueError(msg)
    for s in range(0, block.n_samples, chunk):
        yield SampleBlock(
            stream=block.stream,
            channels=block.channels,
            timestamps_ns=np.array(block.timestamps_ns[s : s + chunk]),
            values=np.array(block.values[s : s + chunk]),
            device=block.device,
            clock_domain=block.clock_domain,
            nominal_rate_hz=block.nominal_rate_hz,
        )


def concat(blocks: Sequence[SampleBlock]) -> SampleBlock:
    first = blocks[0]
    return SampleBlock(
        stream=first.stream,
        channels=first.channels,
        timestamps_ns=np.concatenate([b.timestamps_ns for b in blocks]),
        values=np.concatenate([b.values for b in blocks]),
        device=first.device,
        clock_domain=first.clock_domain,
        nominal_rate_hz=first.nominal_rate_hz,
    )
