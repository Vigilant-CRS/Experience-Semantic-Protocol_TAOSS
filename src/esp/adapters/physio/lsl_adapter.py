# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Lab Streaming Layer adapter (WP-027): discovery, outlets, inlets, clock metadata.

Inlets keep the *sender's* LSL timestamps and record the clock-correction
offsets (``time_correction()``) separately, so a consumer can apply them
explicitly and an audit can see how large they were. :func:`corrected`
returns a block in the receiver's clock domain.

Replay (:class:`ReplayOutlet`) pushes a recorded :class:`SampleBlock` (for
example from an XDF file) back into LSL with its original relative timing.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

import numpy as np
from numpy.typing import NDArray
from pylsl import (
    IRREGULAR_RATE,
    StreamInfo,
    StreamInlet,
    StreamOutlet,
    cf_float32,
    cf_string,
    local_clock,
    resolve_byprop,
)

from esp.adapters.physio.stream import ChannelSpec, EventBlock, SampleBlock
from esp.observation.model import DeviceMetadata

NS = 1_000_000_000


@dataclass(frozen=True, slots=True)
class DiscoveredStream:
    name: str
    type: str
    channel_count: int
    nominal_rate_hz: float
    source_id: str
    info: StreamInfo = field(repr=False, compare=False)


def discover(prop: str = "name", value: str = "", timeout: float = 2.0) -> list[DiscoveredStream]:
    """Resolve streams by property (``name``, ``type``, ``source_id``)."""
    found = resolve_byprop(prop, value, timeout=timeout) if value else []
    return [
        DiscoveredStream(i.name(), i.type(), i.channel_count(), i.nominal_srate(), i.source_id(), i)
        for i in found
    ]


class SignalOutlet:
    def __init__(
        self,
        name: str,
        stype: str,
        channels: tuple[ChannelSpec, ...],
        rate_hz: float,
        source_id: str,
    ) -> None:
        info = StreamInfo(name, stype, len(channels), rate_hz, cf_float32, source_id)
        desc = info.desc().append_child("channels")
        for c in channels:
            ch = desc.append_child("channel")
            ch.append_child_value("label", c.name)
            ch.append_child_value("unit", c.unit)
            ch.append_child_value("type", c.modality.value)
        self.channels = channels
        self._outlet = StreamOutlet(info)

    def push(self, values: NDArray[np.float64], timestamps_s: NDArray[np.float64]) -> None:
        """Push samples with explicit LSL-clock timestamps (seconds)."""
        for row, t in zip(values, timestamps_s, strict=True):
            self._outlet.push_sample(row.tolist(), float(t))

    def have_consumers(self) -> bool:
        return bool(self._outlet.have_consumers())

    def close(self) -> None:
        """Release the native outlet now (not at interpreter shutdown)."""
        self._outlet = None


class MarkerOutlet:
    def __init__(self, name: str, source_id: str) -> None:
        info = StreamInfo(name, "Markers", 1, IRREGULAR_RATE, cf_string, source_id)
        self._outlet = StreamOutlet(info)

    def push(self, label: str, timestamp_s: float | None = None) -> float:
        t = local_clock() if timestamp_s is None else timestamp_s
        self._outlet.push_sample([label], t)
        return t

    def close(self) -> None:
        self._outlet = None


@dataclass(slots=True)
class ClockOffsets:
    """``time_correction()`` samples: (local time s, offset s)."""

    samples: list[tuple[float, float]] = field(default_factory=list)

    def latest(self) -> float:
        return self.samples[-1][1] if self.samples else 0.0


class SignalInlet:
    def __init__(self, stream: DiscoveredStream, channels: tuple[ChannelSpec, ...]) -> None:
        if len(channels) != stream.channel_count:
            msg = "channel specs must match the stream's channel count"
            raise ValueError(msg)
        self._inlet = StreamInlet(stream.info, max_buflen=360)
        self.stream = stream
        self.channels = channels
        self.clock = ClockOffsets()
        self._device = DeviceMetadata(
            device_id=f"lsl-{stream.source_id}"[:128],
            kind=f"lsl-{stream.type.lower()}",
            sampling_rate_hz=stream.nominal_rate_hz or None,
        )

    def open(self, timeout: float = 5.0) -> None:
        self._inlet.open_stream(timeout=timeout)

    def update_clock(self, timeout: float = 2.0) -> float:
        offset = float(self._inlet.time_correction(timeout=timeout))
        self.clock.samples.append((local_clock(), offset))
        return offset

    def pull(self, timeout: float = 0.0, max_samples: int = 4096) -> SampleBlock | None:
        samples, stamps = self._inlet.pull_chunk(timeout=timeout, max_samples=max_samples)
        if not stamps:
            return None
        return SampleBlock(
            stream=self.stream.name,
            channels=self.channels,
            timestamps_ns=np.round(np.asarray(stamps) * NS).astype(np.int64),
            values=np.asarray(samples, dtype=np.float64),
            device=self._device,
            clock_domain=f"lsl-sender:{self.stream.source_id}",
            nominal_rate_hz=self.stream.nominal_rate_hz or None,
        )

    def close(self) -> None:
        self._inlet.close_stream()
        self._inlet = None


class MarkerInlet:
    def __init__(self, stream: DiscoveredStream) -> None:
        self._inlet = StreamInlet(stream.info)
        self.stream = stream

    def open(self, timeout: float = 5.0) -> None:
        self._inlet.open_stream(timeout=timeout)

    def pull(self, timeout: float = 0.0) -> EventBlock:
        samples, stamps = self._inlet.pull_chunk(timeout=timeout)
        return EventBlock(
            stream=self.stream.name,
            timestamps_ns=tuple(round(t * NS) for t in stamps),
            labels=tuple(str(s[0]) for s in samples),
            clock_domain=f"lsl-sender:{self.stream.source_id}",
        )

    def close(self) -> None:
        self._inlet.close_stream()
        self._inlet = None


def corrected(block: SampleBlock, offset_s: float) -> SampleBlock:
    """Map sender LSL timestamps into the receiver's clock (``t + time_correction``)."""
    return SampleBlock(
        stream=block.stream,
        channels=block.channels,
        timestamps_ns=block.timestamps_ns + round(offset_s * NS),
        values=np.array(block.values),
        device=block.device,
        clock_domain="lsl-local",
        nominal_rate_hz=block.nominal_rate_hz,
    )


def unix_to_lsl_offset_s() -> float:
    """Offset to convert Unix seconds (e.g. BrainFlow) into this host's LSL clock."""
    return float(local_clock()) - time.time()


class ReplayOutlet:
    """Push a recorded block into LSL with its original relative timing (paced)."""

    def __init__(self, block: SampleBlock, name: str, stype: str, source_id: str) -> None:
        if not block.nominal_rate_hz:
            msg = "replay needs a nominal rate"
            raise ValueError(msg)
        self.block = block
        self.outlet = SignalOutlet(name, stype, block.channels, block.nominal_rate_hz, source_id)

    def run(self, *, chunk: int = 32, speed: float = 1.0) -> int:
        b = self.block
        rel = (b.timestamps_ns - b.timestamps_ns[0]) / NS
        start = local_clock()
        valid = ~np.isnan(b.values).any(axis=1)  # dropouts stay missing (a gap), never 0
        pushed = 0
        for s in range(0, b.n_samples, chunk):
            due = start + rel[s] / speed
            wait = due - local_clock()
            if wait > 0:
                time.sleep(wait)
            keep = valid[s : s + chunk]
            self.outlet.push(
                b.values[s : s + chunk][keep], start + rel[s : s + chunk][keep] / speed
            )
            pushed += int(keep.sum())
        return pushed
