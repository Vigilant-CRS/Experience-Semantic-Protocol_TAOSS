# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deterministic episode simulation.

Determinism contract: the same :class:`EpisodeSpec` (including ``seed``)
yields byte-identical ground truth and observations, on any machine with
the same numpy bit-generator (PCG64). Each stream draws from its own
``SeedSequence(seed, spawn_key=(index,))`` so adding a stream never changes
the samples of existing streams.
"""

from __future__ import annotations

import bisect
import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

import numpy as np

from esp.core.clock import ClockStamp
from esp.core.model import canonical_json_bytes
from esp.observation.model import DeviceMetadata, Observation, SignalQuality
from esp.simulation.spec import EpisodeSpec, Keyframe, StreamSpec

NS_PER_S: Final = 1_000_000_000
_IDS_SPAWN_KEY: Final = 1_000_000


def deterministic_uuid4(rng: np.random.Generator) -> uuid.UUID:
    """A valid RFC 4122 UUIDv4 whose random bits come from ``rng``."""
    return uuid.UUID(bytes=rng.bytes(16), version=4)


def ground_truth_at(keyframes: tuple[Keyframe, ...], t_s: float) -> dict[str, float]:
    """Linear interpolation between keyframes; hold after the last one."""
    times = [k.t_s for k in keyframes]
    i = bisect.bisect_right(times, t_s) - 1
    if i < 0:
        msg = "time before the first keyframe"
        raise ValueError(msg)
    a = keyframes[i].quantities()
    if i == len(keyframes) - 1:
        return a
    b = keyframes[i + 1].quantities()
    w = (t_s - times[i]) / (times[i + 1] - times[i])
    return {q: a[q] + w * (b[q] - a[q]) for q in a}


@dataclass(frozen=True, slots=True)
class GroundTruthPoint:
    t_ns: int
    values: Mapping[str, float]


@dataclass(frozen=True, slots=True)
class SimulatedEpisode:
    spec: EpisodeSpec
    episode_id: uuid.UUID
    timeline_id: uuid.UUID
    ground_truth: tuple[GroundTruthPoint, ...]
    observations: tuple[Observation, ...]

    def ground_truth_bytes(self) -> bytes:
        """Canonical bytes of the ground truth (for determinism checks)."""
        return canonical_json_bytes(
            {
                "episode_id": str(self.episode_id),
                "timeline_id": str(self.timeline_id),
                "points": [{"t_ns": p.t_ns, "values": dict(p.values)} for p in self.ground_truth],
            }
        )

    def observation_bytes(self) -> bytes:
        return b"\n".join(o.canonical_json() for o in self.observations)

    def truth_at_ns(self, t_ns: int) -> dict[str, float]:
        return ground_truth_at(self.spec.keyframes, t_ns / NS_PER_S)


def _grid(duration_s: float, rate_hz: float) -> list[int]:
    """Integer-ns sample times ``k / rate`` for ``k / rate < duration``."""
    count = int(np.floor(duration_s * rate_hz - 1e-9)) + 1
    return [round(k * NS_PER_S / rate_hz) for k in range(count)]


def _simulate_stream(spec: EpisodeSpec, index: int, stream: StreamSpec) -> list[Observation]:
    rng = np.random.default_rng(np.random.SeedSequence(spec.seed, spawn_key=(index,)))
    device = DeviceMetadata(
        device_id=stream.device_id,
        kind=f"sim-{stream.modality.value}",
        sampling_rate_hz=stream.rate_hz,
        synthetic=True,
    )
    out: list[Observation] = []
    for k, t_ns in enumerate(_grid(spec.duration_s, stream.rate_hz)):
        truth = ground_truth_at(spec.keyframes, t_ns / NS_PER_S)
        signal = stream.base + sum(term.gain * truth[term.quantity] for term in stream.terms)
        noise = float(rng.normal(0.0, stream.noise_sd)) if stream.noise_sd > 0 else 0.0
        dropped = bool(rng.random() < stream.dropout_prob)
        jitter = int(rng.integers(0, stream.clock.jitter_ns + 1)) if stream.clock.jitter_ns else 0
        source_ns = round(t_ns * (1.0 + stream.clock.drift_ppm * 1e-6)) + stream.clock.offset_ns
        out.append(
            Observation(
                id=deterministic_uuid4(rng),
                modality=stream.modality,
                channel=stream.channel,
                value=None if dropped else signal + noise,
                unit=stream.unit,
                device=device,
                timestamp=ClockStamp(
                    source_ns=source_ns + jitter,
                    monotonic_ns=t_ns,
                    clock_domain=stream.clock.domain,
                    sequence=k,
                ),
                quality=SignalQuality(signal_quality=None if dropped else 1.0, dropout=dropped),
            )
        )
    return out


def simulate(spec: EpisodeSpec) -> SimulatedEpisode:
    """Run one episode deterministically."""
    id_rng = np.random.default_rng(np.random.SeedSequence(spec.seed, spawn_key=(_IDS_SPAWN_KEY,)))
    episode_id = deterministic_uuid4(id_rng)
    timeline_id = deterministic_uuid4(id_rng)
    truth = tuple(
        GroundTruthPoint(t_ns, MappingProxyType(ground_truth_at(spec.keyframes, t_ns / NS_PER_S)))
        for t_ns in _grid(spec.duration_s, spec.frame_rate_hz)
    )
    observations: list[Observation] = []
    for index, stream in enumerate(spec.streams):
        observations.extend(_simulate_stream(spec, index, stream))
    observations.sort(key=lambda o: (o.timestamp.monotonic_ns, o.device.device_id, o.channel))
    return SimulatedEpisode(
        spec=spec,
        episode_id=episode_id,
        timeline_id=timeline_id,
        ground_truth=truth,
        observations=tuple(observations),
    )
