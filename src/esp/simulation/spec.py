# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""YAML episode DSL.

Example::

    episode:
      name: fear-at-work
      seed: 42
      duration_s: 10
      frame_rate_hz: 10
      keyframes:
        - {t_s: 0, emotion: {fear: 0.2}, readiness: {avoid: 0.1}, context: {meeting: 1.0}}
        - {t_s: 5, emotion: {fear: 0.8}, readiness: {avoid: 0.7}, context: {meeting: 1.0}}
      streams:
        - modality: ecg
          channel: heart_rate
          unit: bpm
          rate_hz: 4
          base: 70
          terms: [{quantity: emotion.fear, gain: 40}]
          noise_sd: 2
          dropout_prob: 0.05
          device_id: sim-ecg-01
          clock: {domain: "sim:ecg", drift_ppm: 50, offset_ns: 1000000}

Ground truth is linearly interpolated between keyframes and held after the
last one. Every keyframe must define the same quantities.
"""

from __future__ import annotations

from itertools import pairwise
from pathlib import Path
from typing import Annotated, Final

import yaml
from pydantic import Field, StringConstraints, field_validator, model_validator

from esp.core.model import EspModel
from esp.core.scalars import Arousal, FiniteFloat, Intensity, UnitInterval, Valence
from esp.observation.model import Channel, DeviceId, Modality, UnitSymbol
from esp.semantics.affect import Label

QUANTITY_PATTERN: Final = r"^(emotion|readiness|context)\.[a-z][a-z0-9_\-]*$|^(valence|arousal)$"
Quantity = Annotated[str, StringConstraints(pattern=QUANTITY_PATTERN)]
EpisodeName = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9\-]*$", max_length=64)]
ClockDomainName = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_.:\-]*$")]


class Keyframe(EspModel):
    t_s: Annotated[float, Field(ge=0.0, allow_inf_nan=False)]
    emotion: dict[Label, Intensity] = Field(default_factory=dict)
    readiness: dict[Label, Intensity] = Field(default_factory=dict)
    context: dict[Label, UnitInterval] = Field(default_factory=dict)
    valence: Valence | None = None
    arousal: Arousal | None = None

    def quantities(self) -> dict[str, float]:
        """Flat view ``{"emotion.fear": 0.8, "valence": -0.2, ...}``."""
        flat: dict[str, float] = {}
        for group in ("emotion", "readiness", "context"):
            for k, v in getattr(self, group).items():
                flat[f"{group}.{k}"] = v
        if self.valence is not None:
            flat["valence"] = self.valence
        if self.arousal is not None:
            flat["arousal"] = self.arousal
        return flat


class ClockSpec(EspModel):
    domain: ClockDomainName
    drift_ppm: Annotated[float, Field(ge=-1000.0, le=1000.0, allow_inf_nan=False)] = 0.0
    offset_ns: Annotated[int, Field(ge=0, le=10**15)] = 0
    jitter_ns: Annotated[int, Field(ge=0, le=10**9)] = 0


class LinearTerm(EspModel):
    quantity: Quantity
    gain: FiniteFloat


class StreamSpec(EspModel):
    modality: Modality
    channel: Channel
    unit: UnitSymbol
    rate_hz: Annotated[float, Field(gt=0.0, le=1000.0, allow_inf_nan=False)]
    base: FiniteFloat
    terms: tuple[LinearTerm, ...] = ()
    noise_sd: Annotated[float, Field(ge=0.0, allow_inf_nan=False)] = 0.0
    dropout_prob: Annotated[float, Field(ge=0.0, lt=1.0, allow_inf_nan=False)] = 0.0
    device_id: DeviceId
    clock: ClockSpec


class EpisodeSpec(EspModel):
    name: EpisodeName
    seed: Annotated[int, Field(ge=0, le=2**63 - 1)]
    duration_s: Annotated[float, Field(gt=0.0, le=3600.0, allow_inf_nan=False)]
    frame_rate_hz: Annotated[float, Field(gt=0.0, le=1000.0, allow_inf_nan=False)]
    keyframes: Annotated[tuple[Keyframe, ...], Field(min_length=1)]
    streams: tuple[StreamSpec, ...] = ()

    @field_validator("keyframes")
    @classmethod
    def _keyframes(cls, value: tuple[Keyframe, ...]) -> tuple[Keyframe, ...]:
        if value[0].t_s != 0.0:
            msg = "the first keyframe must be at t_s = 0"
            raise ValueError(msg)
        if any(b.t_s <= a.t_s for a, b in pairwise(value)):
            msg = "keyframe times must strictly increase"
            raise ValueError(msg)
        names = set(value[0].quantities())
        if any(set(k.quantities()) != names for k in value):
            msg = "every keyframe must define the same quantities"
            raise ValueError(msg)
        return value

    @model_validator(mode="after")
    def _streams(self) -> EpisodeSpec:
        known = set(self.keyframes[0].quantities())
        for s in self.streams:
            for term in s.terms:
                if term.quantity not in known:
                    msg = f"stream {s.channel}: unknown quantity {term.quantity!r}"
                    raise ValueError(msg)
        keys = [(s.device_id, s.modality, s.channel) for s in self.streams]
        if len(set(keys)) != len(keys):
            msg = "stream (device, modality, channel) must be unique"
            raise ValueError(msg)
        return self


def load_episode_yaml(source: str | Path) -> EpisodeSpec:
    """Parse an episode from YAML text or a file path (``yaml.safe_load`` only)."""
    text = source.read_text(encoding="utf-8") if isinstance(source, Path) else source
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or set(data) != {"episode"}:
        msg = "YAML must contain exactly one top-level key 'episode'"
        raise ValueError(msg)
    return EpisodeSpec.from_data(data["episode"])
