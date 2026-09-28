# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Emotion episodes and traces (plan section 11). Linked to TEM."""

from __future__ import annotations

from itertools import pairwise
from typing import Annotated

from pydantic import Field, field_validator, model_validator

from esp.core.ids import UUID4
from esp.core.model import EspModel
from esp.core.scalars import FiniteFloat, UInt64, UnitInterval
from esp.semantics.affect import Label


class EmotionEpisode(EspModel):
    """An emotion as a process with onset, peak and end (reference-clock ns)."""

    id: UUID4
    label: Label | None = None
    onset_ns: UInt64
    peak_ns: UInt64
    end_ns: UInt64 | None = None
    """``None`` while the episode is ongoing."""
    decay_half_life_ms: Annotated[float, Field(gt=0.0, allow_inf_nan=False)] | None = None
    persistence: UnitInterval | None = None
    volatility: UnitInterval | None = None
    recurrence: UnitInterval | None = None

    @model_validator(mode="after")
    def _ordered(self) -> EmotionEpisode:
        if self.peak_ns < self.onset_ns:
            msg = "peak must not precede onset"
            raise ValueError(msg)
        if self.end_ns is not None and self.end_ns < self.peak_ns:
            msg = "end must not precede peak"
            raise ValueError(msg)
        return self

    @property
    def rise_time_ms(self) -> float:
        """Derived: ``(peak - onset)`` in milliseconds."""
        return (self.peak_ns - self.onset_ns) / 1e6


class TracePoint(EspModel):
    t_ns: UInt64
    value: FiniteFloat


class AffectTrace(EspModel):
    """Time course of one category or dimension; strictly increasing time."""

    quantity: Label
    """Category label or dimension name, e.g. ``fear`` or ``valence``."""
    points: Annotated[tuple[TracePoint, ...], Field(min_length=1)]

    @field_validator("points")
    @classmethod
    def _increasing(cls, value: tuple[TracePoint, ...]) -> tuple[TracePoint, ...]:
        for a, b in pairwise(value):
            if b.t_ns <= a.t_ns:
                msg = "trace time stamps must strictly increase"
                raise ValueError(msg)
        return value
