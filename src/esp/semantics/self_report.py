# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Self reports (plan sections 4.3, 19.2). A self report is its own evidence source.

A report stores the *raw* response on its declared scale. The mapping to
``[0, 1]`` is linear, ``(raw - min) / (max - min)``, and is recorded as a
derived view — the raw answer is never overwritten.
"""

from __future__ import annotations

from enum import StrEnum, unique
from typing import Annotated

from pydantic import Field, StringConstraints, field_validator, model_validator

from esp.core.clock import ClockStamp
from esp.core.ids import UUID4, RegistryName
from esp.core.model import EspModel
from esp.core.provenance import AffectScope, Provenance, SourceKind
from esp.core.scalars import Confidence
from esp.semantics.affect import AffectiveDescriptor, CategoryEstimate, Label
from esp.semantics.intention import ActionReadiness, IntentionState


@unique
class Construct(StrEnum):
    """What a self-report item asks about."""

    EMOTION_CATEGORY = "emotion_category"
    VALENCE = "valence"
    AROUSAL = "arousal"
    AFFECT_INTENSITY = "affect_intensity"
    ACTION_READINESS = "action_readiness"


class SelfReportItem(EspModel):
    kind: Construct
    label: Label | None = None
    """Category / tendency label; required for categories and action readiness."""
    raw: int
    scale_min: int
    scale_max: int
    certainty: Confidence | None = None
    """Respondent's own certainty, if asked."""

    @model_validator(mode="after")
    def _check(self) -> SelfReportItem:
        if not self.scale_min < self.scale_max:
            msg = "scale_min must be < scale_max"
            raise ValueError(msg)
        if not self.scale_min <= self.raw <= self.scale_max:
            msg = f"raw response {self.raw} outside scale [{self.scale_min}, {self.scale_max}]"
            raise ValueError(msg)
        needs_label = self.kind in {Construct.EMOTION_CATEGORY, Construct.ACTION_READINESS}
        if needs_label != (self.label is not None):
            msg = f"label is {'required' if needs_label else 'not allowed'} for {self.kind}"
            raise ValueError(msg)
        return self

    @property
    def unit_value(self) -> float:
        """Linear mapping of the raw answer to ``[0, 1]``."""
        return (self.raw - self.scale_min) / (self.scale_max - self.scale_min)


Instrument = Annotated[str, StringConstraints(min_length=1, max_length=128)]


class SelfReport(EspModel):
    id: UUID4
    instrument: Instrument
    """Questionnaire / UI identifier, e.g. ``esp-wizard-of-oz-likert5``."""
    vocabulary_id: RegistryName
    timestamp: ClockStamp
    items: Annotated[tuple[SelfReportItem, ...], Field(min_length=1)]

    @field_validator("items")
    @classmethod
    def _unique_items(cls, value: tuple[SelfReportItem, ...]) -> tuple[SelfReportItem, ...]:
        keys = [(i.kind, i.label) for i in value]
        if len(set(keys)) != len(keys):
            msg = "each (kind, label) may be reported once"
            raise ValueError(msg)
        return value

    def provenance(self) -> Provenance:
        return Provenance(
            source_kind=SourceKind.SELF_REPORT, source_refs=(f"self_report:{self.id}",)
        )

    def to_affective_descriptor(self) -> AffectiveDescriptor:
        """Self-declared affect (plan section 4.5): scope ``SELF_DECLARED``."""
        valence: float | None = None
        arousal: float | None = None
        intensity: float | None = None
        categories: list[CategoryEstimate] = []
        for item in self.items:
            if item.kind is Construct.EMOTION_CATEGORY and item.label is not None:
                categories.append(
                    CategoryEstimate(
                        label=item.label, intensity=item.unit_value, confidence=item.certainty
                    )
                )
            elif item.kind is Construct.VALENCE:
                valence = 2.0 * item.unit_value - 1.0
            elif item.kind is Construct.AROUSAL:
                arousal = item.unit_value
            elif item.kind is Construct.AFFECT_INTENSITY:
                intensity = item.unit_value
        return AffectiveDescriptor(
            vocabulary_id=self.vocabulary_id,
            affect_scope=AffectScope.SELF_DECLARED,
            provenance=self.provenance(),
            valence=valence,
            arousal=arousal,
            intensity=intensity,
            categories=tuple(categories),
        )

    def to_intention_state(self) -> IntentionState:
        readiness = [
            ActionReadiness(tendency=i.label, intensity=i.unit_value, confidence=i.certainty)
            for i in self.items
            if i.kind is Construct.ACTION_READINESS and i.label is not None
        ]
        return IntentionState(provenance=self.provenance(), readiness=tuple(readiness))
