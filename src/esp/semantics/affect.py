# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""EMO semantic representation (plan sections 8-10).

Hybrid, theory-plural representation:

- Level B/D: named categories with **independent** intensities (no sum rule,
  no softmax, no winner-takes-all; mixed emotions are first class);
- Level C: V13 default descriptive dimensions valence/arousal/intensity plus
  optional profile-declared extra dimensions (``V13_COMPATIBLE_ADDENDUM``).

Intensity, confidence, model probability and anchor similarity are kept in
separate fields and are never derived from one another (plan section 9).
A relative composition can be *derived* on demand but is never stored.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import StringConstraints, field_validator, model_validator

from esp.core.ids import AnchorId, RegistryName
from esp.core.model import EspModel
from esp.core.provenance import AffectScope, Provenance
from esp.core.scalars import (
    Arousal,
    Confidence,
    FiniteFloat,
    Intensity,
    Probability,
    Similarity,
    Valence,
)
from esp.semantics.scope import check_scope_source

Label = Annotated[
    str, StringConstraints(pattern=r"^[a-z][a-z0-9_\-]*$", min_length=1, max_length=64)
]


class CategoryEstimate(EspModel):
    """One named category (e.g. ``fear``) with independent measures."""

    label: Label
    anchor_id: AnchorId | None = None
    """Registry anchor this label refers to, if any."""
    intensity: Intensity
    confidence: Confidence | None = None
    """Certainty of the source; ``None`` = not reported (e.g. plain self report)."""
    model_probability: Probability | None = None
    """Classifier probability, if a classifier produced this; never an intensity."""
    anchor_similarity: Similarity | None = None
    """Geometric similarity to the anchor realization; never an intensity."""


class DimensionValue(EspModel):
    """A profile-declared additional dimension (e.g. dominance, agency)."""

    name: Label
    value: FiniteFloat
    minimum: FiniteFloat
    maximum: FiniteFloat

    @model_validator(mode="after")
    def _in_declared_range(self) -> DimensionValue:
        if not self.minimum < self.maximum:
            msg = "dimension range must satisfy minimum < maximum"
            raise ValueError(msg)
        if not self.minimum <= self.value <= self.maximum:
            msg = f"{self.name}={self.value} outside declared [{self.minimum}, {self.maximum}]"
            raise ValueError(msg)
        return self


#: Names reserved for the V13 default dimensions.
V13_DIMENSIONS = frozenset({"valence", "arousal", "intensity"})


class AffectiveDescriptor(EspModel):
    """Interpretable description of an EMO state from one source."""

    vocabulary_id: RegistryName
    """Vocabulary profile of the category labels, e.g. ``esp-emo-v13-basic8-v1``."""
    affect_scope: AffectScope
    provenance: Provenance
    valence: Valence | None = None
    arousal: Arousal | None = None
    intensity: Intensity | None = None
    """Overall affect intensity (V13 default dimension)."""
    categories: tuple[CategoryEstimate, ...] = ()
    additional_dimensions: tuple[DimensionValue, ...] = ()

    @field_validator("categories")
    @classmethod
    def _canonical_categories(
        cls, value: tuple[CategoryEstimate, ...]
    ) -> tuple[CategoryEstimate, ...]:
        labels = [c.label for c in value]
        if len(set(labels)) != len(labels):
            msg = "category labels must be unique"
            raise ValueError(msg)
        return tuple(sorted(value, key=lambda c: c.label))

    @field_validator("additional_dimensions")
    @classmethod
    def _canonical_dimensions(cls, value: tuple[DimensionValue, ...]) -> tuple[DimensionValue, ...]:
        names = [d.name for d in value]
        if len(set(names)) != len(names):
            msg = "additional dimension names must be unique"
            raise ValueError(msg)
        if V13_DIMENSIONS.intersection(names):
            msg = "valence/arousal/intensity are V13 default fields, not additional dimensions"
            raise ValueError(msg)
        return tuple(sorted(value, key=lambda d: d.name))

    @model_validator(mode="after")
    def _scope_matches_source(self) -> AffectiveDescriptor:
        check_scope_source(self.affect_scope, self.provenance)
        return self

    def category(self, label: str) -> CategoryEstimate | None:
        for c in self.categories:
            if c.label == label:
                return c
        return None

    def composition(self) -> dict[str, float]:
        """Derived relative mix ``intensity_i / sum_j intensity_j`` (plan section 9.5).

        Optional and derived only: it discards absolute intensity and must
        never replace the stored intensities. Empty if all intensities are 0.
        """
        total = sum(c.intensity for c in self.categories)
        if total == 0.0:
            return {}
        return {c.label: c.intensity / total for c in self.categories}

    def active_categories(self, threshold: float) -> tuple[str, ...]:
        """All categories at or above ``threshold`` — possibly several (mixed states)."""
        return tuple(c.label for c in self.categories if c.intensity >= threshold)
