# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""INT semantics: action readiness is not committed intention (plan section 7.2).

A person can have a strong urge to flee (action readiness) without having
decided to leave (committed intention). The two are separate object types
and are never converted into one another.
"""

from __future__ import annotations

from pydantic import field_validator

from esp.core.ids import AnchorId
from esp.core.model import EspModel
from esp.core.provenance import Provenance
from esp.core.scalars import Confidence, Intensity, UnitInterval
from esp.semantics.affect import Label


class ActionReadiness(EspModel):
    """An action tendency / urge (e.g. ``avoid``, ``approach``, ``attack``, ``freeze``)."""

    tendency: Label
    anchor_id: AnchorId | None = None
    intensity: Intensity
    confidence: Confidence | None = None


class CommittedIntention(EspModel):
    """A goal the person has committed to pursue."""

    goal: Label
    anchor_id: AnchorId | None = None
    commitment: UnitInterval
    """Strength of commitment; 0 = merely considered, 1 = firmly decided."""
    confidence: Confidence | None = None


class IntentionState(EspModel):
    """INT description from one source. Readiness and commitment stay separate."""

    provenance: Provenance
    readiness: tuple[ActionReadiness, ...] = ()
    commitments: tuple[CommittedIntention, ...] = ()

    @field_validator("readiness")
    @classmethod
    def _canonical_readiness(
        cls, value: tuple[ActionReadiness, ...]
    ) -> tuple[ActionReadiness, ...]:
        keys = [r.tendency for r in value]
        if len(set(keys)) != len(keys):
            msg = "action-readiness tendencies must be unique"
            raise ValueError(msg)
        return tuple(sorted(value, key=lambda r: r.tendency))

    @field_validator("commitments")
    @classmethod
    def _canonical_commitments(
        cls, value: tuple[CommittedIntention, ...]
    ) -> tuple[CommittedIntention, ...]:
        keys = [c.goal for c in value]
        if len(set(keys)) != len(keys):
            msg = "committed goals must be unique"
            raise ValueError(msg)
        return tuple(sorted(value, key=lambda c: c.goal))
