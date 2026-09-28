# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""EvidenceClaim: one interpreted statement with its evidence (plan section 14).

``value``, ``confidence`` and ``model_probability`` are independent fields.
Nothing in this module derives one from another.
"""

from __future__ import annotations

from enum import StrEnum, unique

from pydantic import model_validator

from esp.core.clock import ClockStamp
from esp.core.ids import UUID4, LocalRef
from esp.core.model import EspModel
from esp.core.provenance import AffectScope, Provenance
from esp.core.scalars import Confidence, Probability, Similarity
from esp.core.taoss_types import TaossType
from esp.semantics.affect import Label
from esp.semantics.scope import check_scope_source


@unique
class ClaimType(StrEnum):
    EMOTION_CATEGORY = "emotion_category"
    AFFECT_DIMENSION = "affect_dimension"
    ACTION_READINESS = "action_readiness"
    COMMITTED_INTENTION = "committed_intention"
    CONTEXT = "context"
    KNOWLEDGE = "knowledge"
    SENSORY = "sensory"
    TEMPORAL = "temporal"
    APPRAISAL = "appraisal"


#: Claim types that describe affect and therefore require an ``affect_scope``.
AFFECT_CLAIMS = frozenset({ClaimType.EMOTION_CATEGORY, ClaimType.AFFECT_DIMENSION})

#: Claim types whose value is an intensity-like quantity in [0, 1].
UNIT_VALUED_CLAIMS = frozenset(
    {ClaimType.EMOTION_CATEGORY, ClaimType.ACTION_READINESS, ClaimType.COMMITTED_INTENTION}
)

#: TAOSS type a claim type primarily belongs to (APPRAISAL spans several).
CLAIM_TAOSS_TYPE = {
    ClaimType.EMOTION_CATEGORY: TaossType.EMO,
    ClaimType.AFFECT_DIMENSION: TaossType.EMO,
    ClaimType.ACTION_READINESS: TaossType.INT,
    ClaimType.COMMITTED_INTENTION: TaossType.INT,
    ClaimType.CONTEXT: TaossType.CTX,
    ClaimType.KNOWLEDGE: TaossType.KNO,
    ClaimType.SENSORY: TaossType.SEN,
    ClaimType.TEMPORAL: TaossType.TEM,
}


class EvidenceClaim(EspModel):
    id: UUID4
    claim_type: ClaimType
    claim: Label
    """What is claimed, e.g. ``fear`` or ``valence``."""
    value: Similarity
    """In ``[0, 1]`` for intensity-like claims, ``[-1, 1]`` otherwise (e.g. valence)."""
    confidence: Confidence
    model_probability: Probability | None = None
    affect_scope: AffectScope | None = None
    provenance: Provenance
    calibration_profile: LocalRef | None = None
    timestamp: ClockStamp

    @model_validator(mode="after")
    def _rules(self) -> EvidenceClaim:
        if self.claim_type in UNIT_VALUED_CLAIMS and self.value < 0.0:
            msg = f"{self.claim_type.value} value must lie in [0, 1]"
            raise ValueError(msg)
        is_affect = self.claim_type in AFFECT_CLAIMS
        if is_affect and self.affect_scope is None:
            msg = "affect claims require affect_scope (plan section 4.5)"
            raise ValueError(msg)
        if not is_affect and self.affect_scope is not None:
            msg = "affect_scope is only allowed on affect claims"
            raise ValueError(msg)
        if self.affect_scope is not None:
            check_scope_source(self.affect_scope, self.provenance)
        return self
