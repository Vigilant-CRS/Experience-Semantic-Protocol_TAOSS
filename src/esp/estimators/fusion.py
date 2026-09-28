# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fusion interface and an experimental reference fusion (plan section 21).

Fusion must not hide source conflicts. A :class:`FusionResult` always keeps
every input claim (including self reports, which are never overwritten),
reports disagreements explicitly, and adds fused claims as *additional*,
derived statements. Fused affect is an inference about a subject and
therefore requires profile L2+ (plan section 4.5).
"""

from __future__ import annotations

import math
import uuid
from collections import defaultdict
from collections.abc import Sequence
from typing import Protocol

from esp.core.model import EspModel
from esp.core.provenance import AffectScope, Provenance, SourceKind
from esp.core.scalars import UnitInterval
from esp.estimators.base import EstimationContext
from esp.evidence.claim import AFFECT_CLAIMS, EvidenceClaim
from esp.semantics.scope import check_scope_profile


class Conflict(EspModel):
    claim: str
    spread: float
    claim_ids: tuple[uuid.UUID, ...]


class FusionResult(EspModel):
    inputs: tuple[EvidenceClaim, ...]
    fused: tuple[EvidenceClaim, ...]
    conflicts: tuple[Conflict, ...]


class FusionEstimator(Protocol):
    @property
    def estimator_id(self) -> str: ...

    @property
    def estimator_version(self) -> str: ...

    def fuse(self, claims: Sequence[EvidenceClaim], context: EstimationContext) -> FusionResult: ...


class ConfidenceWeightedFusion:
    """EXPERIMENTAL: confidence-weighted mean per (claim_type, claim)."""

    estimator_id = "esp-fusion-cw"
    estimator_version = "0.1.0"

    def __init__(self, conflict_threshold: UnitInterval = 0.3) -> None:
        self._threshold = conflict_threshold

    def fuse(self, claims: Sequence[EvidenceClaim], context: EstimationContext) -> FusionResult:
        groups: dict[tuple[str, str], list[EvidenceClaim]] = defaultdict(list)
        for c in claims:
            groups[(c.claim_type.value, c.claim)].append(c)
        fused: list[EvidenceClaim] = []
        conflicts: list[Conflict] = []
        for (_, label), members in sorted(groups.items()):
            values = [m.value for m in members]
            spread = max(values) - min(values)
            ids = tuple(sorted((m.id for m in members), key=str))
            if len(members) > 1 and spread > self._threshold:
                conflicts.append(Conflict(claim=label, spread=spread, claim_ids=ids))
            weight = math.fsum(m.confidence for m in members)
            if len(members) < 2 or weight == 0.0:
                continue
            is_affect = members[0].claim_type in AFFECT_CLAIMS
            if is_affect:
                check_scope_profile(AffectScope.INFERRED_SUBJECT, context.profile)
            fused.append(
                EvidenceClaim(
                    id=uuid.uuid4(),
                    claim_type=members[0].claim_type,
                    claim=label,
                    value=math.fsum(m.value * m.confidence for m in members) / weight,
                    confidence=max(m.confidence for m in members) * (1.0 - min(1.0, spread)),
                    affect_scope=AffectScope.INFERRED_SUBJECT if is_affect else None,
                    provenance=Provenance(
                        source_kind=SourceKind.DERIVED,
                        producer_id=self.estimator_id,
                        producer_version=self.estimator_version,
                        source_refs=tuple(str(i) for i in ids),
                    ),
                    timestamp=members[0].timestamp,
                )
            )
        return FusionResult(inputs=tuple(claims), fused=tuple(fused), conflicts=tuple(conflicts))
