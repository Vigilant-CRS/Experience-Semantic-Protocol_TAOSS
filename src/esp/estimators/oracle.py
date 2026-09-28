# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""OracleEstimator: returns the simulator's known ground truth (plan section 20.3).

The reference component for deterministic end-to-end tests. It ignores the
observations entirely; its claims are marked ``synthetic_ground_truth`` and
affect is a *simulated self report* (``SELF_DECLARED``, plan section 4.5).
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from typing import Final

from esp.core.clock import ClockStamp
from esp.core.provenance import AffectScope, Provenance, SourceKind
from esp.estimators.base import EstimationContext, SemanticEstimate
from esp.evidence.claim import ClaimType, EvidenceClaim
from esp.observation.model import Observation
from esp.simulation.engine import SimulatedEpisode

_GROUP_TO_CLAIM: Final = {
    "emotion": ClaimType.EMOTION_CATEGORY,
    "readiness": ClaimType.ACTION_READINESS,
    "context": ClaimType.CONTEXT,
}
_ORACLE_NAMESPACE: Final = uuid.UUID("0d9d3f4e-8b7a-4c61-9e2f-3a5b6c7d8e9f")


class OracleEstimator:
    estimator_id = "esp-oracle"
    estimator_version = "1.0.0"

    def __init__(self, episode: SimulatedEpisode) -> None:
        self._episode = episode
        self._provenance = Provenance(
            source_kind=SourceKind.SYNTHETIC_GROUND_TRUTH,
            producer_id=self.estimator_id,
            producer_version=self.estimator_version,
            source_refs=(f"episode:{episode.episode_id}",),
        )

    def _claim_id(self, t_ns: int, quantity: str) -> uuid.UUID:
        name = f"{self._episode.episode_id}:{t_ns}:{quantity}"
        return uuid.UUID(bytes=uuid.uuid5(_ORACLE_NAMESPACE, name).bytes, version=4)

    def estimate(
        self, observations: Sequence[Observation], context: EstimationContext
    ) -> SemanticEstimate:
        del observations  # the oracle knows the truth
        truth = self._episode.truth_at_ns(context.at_ns)
        stamp = ClockStamp(
            source_ns=context.at_ns,
            monotonic_ns=context.at_ns,
            clock_domain="sim:ground-truth",
            sequence=0,
        )
        claims: list[EvidenceClaim] = []
        for quantity, value in sorted(truth.items()):
            if "." in quantity:
                group, label = quantity.split(".", 1)
                claim_type = _GROUP_TO_CLAIM[group]
            else:
                label, claim_type = quantity, ClaimType.AFFECT_DIMENSION
            is_affect = claim_type in {ClaimType.EMOTION_CATEGORY, ClaimType.AFFECT_DIMENSION}
            claims.append(
                EvidenceClaim(
                    id=self._claim_id(context.at_ns, quantity),
                    claim_type=claim_type,
                    claim=label,
                    value=value,
                    confidence=1.0,
                    affect_scope=AffectScope.SELF_DECLARED if is_affect else None,
                    provenance=self._provenance,
                    timestamp=stamp,
                )
            )
        return SemanticEstimate(claims=tuple(claims))
