# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""RuleBasedEstimator: transparent, calibrated feature rules.

Produces *derived features* (e.g. physiological activation relative to the
personal baseline), not emotions: plan section 4.2 separates
``ECG 112 bpm`` (observation) from ``physiological activation: high``
(derived feature) from ``fear 0.75`` (interpretation). Emotion inference is
out of scope here (L2+, WP-030/WP-081).
"""

from __future__ import annotations

import math
import uuid
from collections.abc import Sequence
from dataclasses import dataclass

from esp.calibration.model import CalibrationProfile
from esp.core.clock import ClockStamp
from esp.core.provenance import Provenance, SourceKind
from esp.estimators.base import EstimationContext, SemanticEstimate
from esp.evidence.claim import ClaimType, EvidenceClaim
from esp.observation.model import Modality, Observation


@dataclass(frozen=True, slots=True)
class ActivationRule:
    """``activation = tanh(robust_z(mean(window)) / scale)`` for one channel."""

    modality: Modality
    channel: str
    feature: str
    window_ns: int
    expected_samples: int
    scale: float = 3.0


class RuleBasedEstimator:
    estimator_id = "esp-rule-based"
    estimator_version = "0.1.0"

    def __init__(self, rules: Sequence[ActivationRule], calibration: CalibrationProfile) -> None:
        self._rules = tuple(rules)
        self._calibration = calibration

    def estimate(
        self, observations: Sequence[Observation], context: EstimationContext
    ) -> SemanticEstimate:
        claims: list[EvidenceClaim] = []
        for rule in self._rules:
            start = context.at_ns - rule.window_ns
            window = [
                o
                for o in observations
                if o.modality is rule.modality
                and o.channel == rule.channel
                and start < o.timestamp.monotonic_ns <= context.at_ns
            ]
            valid = [o for o in window if o.value is not None]
            if not valid:
                continue  # missing modality: no claim rather than a guess
            baseline = self._calibration.baseline(rule.modality, rule.channel, at_ns=context.at_ns)
            mean = math.fsum(o.value for o in valid if o.value is not None) / len(valid)
            activation = math.tanh(baseline.robust_z(mean) / rule.scale)
            qualities = [o.quality.signal_quality for o in valid]
            quality = min((q for q in qualities if q is not None), default=1.0)
            coverage = min(1.0, len(valid) / rule.expected_samples)
            claims.append(
                EvidenceClaim(
                    id=uuid.uuid4(),
                    claim_type=ClaimType.SENSORY,
                    claim=rule.feature,
                    value=activation,
                    confidence=coverage * quality,
                    provenance=Provenance(
                        source_kind=SourceKind.DERIVED,
                        producer_id=self.estimator_id,
                        producer_version=self.estimator_version,
                        source_refs=tuple(str(o.id) for o in valid),
                    ),
                    calibration_profile=f"cal:{self._calibration.id}",
                    timestamp=ClockStamp(
                        source_ns=context.at_ns,
                        monotonic_ns=context.at_ns,
                        clock_domain="host:monotonic",
                        sequence=0,
                    ),
                )
            )
        return SemanticEstimate(claims=tuple(claims))
