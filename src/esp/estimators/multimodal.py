# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Multimodal state-estimation baseline (WP-030) with the L2 subject-affect gate (WP-081).

Not an "emotion detector". Status: EXPERIMENTAL; no validity claim below
stage 4 of the claims ladder (plan section 25).

Inputs are optional and independent: self report, a text-derived valence
signal, voice activation features, calibrated physiological features and
context tags. Rules:

- every source yields its own claims with provenance; nothing is merged
  silently, and self reports are never overwritten;
- missing modalities produce no claim (and are listed), never a guess;
- signal quality multiplies confidence; below ``min_quality`` a source is
  dropped and listed;
- a per-source :class:`IsotonicCalibrator` may map raw confidence to its
  empirical accuracy;
- **WP-081:** affect about the subject inferred from physiology, voice or
  text (``affect_scope = INFERRED_SUBJECT``) is produced only with profile
  L2 (``0x02``+), a regulatory declaration that covers ``inferred_subject``
  and passes the Art. 5(1)(f) guard, and an explicit L2 consent reference.
  Otherwise these sources yield only neutral activation features (``SENSORY``).
- disagreements between self-declared and inferred affect are reported,
  not resolved.
"""

from __future__ import annotations

import math
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from esp.calibration.pipeline import StandardizedFeature
from esp.core.clock import ClockStamp
from esp.core.provenance import AffectScope, Provenance, SourceKind
from esp.estimators.base import EstimationContext, SemanticEstimate
from esp.estimators.confidence import IsotonicCalibrator
from esp.estimators.fusion import ConfidenceWeightedFusion, Conflict
from esp.evidence.claim import ClaimType, EvidenceClaim
from esp.regulatory.guard import RegulatoryDeclaration, require_permitted
from esp.semantics.self_report import SelfReport

PRODUCER = "esp-multimodal-baseline"
VERSION = "0.1.0"
L2 = 0x02


@dataclass(frozen=True, slots=True)
class SignalInput:
    """A scalar signal from one source (e.g. text valence, vocal pitch z-score)."""

    name: str
    value: float
    quality: float
    ref: str
    """Reference to the evidence (observation / feature id)."""


@dataclass(frozen=True, slots=True)
class MultimodalInputs:
    self_report: SelfReport | None = None
    text: SignalInput | None = None
    """Text-derived valence in [-1, 1] (from a separate, provenance-carrying analyzer)."""
    voice: tuple[SignalInput, ...] = ()
    """Voice activation proxies as robust z-scores (pitch, energy)."""
    physiology: tuple[tuple[StandardizedFeature, float], ...] = ()
    """(standardized feature, quality) from the WP-029 calibration pipeline."""
    context: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class L2Authorization:
    """Everything WP-081 requires before subject affect may be inferred."""

    declaration: RegulatoryDeclaration
    consent_ref: str
    """Reference to the subject's explicit L2 consent (e.g. capability id)."""


@dataclass(frozen=True, slots=True)
class MultimodalEstimate:
    estimate: SemanticEstimate
    fused: tuple[EvidenceClaim, ...]
    conflicts: tuple[Conflict, ...]
    self_vs_inferred: tuple[str, ...]
    missing: tuple[str, ...]
    dropped_low_quality: tuple[str, ...]
    inferred_affect_allowed: bool
    notes: tuple[str, ...] = ()


@dataclass(slots=True)
class _Run:
    stamp: ClockStamp
    allowed: bool
    notes: list[str]
    claims: list[EvidenceClaim] = field(default_factory=list)
    missing: list[str] = field(default_factory=list)
    dropped: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MultimodalBaseline:
    min_quality: float = 0.3
    base_confidence: Mapping[str, float] = field(
        default_factory=lambda: {"text": 0.5, "voice": 0.4, "physiology": 0.6}
    )
    calibrators: Mapping[str, IsotonicCalibrator] = field(default_factory=dict)
    disagreement_threshold: float = 0.4

    estimator_id: str = PRODUCER
    estimator_version: str = VERSION

    def run(
        self,
        inputs: MultimodalInputs,
        context: EstimationContext,
        authorization: L2Authorization | None = None,
    ) -> MultimodalEstimate:
        stamp = ClockStamp(
            source_ns=context.at_ns,
            monotonic_ns=context.at_ns,
            clock_domain="host:monotonic",
            sequence=0,
        )
        allowed, notes = self._inferred_allowed(context, authorization)
        run = _Run(stamp=stamp, allowed=allowed, notes=notes)
        if inputs.self_report is not None:
            run.claims += _self_report_claims(inputs.self_report, stamp)
        else:
            run.missing.append("self_report")
        self._activation_claims(inputs, run)
        self._text_claims(inputs.text, run)
        for tag in inputs.context:
            run.claims.append(
                EvidenceClaim(
                    id=uuid.uuid4(),
                    claim_type=ClaimType.CONTEXT,
                    claim=tag,
                    value=1.0,
                    confidence=1.0,
                    provenance=Provenance(source_kind=SourceKind.SELF_REPORT),
                    timestamp=stamp,
                )
            )
        if not inputs.context:
            run.missing.append("context")
        inferred = [c for c in run.claims if c.affect_scope is AffectScope.INFERRED_SUBJECT]
        fusion = ConfidenceWeightedFusion(conflict_threshold=self.disagreement_threshold).fuse(
            inferred, context
        )
        return MultimodalEstimate(
            estimate=SemanticEstimate(claims=tuple(run.claims)),
            fused=fusion.fused,
            conflicts=fusion.conflicts,
            self_vs_inferred=_self_vs_inferred(run.claims, self.disagreement_threshold),
            missing=tuple(run.missing),
            dropped_low_quality=tuple(run.dropped),
            inferred_affect_allowed=allowed,
            notes=tuple(run.notes),
        )

    def _activation_claims(self, inputs: MultimodalInputs, run: _Run) -> None:
        """Voice and physiology -> neutral activation; inferred arousal only under L2."""
        sources: dict[str, list[tuple[float, float, str]]] = {}
        if not inputs.voice:
            run.missing.append("voice")
        for v in inputs.voice:
            if v.quality < self.min_quality:
                run.dropped.append(f"voice:{v.name}")
            else:
                sources.setdefault("voice", []).append((math.tanh(v.value / 3), v.quality, v.ref))
        if not inputs.physiology:
            run.missing.append("physiology")
        for f, q in inputs.physiology:
            if q < self.min_quality:
                run.dropped.append(f"physiology:{f.name}")
            else:
                ref = f"{f.name}.cal:{f.profile_id}"
                sources.setdefault("physiology", []).append((math.tanh(f.value / 3), q, ref))
        for source, items in sources.items():
            weight = math.fsum(q for _, q, _ in items)
            value = math.fsum(a * q for a, q, _ in items) / weight
            refs = tuple(sorted({r for _, _, r in items}))
            conf = self._confidence(source, min(q for _, q, _ in items))
            run.claims.append(
                self._claim(
                    ClaimType.SENSORY,
                    f"{source}_activation",
                    value=value,
                    confidence=conf,
                    refs=refs,
                    stamp=run.stamp,
                    source=SourceKind.DERIVED,
                )
            )
            if run.allowed:
                run.claims.append(
                    self._claim(
                        ClaimType.AFFECT_DIMENSION,
                        "arousal",
                        value=(value + 1) / 2,
                        confidence=conf,
                        refs=refs,
                        stamp=run.stamp,
                        source=SourceKind.MODEL_INFERENCE,
                        scope=AffectScope.INFERRED_SUBJECT,
                    )
                )

    def _text_claims(self, t: SignalInput | None, run: _Run) -> None:
        if t is None:
            run.missing.append("text")
        elif t.quality < self.min_quality:
            run.dropped.append("text")
        elif not run.allowed:
            run.notes.append("text valence not used: inferring subject affect is not authorized")
        else:
            run.claims.append(
                self._claim(
                    ClaimType.AFFECT_DIMENSION,
                    "valence",
                    value=max(-1.0, min(1.0, t.value)),
                    confidence=self._confidence("text", t.quality),
                    refs=(t.ref,),
                    stamp=run.stamp,
                    source=SourceKind.MODEL_INFERENCE,
                    scope=AffectScope.INFERRED_SUBJECT,
                )
            )

    def _inferred_allowed(
        self, context: EstimationContext, auth: L2Authorization | None
    ) -> tuple[bool, list[str]]:
        if context.profile < L2:
            return False, ["profile L1: subject affect is never inferred (WP-081)"]
        if auth is None:
            return False, ["no L2 authorization: subject affect is not inferred"]
        require_permitted(auth.declaration)  # raises for prohibited / misdeclared deployments
        if AffectScope.INFERRED_SUBJECT not in auth.declaration.affect_scopes:
            return False, ["declaration does not cover inferred_subject"]
        if not auth.consent_ref:
            return False, ["missing L2 consent reference"]
        return True, [f"L2 inference authorized (consent {auth.consent_ref})"]

    def _confidence(self, source: str, quality: float) -> float:
        raw = max(0.0, min(1.0, self.base_confidence.get(source, 0.3) * quality))
        cal = self.calibrators.get(source)
        return cal(raw) if cal is not None else raw

    def _claim(
        self,
        kind: ClaimType,
        name: str,
        *,
        value: float,
        confidence: float,
        refs: tuple[str, ...],
        stamp: ClockStamp,
        source: SourceKind,
        scope: AffectScope | None = None,
    ) -> EvidenceClaim:
        return EvidenceClaim(
            id=uuid.uuid4(),
            claim_type=kind,
            claim=name,
            value=value,
            confidence=confidence,
            affect_scope=scope,
            provenance=Provenance(
                source_kind=source,
                producer_id=self.estimator_id,
                producer_version=self.estimator_version,
                source_refs=refs,
            ),
            timestamp=stamp,
        )


def _self_report_claims(report: SelfReport, stamp: ClockStamp) -> list[EvidenceClaim]:
    d = report.to_affective_descriptor()
    out = []
    for name, value in (("valence", d.valence), ("arousal", d.arousal)):
        if value is not None:
            out.append(
                EvidenceClaim(
                    id=uuid.uuid4(),
                    claim_type=ClaimType.AFFECT_DIMENSION,
                    claim=name,
                    value=value,
                    confidence=1.0,
                    affect_scope=AffectScope.SELF_DECLARED,
                    provenance=report.provenance(),
                    timestamp=stamp,
                )
            )
    for c in d.categories:
        out.append(
            EvidenceClaim(
                id=uuid.uuid4(),
                claim_type=ClaimType.EMOTION_CATEGORY,
                claim=c.label,
                value=c.intensity,
                confidence=1.0 if c.confidence is None else c.confidence,
                affect_scope=AffectScope.SELF_DECLARED,
                provenance=report.provenance(),
                timestamp=stamp,
            )
        )
    return out


def _self_vs_inferred(claims: Sequence[EvidenceClaim], threshold: float) -> tuple[str, ...]:
    out = []
    declared = {c.claim: c.value for c in claims if c.affect_scope is AffectScope.SELF_DECLARED}
    for c in claims:
        if c.affect_scope is AffectScope.INFERRED_SUBJECT and c.claim in declared:
            gap = abs(declared[c.claim] - c.value)
            if gap > threshold:
                out.append(
                    f"{c.claim}: self-declared {declared[c.claim]:.2f} vs inferred {c.value:.2f} "
                    f"({c.provenance.producer_id}); the self report stands"
                )
    return tuple(out)
