# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Regulatory declaration and guard (WP-078; V13 section 23; plan GAP-001).

This is engineering enforcement of a *declared* deployment, not legal advice
(V13 section 23: deploying parties must obtain their own counsel; plan
WP-084 legal review is pending).

Every pipeline start needs a :class:`RegulatoryDeclaration`. Under the EU AI
Act regime:

- **Art. 5(1)(f) guard**: inferring a natural person's *emotions*
  (``affect_scope = INFERRED_SUBJECT``) from *biometric* inputs in a
  *workplace* or *education* context without the medical/safety exception
  is prohibited. The pipeline does not start.
- **Annex III**: any other emotion-recognition system (emotions or
  intentions of natural persons inferred from biometric data) is high-risk.
  It must be declared as such, and the obligations checklist applies.

At runtime, :func:`check_frame` refuses frames whose affect statements carry
a scope the declaration does not cover. This is how a declared
``SELF_DECLARED``-only deployment stays one.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Annotated

from pydantic import Field, model_validator

from esp.core.errors import ErrorCode, EspError
from esp.core.model import EspModel
from esp.core.provenance import AffectScope
from esp.frame.model import ExperienceFrame


class RegulatoryError(EspError):
    code = ErrorCode.REGULATORY_DECLARATION_MISSING


class ProhibitedPracticeError(RegulatoryError):
    code = ErrorCode.REGULATORY_PROHIBITED_PRACTICE


class MisdeclarationError(RegulatoryError):
    code = ErrorCode.REGULATORY_MISDECLARED


class Regime(StrEnum):
    EU_AI_ACT = "eu_ai_act"
    EU_GDPR = "eu_gdpr"
    OTHER = "other"


class DeploymentContext(StrEnum):
    WORKPLACE = "workplace"
    EDUCATION = "education"
    MEDICAL = "medical"
    SAFETY = "safety"
    OTHER = "other"


class Exemption(StrEnum):
    NONE = "none"
    MEDICAL = "medical"
    SAFETY = "safety"


PROHIBITED_CONTEXTS = frozenset({DeploymentContext.WORKPLACE, DeploymentContext.EDUCATION})

#: Annex III high-risk obligations checklist (provider/deployer, by role).
HIGH_RISK_OBLIGATIONS = (
    "risk management system (Art. 9)",
    "data and data governance (Art. 10)",
    "technical documentation (Art. 11, Annex IV)",
    "record-keeping / automatic logs (Art. 12)",
    "transparency and instructions for use (Art. 13)",
    "human oversight (Art. 14)",
    "accuracy, robustness, cybersecurity (Art. 15)",
    "quality management system (Art. 17)",
    "conformity assessment and registration (Art. 43, 49)",
    "inform exposed natural persons of emotion recognition (Art. 50(3))",
    "fundamental rights impact assessment where applicable (Art. 27)",
)


class RegulatoryDeclaration(EspModel):
    """Mandatory per-profile declaration. Logged and auditable (plan WP-078)."""

    regimes: Annotated[tuple[Regime, ...], Field(min_length=1)]
    intended_use: Annotated[str, Field(min_length=1, max_length=500)]
    deployment_context: DeploymentContext
    biometric_inputs: bool
    """Are any inputs biometric data (face, voice, physiology, neural) in the legal sense?"""
    affect_scopes: tuple[AffectScope, ...]
    """Every ``affect_scope`` the pipeline may output."""
    infers_subject_intention: bool = False
    """Does the system infer natural persons' intentions from the inputs?"""
    exemption: Exemption = Exemption.NONE
    exemption_justification: Annotated[str, Field(max_length=2000)] = ""
    high_risk_declared: bool = False

    @model_validator(mode="after")
    def _canonical(self) -> RegulatoryDeclaration:
        if list(self.regimes) != sorted(set(self.regimes)):
            msg = "regimes must be sorted and unique"
            raise ValueError(msg)
        if list(self.affect_scopes) != sorted(set(self.affect_scopes)):
            msg = "affect_scopes must be sorted and unique"
            raise ValueError(msg)
        if (self.exemption is Exemption.NONE) != (not self.exemption_justification):
            msg = "an exemption needs a justification, and a justification needs an exemption"
            raise ValueError(msg)
        return self

    def digest(self) -> str:
        return hashlib.blake2b(self.canonical_json(), digest_size=32).hexdigest()

    def audit_record(self) -> dict[str, object]:
        a = assess(self)
        return {
            "declaration": self.model_dump(mode="json"),
            "declaration_digest": self.digest(),
            "emotion_recognition": a.emotion_recognition,
            "prohibited": a.prohibited,
            "high_risk": a.high_risk,
            "obligations": list(a.obligations),
        }


class Assessment(EspModel):
    emotion_recognition: bool
    prohibited: bool
    high_risk: bool
    obligations: tuple[str, ...]
    reasons: tuple[str, ...]


def assess(decl: RegulatoryDeclaration) -> Assessment:
    """Classify a declaration under the EU AI Act reading of V13 section 23."""
    if Regime.EU_AI_ACT not in decl.regimes:
        return Assessment(
            emotion_recognition=False,
            prohibited=False,
            high_risk=False,
            obligations=(),
            reasons=("EU AI Act not declared: no Art. 5 / Annex III classification",),
        )
    infers_emotion = AffectScope.INFERRED_SUBJECT in decl.affect_scopes
    recognition = decl.biometric_inputs and (infers_emotion or decl.infers_subject_intention)
    exempt = decl.exemption is not Exemption.NONE
    prohibited = (
        decl.biometric_inputs
        and infers_emotion
        and decl.deployment_context in PROHIBITED_CONTEXTS
        and not exempt
    )
    reasons: list[str] = []
    if prohibited:
        reasons.append(
            "Art. 5(1)(f): inferring emotions of natural persons from biometric data in "
            f"{decl.deployment_context.value} without the medical/safety exception"
        )
    elif recognition:
        reasons.append("emotion-recognition system (biometric inference): Annex III high-risk")
    high_risk = recognition and not prohibited
    return Assessment(
        emotion_recognition=recognition,
        prohibited=prohibited,
        high_risk=high_risk,
        obligations=HIGH_RISK_OBLIGATIONS if high_risk else (),
        reasons=tuple(reasons),
    )


def require_permitted(decl: RegulatoryDeclaration | None) -> Assessment:
    """Gate for every pipeline start. Raises instead of starting."""
    if decl is None:
        msg = "no regulatory declaration: the pipeline does not start"
        raise RegulatoryError(msg)
    a = assess(decl)
    if a.prohibited:
        raise ProhibitedPracticeError("; ".join(a.reasons))
    if a.high_risk and not decl.high_risk_declared:
        msg = "emotion recognition is high-risk (Annex III) but high_risk_declared is false"
        raise MisdeclarationError(msg)
    return a


def frame_scopes(frame: ExperienceFrame) -> frozenset[AffectScope]:
    """Affect scopes a frame asserts: descriptors and episodes (GAP-030 resolved)."""
    scopes: set[AffectScope] = set()
    for block in frame.types:
        scopes |= {d.affect_scope for d in block.affect}
        scopes |= {e.affect_scope for e in block.episodes}
    return frozenset(scopes)


def check_frame(decl: RegulatoryDeclaration, frame: ExperienceFrame) -> None:
    """Runtime enforcement: a frame may only carry declared affect scopes."""
    undeclared = frame_scopes(frame) - set(decl.affect_scopes)
    if undeclared:
        msg = f"frame carries undeclared affect scopes: {sorted(s.value for s in undeclared)}"
        raise MisdeclarationError(msg)
