# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Source kinds, affect scope and provenance (plan sections 4.2, 4.3, 4.5, 14)."""

from __future__ import annotations

from enum import StrEnum, unique
from typing import Annotated

from pydantic import StringConstraints, model_validator

from esp.core.errors import ErrorCode
from esp.core.ids import HexDigest, LocalRef
from esp.core.model import EspModel
from esp.core.versions import SemVer


@unique
class SourceKind(StrEnum):
    """Where a statement comes from (plan section 14). Never merged silently."""

    SELF_REPORT = "self_report"
    HUMAN_ANNOTATION = "human_annotation"
    SENSOR_OBSERVATION = "sensor_observation"
    MODEL_INFERENCE = "model_inference"
    DERIVED = "derived"
    SYNTHETIC_GROUND_TRUTH = "synthetic_ground_truth"


#: Source kinds that are interpretations and therefore require provenance.
INFERENTIAL_SOURCES = frozenset({SourceKind.MODEL_INFERENCE, SourceKind.DERIVED})


@unique
class AffectScope(StrEnum):
    """What an affect statement is about (plan section 4.5, ADR-0008).

    V13 section 6.4: L1 EMO is content-side; subject-side inferred affect
    belongs to L2+ and must never be confused with it on the same channel.
    """

    CONTENT = "content"
    """Affect a content item expresses (scene, film, text). L1."""
    SELF_DECLARED = "self_declared"
    """A person's own report about their state. L1, source must be self_report."""
    INFERRED_SUBJECT = "inferred_subject"
    """A person's state inferred from observations. L2+ only."""
    MACHINE_RELAY = "machine_relay"
    """A human-derived affect vector relayed by a machine. L2+, human provenance."""


#: Lowest profile (V13 header ``profile`` byte) at which a scope is allowed.
MIN_PROFILE_FOR_SCOPE = {
    AffectScope.CONTENT: 0x01,
    AffectScope.SELF_DECLARED: 0x01,
    AffectScope.INFERRED_SUBJECT: 0x02,
    AffectScope.MACHINE_RELAY: 0x02,
}

ProducerId = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:@/\-]*$", max_length=128)
]


class ProvenanceError(ValueError):
    """Raised inside validators; surfaces as a pydantic ValidationError."""

    code = ErrorCode.PROVENANCE_REQUIRED


class Provenance(EspModel):
    """Who or what produced a statement, from which evidence."""

    source_kind: SourceKind
    producer_id: ProducerId | None = None
    """Estimator / encoder / annotator identifier, e.g. ``esp-emo-fusion``."""
    producer_version: SemVer | None = None
    model_digest: HexDigest | None = None
    source_refs: tuple[LocalRef, ...] = ()
    """References to the observations / claims this statement is based on."""

    @model_validator(mode="after")
    def _no_inference_without_provenance(self) -> Provenance:
        if self.source_kind in INFERENTIAL_SOURCES:
            if self.producer_id is None or self.producer_version is None:
                msg = f"{self.source_kind.value} requires producer_id and producer_version"
                raise ProvenanceError(msg)
            if not self.source_refs:
                msg = f"{self.source_kind.value} requires at least one source_ref"
                raise ProvenanceError(msg)
        if len(set(self.source_refs)) != len(self.source_refs):
            msg = "source_refs must be unique"
            raise ValueError(msg)
        return self
