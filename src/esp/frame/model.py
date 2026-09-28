# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""ExperienceFrame and disclosure (plan sections 13, 25, 28).

The frame is the *logical* object; the wire serialization is separate
(WP-014 ff.). Rules enforced here:

- each TAOSS type appears at most once, in TAOSS order;
- a type is either present, intentionally masked, or absent — never two;
- absence (⊥) is distinct from a zero latent (V13 section 7.2);
- EMO descriptors must use an affect scope allowed by the frame profile;
- bindings may only reference types present in the frame.

Disclosure removes withheld types *entirely* (masking = not in the object,
not merely hidden in a UI; plan section 28) and filters bindings with the
default-deny rule of :mod:`esp.semantics.bindings`.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal

import numpy as np
from numpy.typing import NDArray
from pydantic import Field, field_validator, model_validator

from esp.core.clock import ClockStamp
from esp.core.ids import UUID4, AnchorId, HexDigest, LocalRef, RegistryName
from esp.core.model import EspModel
from esp.core.scalars import FiniteFloat, Similarity, UInt32
from esp.core.taoss_types import TAOSS6_ORDER, TaossType, TaossTypeName
from esp.core.versions import CURRENT_SCHEMA_VERSION, SchemaVersion
from esp.ontology.registry import EncoderId
from esp.semantics.affect import AffectiveDescriptor
from esp.semantics.bindings import BindingPolicy, SemanticBinding, disclose_bindings
from esp.semantics.episode import EmotionEpisode
from esp.semantics.intention import IntentionState
from esp.semantics.scope import check_scope_profile
from esp.taoss.blocks import TAOSS6_L1, BlockLayout

#: V13 header ``profile`` values.
PROFILE_L1: Final = 0x01
PROFILE_L2: Final = 0x02


class AnchorCoordinate(EspModel):
    anchor_id: AnchorId
    similarity: Similarity


class TypeBlock(EspModel):
    """All information about one TAOSS type in a frame."""

    type: TaossTypeName
    latent: tuple[FiniteFloat, ...] | None = None
    """Typed latent ``E_t``; ``None`` in interpretation-only mode (V13 section 5.4)."""
    anchor_set_id: RegistryName | None = None
    anchors: tuple[AnchorCoordinate, ...] = ()
    similarity_kind: Literal["cosine", "projection", "rbf"] = "cosine"
    """How ``anchors`` were computed (V13 anchor coordinates; wire byte in 0x50)."""
    affect: tuple[AffectiveDescriptor, ...] = ()
    """EMO only: interpretable descriptors, one per source (never merged)."""
    episodes: tuple[EmotionEpisode, ...] = ()
    """EMO only."""
    intention: tuple[IntentionState, ...] = ()
    """INT only."""

    @model_validator(mode="after")
    def _consistency(self) -> TypeBlock:
        if self.latent is None and not self.anchors and not self.affect and not self.intention:
            msg = f"{self.type.name} block carries no content"
            raise ValueError(msg)
        if (self.affect or self.episodes) and self.type is not TaossType.EMO:
            msg = "affect descriptors and episodes are only allowed in the EMO block"
            raise ValueError(msg)
        if self.intention and self.type is not TaossType.INT:
            msg = "intention states are only allowed in the INT block"
            raise ValueError(msg)
        if self.anchors:
            if self.anchor_set_id is None:
                msg = "anchor coordinates require anchor_set_id"
                raise ValueError(msg)
            ids = [a.anchor_id for a in self.anchors]
            if len(set(ids)) != len(ids):
                msg = "anchor coordinates must be unique per anchor"
                raise ValueError(msg)
            prefix = f"esp:{self.type.name.lower()}:"
            if not all(i.startswith(prefix) for i in ids):
                msg = f"anchor coordinates of {self.type.name} must reference {prefix}* anchors"
                raise ValueError(msg)
        return self


class FrameProvenance(EspModel):
    encoder_id: EncoderId | None = None
    model_digest: HexDigest | None = None
    evidence_refs: tuple[LocalRef, ...] = ()


class ConsentRef(EspModel):
    capability_id: UUID4 | None = None


class DisclosurePolicy(EspModel):
    """What a sender releases to one recipient. Default: nothing."""

    allowed_types: tuple[TaossTypeName, ...] = ()
    bindings: BindingPolicy = BindingPolicy()
    keep_evidence_refs: bool = False
    """Evidence refs can hint at withheld sources; dropped unless explicitly kept."""

    @field_validator("allowed_types")
    @classmethod
    def _canonical(cls, value: tuple[TaossType, ...]) -> tuple[TaossType, ...]:
        return tuple(sorted(set(value)))


class ExperienceFrame(EspModel):
    schema_version: SchemaVersion = CURRENT_SCHEMA_VERSION
    frame_id: UUID4
    timeline_id: UUID4
    sequence: UInt32
    profile: Annotated[int, Field(ge=0x01, le=0xFF)] = PROFILE_L1
    timestamp: ClockStamp
    types: tuple[TypeBlock, ...] = ()
    masked_types: tuple[TaossTypeName, ...] = ()
    """Types intentionally withheld by sender consent (generalizes EMO_MASKED)."""
    bindings: tuple[SemanticBinding, ...] = ()
    provenance: FrameProvenance = FrameProvenance()
    consent: ConsentRef = ConsentRef()

    @field_validator("types")
    @classmethod
    def _taoss_ordered(cls, value: tuple[TypeBlock, ...]) -> tuple[TypeBlock, ...]:
        seen = [b.type for b in value]
        if len(set(seen)) != len(seen):
            msg = "each TAOSS type may appear at most once"
            raise ValueError(msg)
        return tuple(sorted(value, key=lambda b: b.type))

    @field_validator("masked_types")
    @classmethod
    def _masked_canonical(cls, value: tuple[TaossType, ...]) -> tuple[TaossType, ...]:
        return tuple(sorted(set(value)))

    @field_validator("bindings")
    @classmethod
    def _bindings_canonical(cls, value: tuple[SemanticBinding, ...]) -> tuple[SemanticBinding, ...]:
        ids = [b.binding_id for b in value]
        if len(set(ids)) != len(ids):
            msg = "binding ids must be unique"
            raise ValueError(msg)
        return tuple(sorted(value, key=lambda b: str(b.binding_id)))

    @model_validator(mode="after")
    def _frame_rules(self) -> ExperienceFrame:
        present = set(self.present_types)
        if present & set(self.masked_types):
            msg = "a type cannot be both present and masked (mask invariant)"
            raise ValueError(msg)
        for block in self.types:
            if block.latent is not None and len(block.latent) != TAOSS6_L1.dims[block.type]:
                msg = f"{block.type.name} latent must have {TAOSS6_L1.dims[block.type]} dims"
                raise ValueError(msg)
            for descriptor in block.affect:
                check_scope_profile(descriptor.affect_scope, self.profile)
        for b in self.bindings:
            if not b.endpoint_types <= present:
                msg = f"binding {b.binding_id} references a type that is not present"
                raise ValueError(msg)
        return self

    @property
    def present_types(self) -> tuple[TaossType, ...]:
        return tuple(b.type for b in self.types)

    def block(self, t: TaossType) -> TypeBlock | None:
        """The block of type ``t`` or ``None`` (⊥: absent or masked)."""
        for b in self.types:
            if b.type is t:
                return b
        return None

    def latent_vector(self, layout: BlockLayout = TAOSS6_L1) -> NDArray[np.float64]:
        """Compose the full latent; every layout type must carry a latent."""
        parts: dict[TaossType, NDArray[np.float64]] = {}
        for t in layout.types:
            block = self.block(t)
            if block is None or block.latent is None:
                msg = f"{t.name} latent is absent (⊥); refusing to substitute zeros"
                raise ValueError(msg)
            parts[t] = np.asarray(block.latent, dtype=np.float64)
        return layout.compose(parts)

    def disclose(self, policy: DisclosurePolicy) -> ExperienceFrame:
        """Return the frame a recipient may receive under ``policy``.

        Withheld present types are removed entirely and listed in
        ``masked_types``. Bindings follow the default-deny rule.
        """
        allowed = frozenset(policy.allowed_types)
        kept = tuple(b for b in self.types if b.type in allowed)
        withheld = {b.type for b in self.types if b.type not in allowed}
        disclosed_types = frozenset(b.type for b in kept)
        bindings = disclose_bindings(self.bindings, disclosed_types, policy.bindings)
        provenance = FrameProvenance(
            encoder_id=self.provenance.encoder_id,
            model_digest=self.provenance.model_digest,
            evidence_refs=self.provenance.evidence_refs if policy.keep_evidence_refs else (),
        )
        return ExperienceFrame(
            schema_version=self.schema_version,
            frame_id=self.frame_id,
            timeline_id=self.timeline_id,
            sequence=self.sequence,
            profile=self.profile,
            timestamp=self.timestamp,
            types=kept,
            masked_types=tuple(sorted(set(self.masked_types) | withheld)),
            bindings=bindings,
            provenance=provenance,
            consent=self.consent,
        )


#: Types in TAOSS order, for convenience.
ALL_TYPES: Final = TAOSS6_ORDER
