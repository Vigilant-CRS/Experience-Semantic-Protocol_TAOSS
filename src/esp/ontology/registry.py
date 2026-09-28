# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Anchors, vocabularies, anchor sets, encoder realizations and the registry.

V13 separates an anchor's *identity* (stable id, label, reference set) from
its *realization* (an encoder-specific vector with a validity region). Shared
labels do not imply shared coordinates.

Registry rules (plan section 23.3):

- IDs are immutable; duplicate IDs are rejected.
- The meaning of an existing ID is never redefined: any change to a semantic
  field requires a new ID (new major version).
- Deprecated anchors remain resolvable; deprecation is one-way.
- The registry has a canonical serialization and a BLAKE2b-256 digest.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable
from enum import StrEnum, unique
from typing import Annotated, Final, Literal

from pydantic import Field, StringConstraints, field_validator, model_validator

from esp.core.errors import ErrorCode, RegistryError
from esp.core.ids import AnchorId, LocalRef, RegistryName, anchor_major_version
from esp.core.model import EspModel
from esp.core.scalars import FiniteFloat
from esp.core.taoss_types import L1_DIMS, TaossTypeName
from esp.core.versions import SemVer
from esp.semantics.affect import Label

#: Namespace for deterministic registry UUIDs (uuid5).
ESP_UUID_NAMESPACE: Final = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://github.com/Vigilant-CRS/Experience-Semantic-Protocol_TAOSS"
)

Text = Annotated[str, StringConstraints(min_length=1, max_length=2000)]
Reference = Annotated[str, StringConstraints(min_length=1, max_length=512)]
SpdxId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9.\-+]+$")]
EncoderId = Annotated[
    str,
    StringConstraints(pattern=r"^[a-z0-9][a-z0-9.\-]*@(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$"),
]


@unique
class AnchorStatus(StrEnum):
    ACTIVE = "active"
    DEPRECATED = "deprecated"


class Anchor(EspModel):
    """Semantic identity of an anchor. Coordinates live in realizations."""

    id: AnchorId
    type: TaossTypeName
    label: Label
    vocabulary_id: RegistryName
    definition: Text
    """Operational criteria describing what the anchor denotes."""
    references: tuple[Reference, ...] = ()
    """Versioned reference stimuli / criteria identifiers."""
    version: Annotated[int, Field(ge=1)]
    status: AnchorStatus = AnchorStatus.ACTIVE
    aliases: tuple[Label, ...] = ()

    @model_validator(mode="after")
    def _id_consistency(self) -> Anchor:
        _, type_part, label_part, _ = self.id.split(":")
        if type_part != self.type.name.lower():
            msg = f"anchor id {self.id} does not match type {self.type.name}"
            raise ValueError(msg)
        if label_part != self.label:
            msg = f"anchor id {self.id} does not match label {self.label!r}"
            raise ValueError(msg)
        if anchor_major_version(self.id) != self.version:
            msg = f"anchor id {self.id} does not match version {self.version}"
            raise ValueError(msg)
        if len(set(self.aliases)) != len(self.aliases) or self.label in self.aliases:
            msg = "aliases must be unique and differ from the label"
            raise ValueError(msg)
        return self

    def semantic_key(self) -> tuple[object, ...]:
        """Fields that define meaning; they may never change under the same id."""
        return (
            self.id,
            self.type,
            self.label,
            self.vocabulary_id,
            self.definition,
            self.references,
            self.version,
        )


class Vocabulary(EspModel):
    id: RegistryName
    type: TaossTypeName
    version: SemVer
    title: Text
    license: SpdxId
    anchors: Annotated[tuple[AnchorId, ...], Field(min_length=1)]

    @field_validator("anchors")
    @classmethod
    def _unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            msg = "vocabulary anchors must be unique"
            raise ValueError(msg)
        return value


class AnchorSet(EspModel):
    """Ordered anchor list used for anchor coordinates ``pi_t``."""

    id: RegistryName
    type: TaossTypeName
    anchors: Annotated[tuple[AnchorId, ...], Field(min_length=1)]

    @field_validator("anchors")
    @classmethod
    def _unique(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if len(set(value)) != len(value):
            msg = "anchor set members must be unique"
            raise ValueError(msg)
        return value

    @property
    def uuid(self) -> uuid.UUID:
        """Deterministic 16-byte registry id (used as ``anchor_set_id`` on the wire)."""
        return uuid.uuid5(ESP_UUID_NAMESPACE, f"anchor-set:{self.id}")


class ValidityRegion(EspModel):
    kind: Literal["cosine_min", "l2_ball"]
    threshold: Annotated[float, Field(allow_inf_nan=False)]

    @model_validator(mode="after")
    def _range(self) -> ValidityRegion:
        if self.kind == "cosine_min" and not -1.0 <= self.threshold <= 1.0:
            msg = "cosine_min threshold must lie in [-1, 1]"
            raise ValueError(msg)
        if self.kind == "l2_ball" and self.threshold <= 0.0:
            msg = "l2_ball radius must be positive"
            raise ValueError(msg)
        return self


class EncoderRealization(EspModel):
    """An encoder/version's validated coordinates for one anchor."""

    anchor_id: AnchorId
    encoder_id: EncoderId
    vector: tuple[FiniteFloat, ...]
    validity: ValidityRegion
    validation_report: LocalRef | None = None


def _sorted_unique[T: EspModel](items: Iterable[T], key_name: str, what: str) -> tuple[T, ...]:
    items = tuple(items)
    keys = [str(getattr(i, key_name)) for i in items]
    if len(set(keys)) != len(keys):
        duplicates = sorted({k for k in keys if keys.count(k) > 1})
        msg = f"duplicate {what} ids: {duplicates}"
        raise ValueError(msg)
    return tuple(sorted(items, key=lambda i: str(getattr(i, key_name))))


def _check_anchor_membership(anchors: Iterable[Anchor], vocabs: dict[str, Vocabulary]) -> None:
    for a in anchors:
        vocab = vocabs.get(a.vocabulary_id)
        if vocab is None or a.id not in vocab.anchors:
            msg = f"anchor {a.id} is not listed in vocabulary {a.vocabulary_id}"
            raise ValueError(msg)


def _check_vocabulary(v: Vocabulary, anchors: dict[str, Anchor]) -> None:
    names: set[str] = set()
    for anchor_id in v.anchors:
        anchor = anchors.get(anchor_id)
        if anchor is None:
            msg = f"vocabulary {v.id} references unknown anchor {anchor_id}"
            raise ValueError(msg)
        if anchor.type is not v.type or anchor.vocabulary_id != v.id:
            msg = f"anchor {anchor_id} does not belong to vocabulary {v.id}"
            raise ValueError(msg)
        if anchor.status is not AnchorStatus.ACTIVE:
            continue  # deprecated anchors resolve by id; labels belong to active ones
        for name in (anchor.label, *anchor.aliases):
            if name in names:
                msg = f"label/alias {name!r} is ambiguous among active anchors of {v.id}"
                raise ValueError(msg)
            names.add(name)


class Registry(EspModel):
    name: RegistryName
    version: SemVer
    anchors: tuple[Anchor, ...] = ()
    vocabularies: tuple[Vocabulary, ...] = ()
    anchor_sets: tuple[AnchorSet, ...] = ()
    realizations: tuple[EncoderRealization, ...] = ()

    @field_validator("anchors")
    @classmethod
    def _anchors(cls, v: tuple[Anchor, ...]) -> tuple[Anchor, ...]:
        return _sorted_unique(v, "id", "anchor")

    @field_validator("vocabularies")
    @classmethod
    def _vocabs(cls, v: tuple[Vocabulary, ...]) -> tuple[Vocabulary, ...]:
        return _sorted_unique(v, "id", "vocabulary")

    @field_validator("anchor_sets")
    @classmethod
    def _sets(cls, v: tuple[AnchorSet, ...]) -> tuple[AnchorSet, ...]:
        return _sorted_unique(v, "id", "anchor set")

    @field_validator("realizations")
    @classmethod
    def _realizations(cls, v: tuple[EncoderRealization, ...]) -> tuple[EncoderRealization, ...]:
        keys = [(r.anchor_id, r.encoder_id) for r in v]
        if len(set(keys)) != len(keys):
            msg = "one realization per (anchor, encoder)"
            raise ValueError(msg)
        return tuple(sorted(v, key=lambda r: (r.anchor_id, r.encoder_id)))

    @model_validator(mode="after")
    def _referential_integrity(self) -> Registry:
        anchors = {a.id: a for a in self.anchors}
        _check_anchor_membership(self.anchors, {v.id: v for v in self.vocabularies})
        for v in self.vocabularies:
            _check_vocabulary(v, anchors)
        for s in self.anchor_sets:
            for anchor_id in s.anchors:
                if anchor_id not in anchors or anchors[anchor_id].type is not s.type:
                    msg = f"anchor set {s.id}: {anchor_id} unknown or of wrong type"
                    raise ValueError(msg)
        for r in self.realizations:
            anchor = anchors.get(r.anchor_id)
            if anchor is None:
                msg = f"realization for unknown anchor {r.anchor_id}"
                raise ValueError(msg)
            if len(r.vector) != L1_DIMS[anchor.type]:
                msg = f"realization {r.anchor_id}@{r.encoder_id} has wrong dimension"
                raise ValueError(msg)
        return self

    # --- queries --------------------------------------------------------------

    def anchor(self, anchor_id: str) -> Anchor:
        """Resolve an anchor id; deprecated anchors stay resolvable."""
        for a in self.anchors:
            if a.id == anchor_id:
                return a
        msg = f"unknown anchor id {anchor_id!r}"
        raise RegistryError(msg, code=ErrorCode.REGISTRY_UNKNOWN_ID)

    def resolve_label(self, vocabulary_id: str, name: str) -> Anchor:
        """Resolve a label or alias within one vocabulary.

        The active anchor wins; otherwise the highest deprecated version.
        """
        matches = [
            a
            for a in self.anchors
            if a.vocabulary_id == vocabulary_id and (a.label == name or name in a.aliases)
        ]
        for a in matches:
            if a.status is AnchorStatus.ACTIVE:
                return a
        if matches:
            return max(matches, key=lambda a: a.version)
        msg = f"{name!r} not found in vocabulary {vocabulary_id!r}"
        raise RegistryError(msg, code=ErrorCode.REGISTRY_UNKNOWN_ID)

    def vocabulary(self, vocabulary_id: str) -> Vocabulary:
        for v in self.vocabularies:
            if v.id == vocabulary_id:
                return v
        msg = f"unknown vocabulary {vocabulary_id!r}"
        raise RegistryError(msg, code=ErrorCode.REGISTRY_UNKNOWN_ID)

    def anchor_set(self, set_id: str) -> AnchorSet:
        for s in self.anchor_sets:
            if s.id == set_id:
                return s
        msg = f"unknown anchor set {set_id!r}"
        raise RegistryError(msg, code=ErrorCode.REGISTRY_UNKNOWN_ID)

    def digest_hex(self) -> str:
        """BLAKE2b-256 over the canonical JSON, lower-case hex."""
        return self.canonical_digest().hex()

    # --- evolution --------------------------------------------------------------

    def with_anchor(self, anchor: Anchor) -> Registry:
        """Add an anchor (idempotent for identical content; conflicts are errors)."""
        for existing in self.anchors:
            if existing.id == anchor.id:
                if existing == anchor:
                    return self
                msg = f"anchor {anchor.id} already exists with different content"
                raise RegistryError(msg)
        data = self.model_dump(mode="json")
        data["anchors"] = [*data["anchors"], anchor.model_dump(mode="json")]
        return Registry.from_data(data)

    def deprecated(self, anchor_id: str) -> Registry:
        """Return a registry in which ``anchor_id`` is deprecated (still resolvable)."""
        self.anchor(anchor_id)  # raises for unknown ids
        data = self.model_dump(mode="json")
        for a in data["anchors"]:
            if a["id"] == anchor_id:
                a["status"] = AnchorStatus.DEPRECATED.value
        return Registry.from_data(data)


def check_evolution(old: Registry, new: Registry) -> None:
    """Enforce plan section 23.3 between two registry versions.

    Raises :class:`RegistryError` if an anchor disappears, changes meaning
    under the same id, is un-deprecated, or loses an alias.
    """
    new_anchors = {a.id: a for a in new.anchors}
    for a in old.anchors:
        b = new_anchors.get(a.id)
        if b is None:
            msg = f"anchor {a.id} was removed; deprecate it instead"
            raise RegistryError(msg)
        if a.semantic_key() != b.semantic_key():
            msg = f"anchor {a.id} changed meaning; semantic changes need a new id/major version"
            raise RegistryError(msg)
        if a.status is AnchorStatus.DEPRECATED and b.status is AnchorStatus.ACTIVE:
            msg = f"anchor {a.id} cannot be un-deprecated"
            raise RegistryError(msg)
        if not set(a.aliases) <= set(b.aliases):
            msg = f"anchor {a.id} lost aliases; aliases may only be added"
            raise RegistryError(msg)
    old_vocabs = {v.id: v for v in old.vocabularies}
    for v in new.vocabularies:
        prev = old_vocabs.get(v.id)
        if prev is not None and not set(prev.anchors) <= set(v.anchors):
            msg = f"vocabulary {v.id} dropped anchors"
            raise RegistryError(msg)
