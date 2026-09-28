# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Semantic bindings between typed elements (plan section 13, WP-005).

A binding ("fear *elicited_by* possible dismissal") is semantically valuable
and privacy sensitive. Bindings are separately maskable: a person can share
*fear* without sharing *why*.

Disclosure rule (default deny): a binding is disclosed only if

1. the policy explicitly permits the binding (by id or by relation class), and
2. **both** endpoint types are disclosed.

Rule 2 prevents a binding from leaking information about a masked type
(e.g. an ``elicited_by`` edge whose target is a withheld KNO item).
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import StrEnum, unique

from pydantic import model_validator

from esp.core.ids import UUID4, LocalRef
from esp.core.model import EspModel
from esp.core.provenance import Provenance
from esp.core.scalars import Confidence
from esp.core.taoss_types import TaossType


@unique
class RelationClass(StrEnum):
    """Relation registry v1 (plan section 13.2)."""

    ELICITED_BY = "elicited_by"
    DIRECTED_AT = "directed_at"
    CAUSED_BY = "caused_by"
    GOAL_RELATED_TO = "goal_related_to"
    APPRAISED_AS = "appraised_as"
    TEMPORALLY_FOLLOWS = "temporally_follows"
    TEMPORALLY_OVERLAPS = "temporally_overlaps"
    SENSORY_SOURCE_OF = "sensory_source_of"
    CONTEXTUALIZED_BY = "contextualized_by"
    SUPPORTS = "supports"
    CONTRADICTS = "contradicts"


class TypedEndpoint(EspModel):
    type: TaossType
    ref: LocalRef


class SemanticBinding(EspModel):
    binding_id: UUID4
    relation: RelationClass
    source: TypedEndpoint
    target: TypedEndpoint
    confidence: Confidence
    provenance: Provenance
    consent_scope: LocalRef | None = None
    """Identifier of the consent scope/capability this binding falls under."""

    @model_validator(mode="after")
    def _no_self_loop(self) -> SemanticBinding:
        if self.source == self.target:
            msg = "a binding must connect two different elements"
            raise ValueError(msg)
        return self

    @property
    def endpoint_types(self) -> frozenset[TaossType]:
        return frozenset({self.source.type, self.target.type})


class BindingPolicy(EspModel):
    """Which bindings may be disclosed. Empty policy = disclose none."""

    allowed_binding_ids: frozenset[UUID4] = frozenset()
    allowed_relations: frozenset[RelationClass] = frozenset()

    def permits(self, binding: SemanticBinding) -> bool:
        return (
            binding.binding_id in self.allowed_binding_ids
            or binding.relation in self.allowed_relations
        )


def disclose_bindings(
    bindings: Iterable[SemanticBinding],
    disclosed_types: frozenset[TaossType],
    policy: BindingPolicy,
) -> tuple[SemanticBinding, ...]:
    """Return only the bindings that may be disclosed (default deny)."""
    return tuple(b for b in bindings if policy.permits(b) and b.endpoint_types <= disclosed_types)
