# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-005 acceptance tests. The full wire-level test is in WP-011/WP-049."""

import itertools
import uuid

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from esp.core.taoss_types import TaossType
from esp.semantics.bindings import (
    BindingPolicy,
    RelationClass,
    SemanticBinding,
    TypedEndpoint,
    disclose_bindings,
)
from tests.unit.semantics.helpers import MODEL

ALL = frozenset(TaossType)


def fear_elicited_by_dismissal() -> SemanticBinding:
    return SemanticBinding(
        binding_id=uuid.uuid4(),
        relation=RelationClass.ELICITED_BY,
        source=TypedEndpoint(type=TaossType.EMO, ref="emotion_episode_17"),
        target=TypedEndpoint(type=TaossType.KNO, ref="possible_dismissal"),
        confidence=0.84,
        provenance=MODEL,
        consent_scope="cap-emo-only",
    )


def test_roundtrip() -> None:
    b = fear_elicited_by_dismissal()
    assert SemanticBinding.from_json(b.canonical_json()) == b


def test_self_loop_rejected() -> None:
    e = TypedEndpoint(type=TaossType.EMO, ref="x")
    with pytest.raises(ValidationError, match="two different elements"):
        SemanticBinding(
            binding_id=uuid.uuid4(),
            relation=RelationClass.SUPPORTS,
            source=e,
            target=e,
            confidence=0.5,
            provenance=MODEL,
        )


def test_default_policy_discloses_nothing() -> None:
    assert disclose_bindings([fear_elicited_by_dismissal()], ALL, BindingPolicy()) == ()


def test_critical_share_fear_without_its_cause() -> None:
    """EMO is disclosed; the elicited_by -> KNO binding is masked."""
    b = fear_elicited_by_dismissal()
    emo_only = frozenset({TaossType.EMO})
    # (a) KNO masked: even an explicitly permitted binding must not leak its target.
    permissive = BindingPolicy(allowed_relations=frozenset(RelationClass))
    assert disclose_bindings([b], emo_only, permissive) == ()
    # (b) KNO disclosed for other content, but this binding not permitted.
    assert disclose_bindings([b], ALL, BindingPolicy()) == ()
    # (c) only when both types and the binding are permitted does it appear.
    by_id = BindingPolicy(allowed_binding_ids=frozenset({b.binding_id}))
    assert disclose_bindings([b], ALL, by_id) == (b,)


@given(
    types=st.frozensets(st.sampled_from(TaossType)),
    permit=st.booleans(),
    src=st.sampled_from(TaossType),
    dst=st.sampled_from(TaossType),
)
def test_disclosure_matches_oracle(
    types: frozenset[TaossType], permit: bool, src: TaossType, dst: TaossType
) -> None:
    b = SemanticBinding(
        binding_id=uuid.uuid4(),
        relation=RelationClass.CONTEXTUALIZED_BY,
        source=TypedEndpoint(type=src, ref="a"),
        target=TypedEndpoint(type=dst, ref="b"),
        confidence=0.5,
        provenance=MODEL,
    )
    policy = BindingPolicy(allowed_binding_ids=frozenset({b.binding_id}) if permit else frozenset())
    disclosed = disclose_bindings([b], types, policy)
    assert (disclosed == (b,)) == (permit and src in types and dst in types)


def test_relation_registry_v1() -> None:
    assert len(RelationClass) == 11
    for a, c in itertools.combinations(RelationClass, 2):
        assert a.value != c.value
