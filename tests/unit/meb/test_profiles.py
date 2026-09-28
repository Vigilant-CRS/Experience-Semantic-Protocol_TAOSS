# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-066: T_mach, domain profiles, M2H defaults, assistive relay."""

import hashlib
import uuid

import pytest

from esp.codec.errors import WireError
from esp.codec.header import ConsentFlags
from esp.consent.capability import AudienceMode, ReceiverPolicy, Rights, SenderCapability
from esp.core.provenance import AffectScope, Provenance, SourceKind
from esp.core.taoss_types import TaossType, types_to_bitmap
from esp.frame.model import PROFILE_L1, PROFILE_L2
from esp.meb.profiles import (
    ASSISTIVE,
    DOMAIN_PROFILES,
    DRONE_SWARM,
    M2H_BASELINE,
    SURGICAL,
    T_MACH,
    VEHICLE_HANDOVER,
    MebError,
    check_assistive_relay,
    check_machine_types,
    m2h_types,
)
from esp.semantics.affect import AffectiveDescriptor
from esp.session.profiles import CUSTOM_PROFILES, TypeSetProfile, custom_profile_digest

NO_RIGHTS = Rights(0)
pytestmark = pytest.mark.security
K, I, E, C, S, T = (
    TaossType.KNO,
    TaossType.INT,
    TaossType.EMO,
    TaossType.CTX,
    TaossType.SEN,
    TaossType.TEM,
)


def cap(types: frozenset[TaossType], rights: Rights = NO_RIGHTS) -> SenderCapability:
    return SenderCapability(
        capability_id=uuid.uuid4(),
        types_allowed=types_to_bitmap(types),
        rights=rights,
        max_segments=10,
        dp_epsilon_ceiling=0.0,
        valid_until_ns=10**18,
        audience_mode=AudienceMode.RECIPIENT_PUBKEY,
        audience_value=b"\x01" * 32,
        issuer_pk=b"\x02" * 32,
        nonce=b"\x03" * 16,
    )


def policy(types: frozenset[TaossType]) -> ReceiverPolicy:
    return ReceiverPolicy(
        accept_types=types,
        norm_caps=dict.fromkeys(types, 1.0),
        valence_bounds=None,
        rate_limit_hz=10,
        valid_from_ns=0,
        valid_until_ns=10**18,
        policy_id="test",
    )


def test_t_mach_excludes_emo() -> None:
    assert frozenset({K, I, C, S, T}) == T_MACH
    assert E not in T_MACH
    assert check_machine_types({I, C}) == {I, C}
    with pytest.raises(MebError, match="never author EMO"):
        check_machine_types({I, E})


@pytest.mark.parametrize("profile", list(DOMAIN_PROFILES.values()), ids=lambda p: p.name)
def test_every_domain_profile_masks_emo_mandatorily(profile) -> None:  # type: ignore[no-untyped-def]
    ts = profile.type_set
    assert profile.registry in CUSTOM_PROFILES
    assert E not in ts.allowed
    assert ts.must_mask == {E}
    assert ts.allowed <= T_MACH
    present = ts.required
    ts.check(present, frozenset({E}))
    with pytest.raises(WireError, match="must be explicitly masked"):
        ts.check(present, frozenset())  # EMO_MASKED=0
    with pytest.raises(WireError, match="not allowed"):
        ts.check(present | {E}, frozenset())  # EMO bit


def test_handover_is_the_custom_set_without_kno() -> None:
    assert VEHICLE_HANDOVER.types == {I, C, T, S}
    with pytest.raises(WireError, match="not allowed"):
        VEHICLE_HANDOVER.type_set.check(frozenset({I, C, T, S, K}), frozenset({E}))
    with pytest.raises(WireError, match="required types missing"):
        VEHICLE_HANDOVER.type_set.check(frozenset({I, C, T}), frozenset({E}))


def test_surgical_requires_no_replay() -> None:
    ts = SURGICAL.type_set
    ts.check_flags(int(ConsentFlags.NO_REPLAY | ConsentFlags.EMO_MASKED))
    with pytest.raises(WireError, match="required consent flags"):
        ts.check_flags(int(ConsentFlags.EMO_MASKED))
    VEHICLE_HANDOVER.type_set.check_flags(0)  # no flag requirement elsewhere
    with pytest.raises(MebError, match="NO_REPLAY is mandatory"):
        SURGICAL.check_capability(cap(frozenset({I, S, T, K}), Rights.ALLOW_REPLAY))
    SURGICAL.check_capability(cap(frozenset({I, S, T, K})))


def test_capability_checks() -> None:
    VEHICLE_HANDOVER.check_capability(cap(frozenset({I, C, T, S})))
    with pytest.raises(MebError, match="never author EMO"):
        VEHICLE_HANDOVER.check_capability(cap(frozenset({I, C, T, S, E})))
    with pytest.raises(MebError, match="required types"):
        VEHICLE_HANDOVER.check_capability(cap(frozenset({I, C, T})))
    assert DRONE_SWARM.bundle_mode
    assert DRONE_SWARM.types == {I, C, T, K, S}


def test_type_set_profile_invariants() -> None:
    with pytest.raises(ValueError, match="only EMO"):
        TypeSetProfile("X", frozenset({I}), must_mask=frozenset({C}))
    with pytest.raises(ValueError, match="both allowed and mandatorily masked"):
        TypeSetProfile("X", frozenset({I}), frozenset({E}), must_mask=frozenset({E}))


def test_profile_digests_pin_the_new_fields_and_keep_old_ones() -> None:
    def old_digest(name: str) -> bytes:
        p = CUSTOM_PROFILES[name]
        sets = (p.required, p.optional, p.maskable)
        definition = "|".join([name, *(",".join(sorted(t.name for t in s)) for s in sets)])
        return hashlib.blake2b(definition.encode(), digest_size=32).digest()

    # pre-existing definitions without MEB fields keep their pinned digests
    assert custom_profile_digest("esp-typeset-demo-v1") == old_digest("esp-typeset-demo-v1")
    # MEB profiles pin must_mask / required flags: a weakened definition would differ
    for name in DOMAIN_PROFILES:
        assert custom_profile_digest(name) != old_digest(name)
    assert len({custom_profile_digest(n) for n in CUSTOM_PROFILES}) == len(CUSTOM_PROFILES)


def test_m2h_defaults_intersect_with_receiver_capability() -> None:
    assert frozenset({K, C, T}) == M2H_BASELINE
    # no receiver capability: default deny leaves at most {KNO, CTX}
    assert m2h_types(None) == {K, C}
    assert m2h_types(ReceiverPolicy.default_deny()) == {K, C}
    # TEM only when the receiver explicitly permits it
    assert m2h_types(policy(frozenset({K, C, T}))) == {K, C, T}
    assert m2h_types(policy(frozenset({C}))) == {C}
    # machine SEN needs an explicit user opt-in, even if the receiver accepts SEN
    offer = {K, C, T, S}
    everything = policy(frozenset({K, I, C, S, T}))
    assert m2h_types(everything, offer=offer) == {K, C, T}
    assert m2h_types(everything, offer=offer, sen_opt_in=True) == {K, C, T, S}
    with pytest.raises(MebError):
        m2h_types(everything, offer={K, E})


def _affect(scope: AffectScope, refs: tuple[str, ...]) -> AffectiveDescriptor:
    kind = (
        SourceKind.MODEL_INFERENCE if scope is AffectScope.INFERRED_SUBJECT else SourceKind.DERIVED
    )
    return AffectiveDescriptor(
        vocabulary_id="esp-emo-v13-basic8-v1",
        affect_scope=scope,
        provenance=Provenance(
            source_kind=kind, producer_id="relay", producer_version="1.0.0", source_refs=refs
        ),
        valence=-0.4,
    )


def test_assistive_relay_is_human_origin_only() -> None:
    assert E not in ASSISTIVE.types  # the device itself never authors EMO
    check_assistive_relay(
        _affect(AffectScope.MACHINE_RELAY, ("self_report.user1",)), frame_profile=PROFILE_L2
    )
    with pytest.raises(MebError, match="machine_relay"):
        check_assistive_relay(_affect(AffectScope.INFERRED_SUBJECT, ("x",)), frame_profile=2)
    # defence in depth: even an unvalidated object without human-origin refs is refused
    good = _affect(AffectScope.MACHINE_RELAY, ("self_report.user1",))
    unrefd = AffectiveDescriptor.model_construct(
        **(
            dict(good)
            | {
                "provenance": good.provenance.model_construct(
                    source_kind=SourceKind.DERIVED, source_refs=()
                )
            }
        )
    )
    with pytest.raises(MebError, match="human-origin"):
        check_assistive_relay(unrefd, frame_profile=PROFILE_L2)
    with pytest.raises(MebError, match="L2"):
        check_assistive_relay(
            _affect(AffectScope.MACHINE_RELAY, ("self_report.user1",)), frame_profile=PROFILE_L1
        )
