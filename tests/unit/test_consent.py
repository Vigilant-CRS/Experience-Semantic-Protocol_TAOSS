# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-019 / WP-051 acceptance tests: capabilities and the Accept predicate."""

import dataclasses
import uuid

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv
from esp.consent.accept import (
    AcceptState,
    PacketFacts,
    audience_leaf,
    audience_proof_ok,
    audience_root,
    commit,
    evaluate,
)
from esp.consent.capability import (
    AudienceMode,
    ReceiverCapability,
    ReceiverPolicy,
    Rights,
    SenderCapability,
)
from esp.core.taoss_types import TaossType
from esp.crypto.primitives import CryptoError, SigningKey, blake2b

T = TaossType
MASTER = SigningKey.from_seed(b"\x31" * 32)
RECEIVER = SigningKey.from_seed(b"\x32" * 32)
NOISE_H = b"\x77" * 32
NOW = 1_000 * 10**9
DELTA = 2 * 10**9


def sender_cap(**kw: object) -> SenderCapability:
    fields: dict[str, object] = {
        "capability_id": uuid.UUID("11111111-2222-4333-8444-555555555555"),
        "types_allowed": 0x3F,
        "rights": Rights(0),
        "max_segments": 1_000,
        "dp_epsilon_ceiling": 8.0,
        "valid_until_ns": NOW + 3600 * 10**9,
        "audience_mode": AudienceMode.RECIPIENT_PUBKEY,
        "audience_value": RECEIVER.public_bytes,
        "issuer_pk": MASTER.public_bytes,
        "nonce": b"\x00" * 16,
    }
    fields.update(kw)
    return SenderCapability(**fields)  # type: ignore[arg-type]


def receiver_cap(**kw: object) -> ReceiverCapability:
    fields: dict[str, object] = {
        "accept_types": 0x0F,  # KNO INT EMO CTX
        "max_norm": (10.0, 10.0, 10.0, 10.0),
        "valence_bounds": (-0.5, 1.0),
        "rate_limit_hz": 50,
        "valid_from_ns": 0,
        "valid_until_ns": NOW + 3600 * 10**9,
        "nonce": b"\x01" * 16,
        "pk_receiver": RECEIVER.public_bytes,
        "noise_h": NOISE_H,
    }
    fields.update(kw)
    return ReceiverCapability(**fields)  # type: ignore[arg-type]


def facts(**kw: object) -> PacketFacts:
    fields: dict[str, object] = {
        "authenticated": True,
        "types": frozenset({T.KNO, T.CTX}),
        "consent_flags": 0x0006,  # NO_REPLAY | NO_STORE
        "norms": {T.KNO: 1.0, T.CTX: 1.0},
        "valence": None,
    }
    fields.update(kw)
    return PacketFacts(**fields)  # type: ignore[arg-type]


def decide(
    p: PacketFacts, c_s: SenderCapability | None, policy: ReceiverPolicy | None, **kw: object
):  # type: ignore[no-untyped-def]
    state = kw.pop("state", AcceptState())
    return evaluate(
        p,
        c_s,
        policy,
        state,  # type: ignore[arg-type]
        recipient_pk=kw.pop("recipient_pk", RECEIVER.public_bytes),  # type: ignore[arg-type]
        now_ns=kw.pop("now_ns", NOW),  # type: ignore[arg-type]
        clock_tolerance_ns=DELTA,
        **kw,  # type: ignore[arg-type]
    )


# --- codecs ---------------------------------------------------------------------


def test_sender_capability_roundtrip_signature_and_layout() -> None:
    cap = sender_cap(rights=Rights.ALLOW_STORE)
    tlv = cap.sign(MASTER)
    assert len(tlv.value) == 121 + 64
    assert SenderCapability.verify(tlv) == cap
    tampered = Tlv(
        0x22, tlv.value[:27] + bytes([tlv.value[27] ^ 1]) + tlv.value[28:]
    )  # max_segments
    with pytest.raises(CryptoError):
        SenderCapability.verify(tampered)
    other_issuer = dataclasses.replace(cap, issuer_pk=RECEIVER.public_bytes).sign(MASTER)
    with pytest.raises(CryptoError):
        SenderCapability.verify(other_issuer)


def test_sender_capability_field_rules() -> None:
    with pytest.raises(WireError, match="bits 2-7"):
        sender_cap(rights=Rights(0x04))
    with pytest.raises(WireError, match="reserved"):
        sender_cap(types_allowed=0x40)
    with pytest.raises(WireError, match="binary32"):
        sender_cap(dp_epsilon_ceiling=0.1)
    with pytest.raises(WireError, match="non-negative"):
        sender_cap(dp_epsilon_ceiling=-1.0)


def test_receiver_capability_roundtrip_and_session_binding() -> None:
    cap = receiver_cap()
    tlv = cap.sign(RECEIVER)
    assert len(tlv.value) == 4 + 16 + 8 + 18 + 16 + 32 + 32 + 64
    assert ReceiverCapability.verify(tlv, noise_h=NOISE_H) == cap
    with pytest.raises(CryptoError, match="another session"):
        ReceiverCapability.verify(tlv, noise_h=b"\x00" * 32)


def test_valence_bounds_present_iff_emo_accepted() -> None:
    no_emo = receiver_cap(accept_types=0x09, max_norm=(1.0, 1.0), valence_bounds=None)
    raw = no_emo.sign(RECEIVER)
    assert ReceiverCapability.verify(raw, noise_h=NOISE_H).valence_bounds is None
    assert len(raw.value) == 4 + 8 + 18 + 16 + 32 + 32 + 64
    with pytest.raises(WireError, match="iff EMO"):
        receiver_cap(accept_types=0x09, max_norm=(1.0, 1.0))
    with pytest.raises(WireError, match="iff EMO"):
        receiver_cap(valence_bounds=None)


def test_receiver_capability_rejects_inconsistent_encoding() -> None:
    tlv = receiver_cap().sign(RECEIVER)
    bad_n = Tlv(0x21, tlv.value[:3] + b"\x03" + tlv.value[4:])
    with pytest.raises(WireError, match="n_types"):
        ReceiverCapability.verify(bad_n, noise_h=NOISE_H)
    with pytest.raises(WireError, match="length"):
        ReceiverCapability.verify(Tlv(0x21, tlv.value + b"\x00"), noise_h=NOISE_H)


# --- Accept predicate -----------------------------------------------------------


def test_frame_before_consent_is_rejected() -> None:
    d = decide(facts(), None, ReceiverPolicy.default_deny())
    assert not d.accepted
    assert "2:no sender capability (no consent)" in d.violations


def test_default_deny_accepts_only_kno_ctx() -> None:
    policy = ReceiverPolicy.default_deny()
    assert decide(facts(), sender_cap(), policy).accepted
    emo = facts(types=frozenset({T.KNO, T.EMO}), norms={T.KNO: 1.0, T.EMO: 1.0})
    assert decide(emo, sender_cap(), policy).violations == ("3:types not permitted: EMO",)


def test_types_must_be_allowed_by_both_sides() -> None:
    policy = ReceiverPolicy.from_capability(receiver_cap())
    sen = facts(types=frozenset({T.SEN}), norms={T.SEN: 1.0})
    assert "3:types not permitted: SEN" in decide(sen, sender_cap(), policy).violations
    kno_only = sender_cap(types_allowed=0x01)
    assert not decide(facts(), kno_only, policy).accepted


def test_rights_flags() -> None:
    policy = ReceiverPolicy.default_deny()
    no_flags = facts(consent_flags=0)
    d = decide(no_flags, sender_cap(), policy)
    assert set(d.violations) == {
        "9:replay not allowed but NO_REPLAY not set",
        "9:store not allowed but NO_STORE not set",
    }
    permissive = sender_cap(rights=Rights.ALLOW_REPLAY | Rights.ALLOW_STORE)
    assert decide(no_flags, permissive, policy).accepted


def test_audience_pubkey_and_merkle_set() -> None:
    policy = ReceiverPolicy.default_deny()
    other = SigningKey.from_seed(b"\x40" * 32).public_bytes
    assert (
        "4:recipient not in audience"
        in decide(facts(), sender_cap(), policy, recipient_pk=other).violations
    )
    members = [RECEIVER.public_bytes, other, b"\x41" * 32]
    root = audience_root(members)
    cap = sender_cap(audience_mode=AudienceMode.AUDIENCE_SET_ROOT, audience_value=root)
    assert "4:recipient not in audience" in decide(facts(), cap, policy).violations  # no proof
    # build the proof path for a 3-member tree (leaves sorted, last duplicated)
    leaves = sorted(audience_leaf(m) for m in members)
    leaves.append(leaves[-1])
    mine = leaves.index(audience_leaf(RECEIVER.public_bytes))
    sibling = leaves[mine ^ 1]
    parents = [blake2b(b"esp/v1/audience-node" + leaves[i] + leaves[i + 1]) for i in (0, 2)]
    proof = [(sibling, mine % 2 == 1), (parents[1 - mine // 2], mine // 2 == 1)]
    assert audience_proof_ok(root, RECEIVER.public_bytes, proof)
    assert decide(facts(), cap, policy, audience_proof=proof).accepted


def test_max_segments_survive_across_sessions_and_count_only_accepted() -> None:
    policy = ReceiverPolicy.default_deny()
    cap = sender_cap(max_segments=2)
    state = AcceptState()
    for i in range(2):
        p = facts()
        assert decide(p, cap, policy, state=state, now_ns=NOW + i * 10**9).accepted
        commit(p, cap, state, recipient_pk=RECEIVER.public_bytes, now_ns=NOW + i * 10**9)
    # a "new session" reuses the same persistent AcceptState: the counter is not reset
    assert (
        "5:max_segments exhausted"
        in decide(facts(), cap, policy, state=state, now_ns=NOW + 5 * 10**9).violations
    )


def test_time_bounds_with_clock_tolerance() -> None:
    policy = ReceiverPolicy.default_deny()
    cap = sender_cap(valid_until_ns=NOW)
    assert decide(facts(), cap, policy, now_ns=NOW + DELTA).accepted
    assert (
        "6:sender capability expired"
        in decide(facts(), cap, policy, now_ns=NOW + DELTA + 1).violations
    )
    rc = ReceiverPolicy.from_capability(receiver_cap(valid_from_ns=NOW + 10 * DELTA))
    assert "7:receiver policy not valid now" in decide(facts(), sender_cap(), rc).violations


def test_dp_epsilon_ceiling() -> None:
    policy = ReceiverPolicy.default_deny()
    cap = sender_cap(dp_epsilon_ceiling=1.0)
    state = AcceptState()
    state.epsilon_spent[cap.capability_id.bytes] = 0.75
    release = facts(creates_dp_release=True, epsilon_increment=0.5)
    assert "8:DP epsilon ceiling exceeded" in decide(release, cap, policy, state=state).violations
    retransmission = facts(creates_dp_release=False, epsilon_increment=0.5)
    assert decide(retransmission, cap, policy, state=state).accepted


def test_norm_caps_and_valence_bounds() -> None:
    policy = ReceiverPolicy.from_capability(receiver_cap())
    big = facts(norms={T.KNO: 10.5, T.CTX: 1.0})
    assert "10:KNO norm exceeds cap" in decide(big, sender_cap(), policy).violations
    emo = facts(types=frozenset({T.EMO}), norms={T.EMO: 1.0}, valence=-0.8)
    assert "11:valence outside receiver bounds" in decide(emo, sender_cap(), policy).violations
    unknown = dataclasses.replace(emo, valence=None)
    assert "11:valence outside receiver bounds" in decide(unknown, sender_cap(), policy).violations
    ok = dataclasses.replace(emo, valence=0.2)
    assert decide(ok, sender_cap(), policy).accepted


def test_rate_limit() -> None:
    policy = ReceiverPolicy.default_deny(rate_limit_hz=3)
    state = AcceptState()
    cap = sender_cap()
    for k in range(3):
        t = NOW + k * 100_000_000
        assert decide(facts(), cap, policy, state=state, now_ns=t).accepted
        commit(facts(), cap, state, recipient_pk=RECEIVER.public_bytes, now_ns=t)
    assert (
        "12:rate limit exceeded"
        in decide(facts(), cap, policy, state=state, now_ns=NOW + 300_000_000).violations
    )
    assert decide(facts(), cap, policy, state=state, now_ns=NOW + 1_000_000_001).accepted


def test_unauthenticated_packet_never_accepted() -> None:
    d = decide(facts(authenticated=False), sender_cap(), ReceiverPolicy.default_deny())
    assert not d.accepted
    assert d.violations[0] == "1:not authenticated"


# --- property: acceptance equals an independent oracle ------------------------


def oracle(
    p: PacketFacts,
    cap: SenderCapability,
    policy: ReceiverPolicy,
    spent: float,
    count: int,
    now: int,
) -> bool:
    """Straight transcription of V13 section 9.7 (independent of esp.consent.accept)."""
    allowed = {t for t in TaossType if cap.types_allowed >> t.value & 1} & set(policy.accept_types)
    ok = p.authenticated and set(p.types) <= allowed
    ok = ok and cap.audience_value == RECEIVER.public_bytes
    ok = ok and count < cap.max_segments
    ok = ok and now <= cap.valid_until_ns + DELTA
    ok = ok and policy.valid_from_ns - DELTA <= now <= policy.valid_until_ns + DELTA
    ok = (
        ok
        and spent + (p.epsilon_increment if p.creates_dp_release else 0.0) <= cap.dp_epsilon_ceiling
    )
    ok = ok and (bool(cap.rights & 1) or bool(p.consent_flags & 2))
    ok = ok and (bool(cap.rights & 2) or bool(p.consent_flags & 4))
    for t in p.types:
        if t in policy.norm_caps:
            ok = ok and p.norms.get(t, float("inf")) <= policy.norm_caps[t]
    if T.EMO in p.types and policy.valence_bounds is not None:
        lo, hi = policy.valence_bounds
        if not (lo <= -1.0 and hi >= 1.0):
            ok = ok and p.valence is not None and lo <= p.valence <= hi
    return ok


type_sets = st.frozensets(st.sampled_from(list(TaossType)), max_size=6)


@settings(max_examples=3000)
@given(
    types=type_sets,
    allowed=st.integers(0, 0x3F),
    accept=st.integers(1, 0x3F),
    flags=st.integers(0, 7),
    rights=st.integers(0, 3),
    norm=st.floats(0.0, 20.0),
    valence=st.none() | st.floats(-1.0, 1.0),
    spent=st.floats(0.0, 10.0, width=32),
    inc=st.floats(0.0, 5.0, width=32),
    release=st.booleans(),
    count=st.integers(0, 5),
    max_segments=st.integers(0, 5),
    now_offset=st.integers(-5, 5),
    authenticated=st.booleans(),
    mine=st.booleans(),
)
def test_acceptance_matches_oracle(
    types: frozenset[TaossType],
    allowed: int,
    accept: int,
    flags: int,
    rights: int,
    norm: float,
    valence: float | None,
    spent: float,
    inc: float,
    release: bool,
    count: int,
    max_segments: int,
    now_offset: int,
    authenticated: bool,
    mine: bool,
) -> None:
    accept_types = [t for t in TaossType if accept >> t.value & 1]
    rc = receiver_cap(
        accept_types=accept,
        max_norm=tuple(10.0 for _ in accept_types),
        valence_bounds=(-0.5, 0.5) if T.EMO in accept_types else None,
        valid_until_ns=NOW,
    )
    policy = ReceiverPolicy.from_capability(rc)
    cap = sender_cap(
        types_allowed=allowed,
        rights=Rights(rights),
        max_segments=max_segments,
        valid_until_ns=NOW,
        dp_epsilon_ceiling=8.0,
        audience_value=RECEIVER.public_bytes if mine else b"\x55" * 32,
    )
    p = facts(
        authenticated=authenticated,
        types=types,
        consent_flags=flags,
        norms=dict.fromkeys(types, norm),
        valence=valence,
        creates_dp_release=release,
        epsilon_increment=inc,
    )
    state = AcceptState()
    state.segments[(cap.capability_id.bytes, RECEIVER.public_bytes)] = count
    state.epsilon_spent[cap.capability_id.bytes] = spent
    now = NOW + now_offset * DELTA
    got = decide(p, cap, policy, state=state, now_ns=now).accepted
    assert got == oracle(p, cap, policy, spent, count, now)
