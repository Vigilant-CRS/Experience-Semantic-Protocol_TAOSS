# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-053 (key lifecycle, transparency log) and WP-020 (revocation) acceptance tests."""

import uuid

import pytest
from hypothesis import given
from hypothesis import strategies as st

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv
from esp.consent.accept import AcceptState, PacketFacts, evaluate
from esp.consent.capability import AudienceMode, ReceiverPolicy, Rights, SenderCapability
from esp.consent.revocation import (
    ConsentRevocationReason,
    DeletionAttestation,
    DeletionScope,
    Effects,
    RevocationIntent,
    RevocationRegistry,
    request_digest,
)
from esp.core.taoss_types import TaossType
from esp.crypto.primitives import CryptoError, SigningKey
from esp.keys.evidence import (
    encode_inclusion_evidence,
    encode_witness_evidence,
    make_verifier,
    witness_sign,
)
from esp.keys.lineage import (
    AuthMode,
    BindingMode,
    KeyLineage,
    KeyRevoked,
    KeyState,
    RevocationReason,
    RotationBinding,
    make_rotation,
    successor_pre_registration,
)
from esp.keys.transparency import (
    TransparencyLog,
    consistency_proof,
    cosign,
    inclusion_path,
    leaf_hash,
    merkle_root,
    verify_consistency,
    verify_inclusion,
)

OLD = SigningKey.from_seed(b"\x51" * 32)
NEW = SigningKey.from_seed(b"\x52" * 32)
ATTACKER = SigningKey.from_seed(b"\x53" * 32)
RECEIVER = SigningKey.from_seed(b"\x54" * 32)
WITNESSES = [SigningKey.from_seed(bytes([0x60 + i]) * 32) for i in range(3)]
T_ROTATE = 5_000


# --- transparency log (RFC 9162) --------------------------------------------------

CT_INPUTS = [
    b"",
    b"\x00",
    b"\x10",
    b"\x20\x21",
    b"\x30\x31",
    b"\x40\x41\x42\x43",
    bytes(range(0x50, 0x58)),
    bytes(range(0x60, 0x70)),
]
CT_ROOTS = [
    "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
    "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
    "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
    "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
    "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
    "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
    "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
    "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
]


@pytest.mark.parametrize("n", range(1, 9))
def test_rfc6962_reference_roots(n: int) -> None:
    leaves = [leaf_hash(x) for x in CT_INPUTS]
    assert merkle_root(leaves[:n]).hex() == CT_ROOTS[n - 1]


@given(st.integers(1, 70), st.data())
def test_inclusion_and_consistency_proofs(n: int, data: st.DataObject) -> None:
    leaves = [leaf_hash(i.to_bytes(4, "big")) for i in range(n)]
    root = merkle_root(leaves)
    m = data.draw(st.integers(0, n - 1))
    path = inclusion_path(m, leaves)
    assert verify_inclusion(leaves[m], m, n, path, root)
    if path:
        bad = [bytes(32), *path[1:]]
        assert not verify_inclusion(leaves[m], m, n, bad, root)
    assert not verify_inclusion(leaf_hash(b"other"), m, n, path, root)
    old = data.draw(st.integers(1, n))
    proof = consistency_proof(old, leaves)
    assert verify_consistency(old, n, merkle_root(leaves[:old]), root, proof)
    if old < n:
        assert not verify_consistency(old, n, bytes(32), root, proof)


def test_tree_head_requires_witness_quorum() -> None:
    log = TransparencyLog(SigningKey.from_seed(b"\x70" * 32))
    log.append(b"a")
    head = log.tree_head(timestamp_ns=1)
    with pytest.raises(CryptoError, match="0 valid witness"):
        head.verify(witnesses=[w.public_bytes for w in WITNESSES], quorum=2)
    head = cosign(cosign(head, WITNESSES[0]), WITNESSES[1])
    head.verify(witnesses=[w.public_bytes for w in WITNESSES], quorum=2)
    selfie = cosign(log.tree_head(timestamp_ns=1), SigningKey.from_seed(b"\x70" * 32))
    with pytest.raises(CryptoError):
        selfie.verify(witnesses=[selfie.log_pk], quorum=1)  # the log cannot witness itself


# --- rotation & key revocation ------------------------------------------------------


def witnessed_lineage() -> tuple[KeyLineage, RotationBinding]:
    sigs = [
        witness_sign(
            w,
            mode=BindingMode.WITNESS_QUORUM,
            old_pk=OLD.public_bytes,
            new_pk=NEW.public_bytes,
            effective_ns=T_ROTATE,
        )
        for w in WITNESSES[:2]
    ]
    binding = make_rotation(
        mode=BindingMode.WITNESS_QUORUM,
        old=None,
        old_pk=OLD.public_bytes,
        new=NEW,
        new_pk=NEW.public_bytes,
        effective_ns=T_ROTATE,
        evidence=encode_witness_evidence(sigs),
    )
    lineage = KeyLineage(
        evidence_verifier=make_verifier(witnesses=[w.public_bytes for w in WITNESSES], quorum=2)
    )
    lineage.enroll(OLD.public_bytes)
    lineage.apply_rotation(binding)
    return lineage, binding


def test_witness_quorum_rotation() -> None:
    lineage, binding = witnessed_lineage()
    assert lineage.state(OLD.public_bytes) is KeyState.ROTATED
    assert lineage.state(NEW.public_bytes) is KeyState.ACTIVE
    assert not lineage.can_grant(OLD.public_bytes)  # old key may not grant after rotation
    assert lineage.can_grant(NEW.public_bytes)
    assert RotationBinding.decode(binding.encode()) == binding


def test_witness_evidence_for_another_tuple_is_rejected() -> None:
    sigs = [
        witness_sign(
            w,
            mode=BindingMode.WITNESS_QUORUM,
            old_pk=OLD.public_bytes,
            new_pk=NEW.public_bytes,
            effective_ns=T_ROTATE + 1,
        )
        for w in WITNESSES[:2]
    ]
    binding = make_rotation(
        mode=BindingMode.WITNESS_QUORUM,
        old=None,
        old_pk=OLD.public_bytes,
        new=NEW,
        new_pk=NEW.public_bytes,
        effective_ns=T_ROTATE,
        evidence=encode_witness_evidence(sigs),
    )
    lineage = KeyLineage(
        evidence_verifier=make_verifier(witnesses=[w.public_bytes for w in WITNESSES], quorum=2)
    )
    lineage.enroll(OLD.public_bytes)
    with pytest.raises(CryptoError, match="evidence does not authenticate"):
        lineage.apply_rotation(binding)


def test_pre_registered_rotation_via_transparency_log() -> None:
    log = TransparencyLog(SigningKey.from_seed(b"\x70" * 32))
    log.append(b"unrelated")
    index = log.append(successor_pre_registration(OLD.public_bytes, NEW.public_bytes))
    log.append(b"later")
    head = cosign(log.tree_head(timestamp_ns=T_ROTATE - 1), WITNESSES[0])
    head.verify(witnesses=[WITNESSES[0].public_bytes], quorum=1)
    evidence = encode_inclusion_evidence(index, log.size, log.inclusion(index))
    binding = make_rotation(
        mode=BindingMode.PRE_REGISTERED,
        old=None,
        old_pk=OLD.public_bytes,
        new=NEW,
        new_pk=NEW.public_bytes,
        effective_ns=T_ROTATE,
        evidence=evidence,
    )
    lineage = KeyLineage(evidence_verifier=make_verifier(trusted_head=head))
    lineage.enroll(OLD.public_bytes)
    lineage.apply_rotation(binding)
    # an attacker holding the old key cannot rotate to an unregistered key
    rogue = make_rotation(
        mode=BindingMode.PRE_REGISTERED,
        old=OLD,
        old_pk=OLD.public_bytes,
        new=ATTACKER,
        new_pk=ATTACKER.public_bytes,
        effective_ns=T_ROTATE,
        evidence=evidence,
    )
    victim = KeyLineage(evidence_verifier=make_verifier(trusted_head=head))
    victim.enroll(OLD.public_bytes)
    with pytest.raises(CryptoError):
        victim.apply_rotation(rogue)


def test_sig_new_proves_possession_and_sig_old_rules() -> None:
    good = make_rotation(
        mode=BindingMode.PROFILE_DEFINED,
        old=OLD,
        old_pk=OLD.public_bytes,
        new=NEW,
        new_pk=NEW.public_bytes,
        effective_ns=T_ROTATE,
    )
    lineage = KeyLineage()
    lineage.enroll(OLD.public_bytes)
    no_possession = RotationBinding(
        good.mode,
        good.old_pk,
        good.new_pk,
        good.effective_ns,
        good.evidence,
        good.sig_old,
        ATTACKER.sign(good.core()),
    )
    with pytest.raises(CryptoError):
        lineage.apply_rotation(no_possession)
    missing_old = RotationBinding(
        good.mode,
        good.old_pk,
        good.new_pk,
        good.effective_ns,
        good.evidence,
        bytes(64),
        good.sig_new,
    )
    with pytest.raises(CryptoError):
        lineage.apply_rotation(missing_old)  # PROFILE_DEFINED requires old co-signature here
    lineage.apply_rotation(good)


def test_arbitrary_fresh_key_cannot_revoke_another_identity() -> None:
    lineage, _ = witnessed_lineage()
    forged = KeyRevoked(
        AuthMode.SUCCESSOR_BOUND,
        NEW.public_bytes,
        ATTACKER.public_bytes,
        0,
        RevocationReason.COMPROMISED,
        b"\x09" * 32,
    ).sign(ATTACKER)
    with pytest.raises(CryptoError, match="without a verified rotation binding"):
        lineage.apply_key_revoked(forged)
    assert lineage.state(NEW.public_bytes) is KeyState.ACTIVE
    assert len(lineage.unauthenticated_claims) == 1


def test_self_and_successor_bound_revocation() -> None:
    lineage, binding = witnessed_lineage()
    notice = KeyRevoked(
        AuthMode.SUCCESSOR_BOUND,
        OLD.public_bytes,
        NEW.public_bytes,
        T_ROTATE,
        RevocationReason.COMPROMISED,
        binding.digest(),
    ).sign(NEW)
    lineage.apply_key_revoked(notice)
    assert lineage.state(OLD.public_bytes) is KeyState.REVOKED
    assert lineage.is_compromised(OLD.public_bytes)
    self_notice = KeyRevoked(
        AuthMode.SELF, NEW.public_bytes, bytes(32), 9, RevocationReason.RETIRED, bytes(32)
    ).sign(NEW)
    lineage.apply_key_revoked(self_notice)
    assert lineage.state(NEW.public_bytes) is KeyState.REVOKED
    bad_self = KeyRevoked(
        AuthMode.SELF, OLD.public_bytes, NEW.public_bytes, 0, RevocationReason.LOST, bytes(32)
    ).sign(OLD)
    with pytest.raises(CryptoError, match="all-zero"):
        lineage.apply_key_revoked(bad_self)


def test_rotation_binding_decoder_rejects_overflow_and_digest_mismatch() -> None:
    _, binding = witnessed_lineage()
    raw = binding.encode().value
    with pytest.raises(WireError):
        RotationBinding.decode(Tlv(0x42, raw[:-1]))
    tampered = raw[:74] + bytes(32) + raw[106:]
    with pytest.raises(WireError, match="digest mismatch"):
        RotationBinding.decode(Tlv(0x42, tampered))


# --- consent revocation ----------------------------------------------------------------

CAP_ID = uuid.UUID("11111111-2222-4333-8444-555555555555")
ZERO = uuid.UUID(int=0)


def capability(issuer: SigningKey) -> SenderCapability:
    return SenderCapability(
        CAP_ID,
        0x09,
        Rights(0),
        100,
        8.0,
        10**18,
        AudienceMode.RECIPIENT_PUBKEY,
        RECEIVER.public_bytes,
        issuer.public_bytes,
        b"\x00" * 16,
    )


def withdraw(signer: SigningKey, issuer: SigningKey) -> Tlv:
    return RevocationIntent(
        CAP_ID,
        ZERO,
        0,
        ConsentRevocationReason.CONSENT_WITHDRAWN,
        Effects.REVOKE_FUTURE_USE | Effects.REQUEST_DELETE_STORED,
        issuer.public_bytes,
        signer.public_bytes,
    ).sign(signer)


def packet() -> PacketFacts:
    return PacketFacts(
        True,
        frozenset({TaossType.KNO}),
        0x6,
        {TaossType.KNO: 1.0},
        None,
        timeline_id=uuid.uuid4(),
        segment_seq=3,
    )


def test_revoked_capability_cannot_send() -> None:
    cap = capability(OLD)
    registry = RevocationRegistry()
    policy = ReceiverPolicy.default_deny()
    kw = {"recipient_pk": RECEIVER.public_bytes, "now_ns": 1, "clock_tolerance_ns": 0}
    assert evaluate(packet(), cap, policy, AcceptState(), revocations=registry, **kw).accepted  # type: ignore[arg-type]
    registry.apply(withdraw(OLD, OLD), capability=cap, lineage=None)
    d = evaluate(packet(), cap, policy, AcceptState(), revocations=registry, **kw)  # type: ignore[arg-type]
    assert d.violations == ("13:capability or timeline revoked",)
    assert registry.deletion_requests  # deletion requested, not guaranteed


def test_successor_may_narrow_prior_grant() -> None:
    lineage, _ = witnessed_lineage()
    cap = capability(OLD)  # granted before rotation
    registry = RevocationRegistry()
    registry.apply(withdraw(NEW, OLD), capability=cap, lineage=lineage)
    assert CAP_ID.bytes in registry.revoked_capabilities


def test_unrelated_or_compromised_signer_fails_closed() -> None:
    lineage, binding = witnessed_lineage()
    cap = capability(OLD)
    with pytest.raises(CryptoError, match="neither the issuer"):
        RevocationRegistry().apply(withdraw(ATTACKER, OLD), capability=cap, lineage=lineage)
    compromise = KeyRevoked(
        AuthMode.SELF, NEW.public_bytes, bytes(32), 0, RevocationReason.COMPROMISED, bytes(32)
    ).sign(NEW)
    lineage.apply_key_revoked(compromise)
    with pytest.raises(CryptoError, match="neither the issuer"):
        RevocationRegistry().apply(withdraw(NEW, OLD), capability=cap, lineage=lineage)
    assert not lineage.can_grant(NEW.public_bytes)
    del binding


def test_consent_withdrawal_must_use_capability_scope() -> None:
    with pytest.raises(WireError, match="capability scope"):
        RevocationIntent(
            CAP_ID,
            uuid.uuid4(),
            0,
            ConsentRevocationReason.CONSENT_WITHDRAWN,
            Effects.REVOKE_FUTURE_USE,
            OLD.public_bytes,
            OLD.public_bytes,
        )
    with pytest.raises(WireError, match="capability scope"):
        RevocationIntent(
            ZERO,
            uuid.uuid4(),
            0,
            ConsentRevocationReason.CONSENT_WITHDRAWN,
            Effects.REVOKE_FUTURE_USE,
            OLD.public_bytes,
            OLD.public_bytes,
        )
    with pytest.raises(WireError, match="bits 4-7"):
        RevocationIntent(
            CAP_ID,
            ZERO,
            0,
            ConsentRevocationReason.ERROR,
            Effects(0x10),
            OLD.public_bytes,
            OLD.public_bytes,
        )


def test_timeline_scope_and_technical_revocation() -> None:
    timeline = uuid.uuid4()
    tech = RevocationIntent(
        ZERO,
        timeline,
        10,
        ConsentRevocationReason.ERROR,
        Effects.TERMINATE_SESSIONS,
        OLD.public_bytes,
        OLD.public_bytes,
    ).sign(OLD)
    registry = RevocationRegistry()
    with pytest.raises(CryptoError, match="session master binding"):
        registry.apply(tech, capability=None, lineage=None, session_master_pk=NEW.public_bytes)
    registry.apply(tech, capability=None, lineage=None, session_master_pk=OLD.public_bytes)
    assert not registry.is_revoked(CAP_ID, timeline, 9)
    assert registry.is_revoked(CAP_ID, timeline, 10)


def test_deletion_attestation_is_a_bound_claim() -> None:
    request = withdraw(OLD, OLD)
    att = DeletionAttestation(
        CAP_ID,
        ZERO,
        DeletionScope.STORED_CAPSULES | DeletionScope.DERIVED_ARTIFACTS,
        request_digest(request),
        bytes(32),
        123,
        RECEIVER.public_bytes,
    ).sign(RECEIVER)
    verified = DeletionAttestation.verify(att, request=request)
    assert verified.signer_pk == RECEIVER.public_bytes
    other_request = withdraw(OLD, OLD)
    assert other_request == request  # Ed25519 is deterministic: same request, same bytes
    different = RevocationIntent(
        CAP_ID,
        ZERO,
        0,
        ConsentRevocationReason.CONSENT_WITHDRAWN,
        Effects.REVOKE_FUTURE_USE,
        OLD.public_bytes,
        OLD.public_bytes,
    ).sign(OLD)
    with pytest.raises(CryptoError, match="does not bind"):
        DeletionAttestation.verify(att, request=different)


def test_can_reduce_excludes_compromised_successors_directly() -> None:
    lineage, _ = witnessed_lineage()
    assert lineage.can_reduce(OLD.public_bytes, OLD.public_bytes)
    assert lineage.can_reduce(OLD.public_bytes, NEW.public_bytes)
    assert not lineage.can_reduce(NEW.public_bytes, OLD.public_bytes)  # lineage is directed
    assert not lineage.can_reduce(OLD.public_bytes, ATTACKER.public_bytes)
    lineage.apply_key_revoked(
        KeyRevoked(
            AuthMode.SELF, NEW.public_bytes, bytes(32), 0, RevocationReason.COMPROMISED, bytes(32)
        ).sign(NEW)
    )
    assert not lineage.can_reduce(OLD.public_bytes, NEW.public_bytes)


def test_capability_issuer_pk_must_match_the_capability() -> None:
    cap = capability(OLD)
    mismatched = RevocationIntent(
        CAP_ID,
        ZERO,
        0,
        ConsentRevocationReason.CONSENT_WITHDRAWN,
        Effects.REVOKE_FUTURE_USE,
        ATTACKER.public_bytes,
        OLD.public_bytes,
    ).sign(OLD)
    with pytest.raises(CryptoError, match="does not match the capability"):
        RevocationRegistry().apply(mismatched, capability=cap, lineage=None)
    unknown = RevocationIntent(
        uuid.uuid4(),
        ZERO,
        0,
        ConsentRevocationReason.CONSENT_WITHDRAWN,
        Effects.REVOKE_FUTURE_USE,
        OLD.public_bytes,
        OLD.public_bytes,
    ).sign(OLD)
    with pytest.raises(CryptoError, match="unknown capability"):
        RevocationRegistry().apply(unknown, capability=cap, lineage=None)


def test_grant_first_presented_after_rotation_needs_prior_evidence() -> None:
    lineage, _ = witnessed_lineage()
    assert lineage.admit_grant(
        NEW.public_bytes, previously_accepted=False, logged_before_cutoff=False
    )
    rotated = OLD.public_bytes
    assert not lineage.admit_grant(rotated, previously_accepted=False, logged_before_cutoff=False)
    assert lineage.admit_grant(rotated, previously_accepted=True, logged_before_cutoff=False)
    assert lineage.admit_grant(rotated, previously_accepted=False, logged_before_cutoff=True)
    assert not lineage.admit_grant(
        ATTACKER.public_bytes, previously_accepted=True, logged_before_cutoff=True
    )
    lineage.apply_key_revoked(
        KeyRevoked(
            AuthMode.SELF, NEW.public_bytes, bytes(32), 0, RevocationReason.COMPROMISED, bytes(32)
        ).sign(NEW)
    )
    # compromised: fail closed by default, even for logged or previously seen grants
    for seen, logged in ((True, False), (True, True), (False, True)):
        assert not lineage.admit_grant(
            NEW.public_bytes, previously_accepted=seen, logged_before_cutoff=logged
        )
    lineage.grandfather_logged_on_compromise = True  # a profile MAY enable this
    assert lineage.admit_grant(
        NEW.public_bytes, previously_accepted=False, logged_before_cutoff=True
    )
    assert not lineage.admit_grant(
        NEW.public_bytes, previously_accepted=True, logged_before_cutoff=False
    )
