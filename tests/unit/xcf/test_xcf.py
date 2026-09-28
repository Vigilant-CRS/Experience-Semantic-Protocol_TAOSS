# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-068 XCF capsules, gate, recall; WP-069 trust vector."""

import time
import uuid

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from esp.consent.capability import AudienceMode, Rights, SenderCapability
from esp.consent.revocation import RevocationRegistry
from esp.crypto.primitives import CryptoError, SigningKey
from esp.xcf.capsule import (
    HEADER,
    HEADER_LEN,
    REVOCATION_GUARANTEE,
    Capsule,
    CapsuleSpec,
    EnvelopeAlg,
    Header,
    PrivateBody,
    SignerMode,
    XcfError,
    hpke_access,
    hpke_unwrap,
    seal,
    sender_binding,
)
from esp.xcf.gate import (
    Gate,
    GateRefused,
    RecallFrame,
    RecallPolicy,
    Tombstone,
    gated_access,
    recall,
    unwrap_release,
)
from esp.xcf.trust import (
    TrustScore,
    TrustVector,
    score,
    tau_anchor,
    tau_drift,
    tau_lineage,
    tau_privacy,
    tau_sig,
)

NOW = time.time_ns()
MASTER = SigningKey.generate()
ENC, ANC = (
    uuid.UUID("11111111-1111-4111-8111-111111111111"),
    uuid.UUID("22222222-2222-4222-8222-222222222222"),
)


def spec(
    parent: bytes = bytes(32), mode: SignerMode = SignerMode.PER_CAPSULE, types: int = 0x0B
) -> CapsuleSpec:
    return CapsuleSpec(
        types_bitmap=types,
        encoder_id=ENC,
        anchor_set_id=ANC,
        created_ns=NOW,
        packets_count=3,
        dp_eps_spent=0.5,
        dp_delta=1e-6,
        parent_cid=parent,
        signer_mode=mode,
    )


def body(policy: uuid.UUID | None = None, timeline: uuid.UUID | None = None) -> PrivateBody:
    return PrivateBody(
        policy or uuid.uuid4(), timeline or uuid.uuid4(), payload=b"typed latents ..."
    )


def cap(types: int = 0x3F, until: int = NOW + 10**12) -> SenderCapability:
    rid = SigningKey.generate().public_bytes
    return SenderCapability(
        uuid.uuid4(),
        types,
        Rights(0),
        10,
        0.0,
        until,
        AudienceMode.RECIPIENT_PUBKEY,
        rid,
        MASTER.public_bytes,
        b"\x00" * 16,
    )


def test_header_is_exactly_148_bytes_and_roundtrips() -> None:
    assert HEADER.size == HEADER_LEN == 148
    recipient = X25519PrivateKey.generate()
    c, _ = seal(
        spec(),
        body(),
        envelope_alg=EnvelopeAlg.DIRECT_HPKE,
        access_material=hpke_access(recipient.public_key()),
    )
    raw = c.raw[:HEADER_LEN]
    assert Header.decode(raw).encode() == raw
    bad = bytearray(raw)
    bad[5] = 1  # reserved byte
    with pytest.raises(XcfError, match="reserved"):
        Header.decode(bytes(bad))


def test_direct_hpke_roundtrip_signature_and_cid() -> None:
    recipient = X25519PrivateKey.generate()
    b = body()
    c, cek = seal(
        spec(),
        b,
        envelope_alg=EnvelopeAlg.DIRECT_HPKE,
        access_material=hpke_access(recipient.public_key()),
    )
    assert hpke_unwrap(c, recipient) == cek
    assert c.open_with_cek(cek) == b
    assert len(c.cid) == 32
    tampered = bytearray(c.raw)
    tampered[HEADER_LEN + 40] ^= 1
    with pytest.raises(CryptoError):
        Capsule(bytes(tampered)).verify_signature()
    with pytest.raises(CryptoError):
        hpke_unwrap(c, X25519PrivateKey.generate())
    assert (
        "policy revocation only" in REVOCATION_GUARANTEE[EnvelopeAlg.DIRECT_HPKE]
    )  # never "erasure"
    assert "erasure" not in REVOCATION_GUARANTEE[EnvelopeAlg.DIRECT_HPKE]


def test_per_capsule_refs_are_unlinkable_lineage_refs_are_linkable() -> None:
    policy, timeline = uuid.uuid4(), uuid.uuid4()
    r = X25519PrivateKey.generate().public_key()
    a, _ = seal(
        spec(),
        body(policy, timeline),
        envelope_alg=EnvelopeAlg.DIRECT_HPKE,
        access_material=hpke_access(r),
    )
    b, _ = seal(
        spec(),
        body(policy, timeline),
        envelope_alg=EnvelopeAlg.DIRECT_HPKE,
        access_material=hpke_access(r),
    )
    assert a.header.policy_ref != b.header.policy_ref  # same policy, uncorrelated public tags
    assert a.header.timeline_ref != b.header.timeline_ref
    assert a.signer_pk != b.signer_pk  # fresh pseudonymous key per capsule
    lin, _ = seal(
        spec(mode=SignerMode.LINEAGE_PSEUDONYM),
        body(policy, timeline),
        envelope_alg=EnvelopeAlg.DIRECT_HPKE,
        access_material=hpke_access(r),
    )
    assert lin.header.policy_ref == policy.bytes  # explicitly linkable metadata


def test_sender_binding_proves_provenance_privately() -> None:
    import struct  # noqa: PLC0415

    from esp.crypto.primitives import ed25519_verify  # noqa: PLC0415

    pid, tid = uuid.uuid4(), uuid.uuid4()
    capsule_key = SigningKey.generate()
    binding = sender_binding(MASTER, capsule_key.public_bytes, pid, tid, NOW)
    msg = (
        b"esp/xcf/v1/bind"
        + capsule_key.public_bytes
        + pid.bytes
        + tid.bytes
        + struct.pack(">Q", NOW)
    )
    ed25519_verify(binding[:32], msg, binding[32:])


def test_gated_cek_release_tombstone_and_destroyed_gate() -> None:
    gate = Gate()
    gate_id, secret = gate.new_gate()
    b = PrivateBody(uuid.uuid4(), uuid.uuid4(), b"x", sender_binding=MASTER.public_bytes)
    c, cek = seal(
        spec(), b, envelope_alg=EnvelopeAlg.GATED_CEK, access_material=gated_access(gate_id, secret)
    )
    assert secret not in c.raw  # the gate secret is never in the capsule
    recipient = X25519PrivateKey.generate()
    released = gate.release(
        c, cap(), recipient.public_key(), now_ns=NOW, revocations=RevocationRegistry()
    )
    assert unwrap_release(c, released, recipient) == cek
    with pytest.raises(GateRefused, match="does not cover"):
        gate.release(
            c, cap(types=0x01), recipient.public_key(), now_ns=NOW, revocations=RevocationRegistry()
        )
    # a new recipient after the gate secret is destroyed: no first-time access
    gate.destroy(gate_id)
    with pytest.raises(GateRefused, match="destroyed"):
        gate.release(
            c,
            cap(),
            X25519PrivateKey.generate().public_key(),
            now_ns=NOW,
            revocations=RevocationRegistry(),
        )
    # tombstones stop protocol-compliant access
    gate2 = Gate()
    gid, sec = gate2.new_gate()
    c2, _ = seal(
        spec(), b, envelope_alg=EnvelopeAlg.GATED_CEK, access_material=gated_access(gid, sec)
    )
    gate2.tombstone(c2, Tombstone.create(c2.cid, MASTER), MASTER.public_bytes)
    with pytest.raises(GateRefused, match="tombstoned"):
        gate2.release(
            c2, cap(), recipient.public_key(), now_ns=NOW, revocations=RevocationRegistry()
        )
    with pytest.raises(GateRefused, match="lineage master"):
        gate2.tombstone(c2, Tombstone.create(c2.cid, SigningKey.generate()), MASTER.public_bytes)


def test_guardian_quorum_gate() -> None:
    gate = Gate()
    gate_id, secret = gate.new_gate(guardians=5, threshold=3)
    c, cek = seal(
        spec(),
        body(),
        envelope_alg=EnvelopeAlg.GATED_CEK,
        access_material=gated_access(gate_id, secret),
    )
    shares = gate.quorum[gate_id][1]
    r = X25519PrivateKey.generate()
    with pytest.raises(GateRefused, match="quorum"):
        gate.release(
            c,
            cap(),
            r.public_key(),
            now_ns=NOW,
            revocations=RevocationRegistry(),
            guardian_shares=shares[:2],
        )
    released = gate.release(
        c,
        cap(),
        r.public_key(),
        now_ns=NOW,
        revocations=RevocationRegistry(),
        guardian_shares=shares[1:4],
    )
    assert unwrap_release(c, released, r) == cek


def lineage(n: int) -> list[Capsule]:
    r = X25519PrivateKey.generate().public_key()
    out: list[Capsule] = []
    parent = bytes(32)
    for _ in range(n):
        c, _ = seal(
            spec(parent=parent),
            body(),
            envelope_alg=EnvelopeAlg.DIRECT_HPKE,
            access_material=hpke_access(r),
        )
        out.append(c)
        parent = c.cid
    return out


def test_recall_respects_no_replay_across_the_lineage() -> None:
    chain = lineage(3)
    store = {c.cid: c for c in chain}
    leaf = chain[-1].cid
    frame = recall(
        store,
        leaf,
        cap(),
        now_ns=NOW,
        policy=RecallPolicy({}),
        epsilon_budget=1.0,
        offset_ns=5,
        span_ns=10,
    )
    assert RecallFrame.decode(frame.encode()) == frame
    assert len(frame.encode().value) == 32 + 8 + 8 + 4
    with pytest.raises(GateRefused, match="NO_REPLAY"):
        recall(
            store,
            leaf,
            cap(),
            now_ns=NOW,
            policy=RecallPolicy({chain[0].cid: True}),
            epsilon_budget=1.0,
        )
    with pytest.raises(GateRefused, match="DP budget"):
        recall(store, leaf, cap(), now_ns=NOW, policy=RecallPolicy({}), epsilon_budget=0.1)
    with pytest.raises(GateRefused, match="expired"):
        recall(
            store, leaf, cap(until=NOW - 1), now_ns=NOW, policy=RecallPolicy({}), epsilon_budget=1.0
        )


def test_trust_vector_rules() -> None:
    chain = lineage(3)
    store = {c.cid: c for c in chain}
    assert tau_lineage(chain[0], store, frozenset()) == 1.0  # genesis
    assert tau_lineage(chain[2], store, frozenset()) == 1.0
    assert tau_lineage(chain[2], store, frozenset({chain[0].cid})) == 0.0  # tombstone in lineage
    partial = {chain[2].cid: chain[2], chain[1].cid: chain[1]}  # grandparent missing
    assert tau_lineage(chain[2], partial, frozenset()) == 0.5
    broken = Capsule(chain[2].raw[:-1] + bytes([chain[2].raw[-1] ^ 1]))
    assert tau_sig(broken) == 0.0
    # a broken signature can never be recalled, whatever the scalar says
    high = score(
        TrustVector(sig=0.0, anchor=1.0, drift=1.0, privacy=1.0, lineage=1.0),
        (0.0, 0.25, 0.25, 0.25, 0.25),
    )
    assert high.scalar == pytest.approx(1.0)
    assert not high.admissible(0.5)
    ok = score(
        TrustVector(
            1.0,
            tau_anchor(validated=True, age_days=0),
            tau_drift(0.1, 1.0),
            tau_privacy(i_max=0.01, iota_max=0.05, eps_spent=1, eps_budget=4),
            1.0,
        )
    )
    assert ok.admissible(0.5)
    assert tau_privacy(i_max=0.2, iota_max=0.05, eps_spent=0, eps_budget=4) == 0.0
    assert tau_anchor(validated=False, age_days=1) == 0.0
    with pytest.raises(ValueError, match="binary"):
        TrustVector(0.5, 1, 1, 1, 1)


def test_scalar_is_never_exposed_without_the_vector() -> None:
    s = score(TrustVector(1.0, 0.5, 0.5, 0.5, 1.0))
    assert isinstance(s, TrustScore)
    assert s.vector.as_tuple() == (1.0, 0.5, 0.5, 0.5, 1.0)
    text = str(s)
    for name in ("sig", "anchor", "drift", "privacy", "lineage"):
        assert f"{name}=" in text  # any rendering of T carries the components


def test_signed_capsule_with_mismatching_reference_tags_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A sender signing public tags not derived from the private ids is caught on open."""
    import esp.xcf.capsule as cap_mod  # noqa: PLC0415

    r = X25519PrivateKey.generate()
    monkeypatch.setattr(cap_mod, "ref_tag", lambda k, d, i: bytes(16))
    c, cek = seal(
        spec(),
        body(),
        envelope_alg=EnvelopeAlg.DIRECT_HPKE,
        access_material=hpke_access(r.public_key()),
    )
    monkeypatch.undo()
    c.verify_signature()  # the capsule itself is validly signed
    with pytest.raises(XcfError, match="reference tags"):
        c.open_with_cek(cek)
