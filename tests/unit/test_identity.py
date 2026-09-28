# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-018 / WP-052 acceptance tests: pseudonymous session identity."""

import uuid

import pytest

from esp.codec.errors import WireError
from esp.codec.header import Header
from esp.codec.tlv import Tlv
from esp.crypto.envelope import seal_packet
from esp.crypto.identity import (
    IdentityProof,
    IdentityProofGuard,
    new_session_identity,
    session_binding,
    static_key_binding,
    verify_session_binding,
    verify_static_key_binding,
)
from esp.crypto.keys import DirectionKeys, deterministic_nonce
from esp.crypto.noise_ik import NoiseIK, Role, StaticKeyPair
from esp.crypto.primitives import CryptoError, SigningKey

MASTER = SigningKey.from_seed(b"\x11" * 32)
RESPONDER_STATIC = StaticKeyPair.generate()


def established() -> tuple[NoiseIK, NoiseIK]:
    i = NoiseIK(
        Role.INITIATOR, StaticKeyPair.generate(), remote_static=RESPONDER_STATIC.public_bytes
    )
    r = NoiseIK(Role.RESPONDER, RESPONDER_STATIC)
    r.read_handshake(i.write_handshake(b""))
    i.read_handshake(r.write_handshake(b""))
    return i, r


def test_two_sessions_use_different_sender_ids() -> None:
    ids = {new_session_identity().public_bytes for _ in range(50)}
    assert len(ids) == 50
    assert MASTER.public_bytes not in ids


def test_master_key_absent_from_clear_header_and_packet() -> None:
    i, _ = established()
    session = new_session_identity()
    proof = IdentityProof(MASTER.public_bytes, i.noise_h, 1_727_000_000).encode(
        MASTER, session.public_bytes
    )
    keys = DirectionKeys.from_split_key(i.split_keys()[0])
    timeline = uuid.uuid4()
    header = Header(
        profile=1,
        sf_level=0,
        types_bitmap=1,
        consent_flags=0,
        privacy_flags=0,
        capabilities=0,
        timestamp_ns=0,
        timeline_id=timeline,
        segment_seq=0,
        dt_ms=0,
        phase=0.0,
        sender_id=session.public_bytes,
        payload_len=0,
        nonce=deterministic_nonce(keys, timeline, 0),
    )
    packet = seal_packet(header, proof.encode(), keys, session)
    assert MASTER.public_bytes not in packet  # the proof travels encrypted
    assert packet[52:84] == session.public_bytes


def test_identity_proof_verifies_in_its_own_transcript() -> None:
    i, r = established()
    session = new_session_identity()
    tlv = IdentityProof(MASTER.public_bytes, i.noise_h, 42).encode(MASTER, session.public_bytes)
    proof = IdentityProof.verify(tlv, pk_session=session.public_bytes, noise_h=r.noise_h)
    assert (proof.pk_master, proof.epoch) == (MASTER.public_bytes, 42)


def test_replayed_identity_proof_fails_in_another_transcript() -> None:
    first, _ = established()
    _, second = established()
    session = new_session_identity()
    tlv = IdentityProof(MASTER.public_bytes, first.noise_h, 42).encode(MASTER, session.public_bytes)
    with pytest.raises(CryptoError, match="another transcript"):
        IdentityProof.verify(tlv, pk_session=session.public_bytes, noise_h=second.noise_h)
    # re-binding to the other transcript without the master key is impossible
    forged = Tlv(0x20, tlv.value[:32] + second.noise_h + tlv.value[64:])
    with pytest.raises(CryptoError, match="signature"):
        IdentityProof.verify(forged, pk_session=session.public_bytes, noise_h=second.noise_h)


def test_identity_proof_bound_to_session_key() -> None:
    i, _ = established()
    tlv = IdentityProof(MASTER.public_bytes, i.noise_h, 1).encode(MASTER, b"\x01" * 32)
    with pytest.raises(CryptoError, match="signature"):
        IdentityProof.verify(tlv, pk_session=b"\x02" * 32, noise_h=i.noise_h)
    with pytest.raises(WireError, match="malformed"):
        IdentityProof.verify(Tlv(0x20, tlv.value[:-1]), pk_session=b"\x01" * 32, noise_h=i.noise_h)
    with pytest.raises(CryptoError, match="its own master key"):
        IdentityProof(b"\x00" * 32, i.noise_h, 1).encode(MASTER, b"\x01" * 32)


def test_identity_proof_at_most_once_per_session() -> None:
    guard = IdentityProofGuard()
    guard.admit()
    with pytest.raises(CryptoError, match="already"):
        guard.admit()


def test_session_binding() -> None:
    i, r = established()
    session = new_session_identity()
    tlv = session_binding(session, i.noise_h)
    assert verify_session_binding(tlv, noise_h=r.noise_h) == session.public_bytes
    _, other = established()
    with pytest.raises(CryptoError, match="another transcript"):
        verify_session_binding(tlv, noise_h=other.noise_h)
    swapped = Tlv(0x85, tlv.value[:1] + new_session_identity().public_bytes + tlv.value[33:])
    with pytest.raises(CryptoError, match="signature"):
        verify_session_binding(swapped, noise_h=i.noise_h)


def test_static_key_binding() -> None:
    identity = SigningKey.from_seed(b"\x22" * 32)
    tlv = static_key_binding(identity, RESPONDER_STATIC.public_bytes, valid_until_ns=10_000)
    verify_static_key_binding(
        tlv,
        x25519_pk=RESPONDER_STATIC.public_bytes,
        identity_pk=identity.public_bytes,
        now_ns=9_999,
    )
    with pytest.raises(CryptoError, match="expired"):
        verify_static_key_binding(
            tlv,
            x25519_pk=RESPONDER_STATIC.public_bytes,
            identity_pk=identity.public_bytes,
            now_ns=10_001,
        )
    with pytest.raises(CryptoError, match="other keys"):
        verify_static_key_binding(
            tlv, x25519_pk=b"\x00" * 32, identity_pk=identity.public_bytes, now_ns=0
        )
