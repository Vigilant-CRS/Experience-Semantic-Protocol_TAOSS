# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-016 acceptance tests: official vectors, project vectors, tamper detection."""

import dataclasses
import json
import uuid
from pathlib import Path

import pytest

from esp.codec.errors import WireError
from esp.codec.header import Header
from esp.codec.tlv import Tlv
from esp.crypto.envelope import open_packet, seal_packet
from esp.crypto.keys import DirectionKeys, TimelineTagRegistry, deterministic_nonce
from esp.crypto.noise_ik import NoiseIK, Role, StaticKeyPair
from esp.crypto.primitives import (
    CryptoError,
    SigningKey,
    aead_open,
    aead_seal,
    blake2b,
    ed25519_verify,
)
from esp.crypto.signed import sign_tlv, verify_signed_tlv

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "noise"

# --- official / library vectors ---------------------------------------------

# RFC 8439 section 2.8.2 (AEAD_CHACHA20_POLY1305 test vector)
RFC8439_KEY = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
RFC8439_NONCE = bytes.fromhex("070000004041424344454647")
RFC8439_AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
RFC8439_PT = (
    b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
    b"for the future, sunscreen would be it."
)
RFC8439_CT = bytes.fromhex(
    "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
    "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
    "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
    "3ff4def08e4b7a9de576d26586cec64b6116"
)
RFC8439_TAG = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")

# RFC 8032 section 7.1, TEST 1 (empty message) and TEST 2
RFC8032 = [
    (
        "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
        "",
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    ),
    (
        "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
        "72",
        "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
    ),
]

# RFC 7693 Appendix A: BLAKE2b-512("abc")
RFC7693_ABC = bytes.fromhex(
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
    "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
)


def test_rfc8439_aead_vector() -> None:
    ct, tag = aead_seal(RFC8439_KEY, RFC8439_NONCE, RFC8439_AAD, RFC8439_PT)
    assert (ct, tag) == (RFC8439_CT, RFC8439_TAG)
    assert aead_open(RFC8439_KEY, RFC8439_NONCE, RFC8439_AAD, ct, tag) == RFC8439_PT


@pytest.mark.parametrize(("sk", "pk", "msg", "sig"), RFC8032)
def test_rfc8032_ed25519_vectors(sk: str, pk: str, msg: str, sig: str) -> None:
    key = SigningKey.from_seed(bytes.fromhex(sk))
    assert key.public_bytes.hex() == pk
    assert key.sign(bytes.fromhex(msg)).hex() == sig
    ed25519_verify(bytes.fromhex(pk), bytes.fromhex(msg), bytes.fromhex(sig))


def test_rfc7693_blake2b_vector() -> None:
    assert blake2b(b"abc", digest_size=64) == RFC7693_ABC


def test_cacophony_noise_ik_vector() -> None:
    doc = json.loads((FIXTURES / "cacophony_IK_25519_ChaChaPoly_BLAKE2b.json").read_text())
    v = doc["vectors"][0]
    h = bytes.fromhex
    i = NoiseIK(
        Role.INITIATOR,
        StaticKeyPair.from_private_bytes(h(v["init_static"])),
        remote_static=h(v["init_remote_static"]),
        prologue=h(v["init_prologue"]),
        _test_ephemeral=h(v["init_ephemeral"]),
    )
    r = NoiseIK(
        Role.RESPONDER,
        StaticKeyPair.from_private_bytes(h(v["resp_static"])),
        prologue=h(v["resp_prologue"]),
        _test_ephemeral=h(v["resp_ephemeral"]),
    )
    m = v["messages"]
    c0 = i.write_handshake(h(m[0]["payload"]))
    assert c0.hex() == m[0]["ciphertext"]
    assert r.read_handshake(c0) == h(m[0]["payload"])
    c1 = r.write_handshake(h(m[1]["payload"]))
    assert c1.hex() == m[1]["ciphertext"]
    assert i.read_handshake(c1) == h(m[1]["payload"])
    assert i.handshake_hash.hex() == v["handshake_hash"] == r.handshake_hash.hex()
    for n, msg in enumerate(m[2:], start=2):
        sender, receiver = (i, r) if n % 2 == 0 else (r, i)
        ct = sender.send(h(msg["payload"]))
        assert ct.hex() == msg["ciphertext"]
        assert receiver.receive(ct) == h(msg["payload"])


# --- noise session behaviour ---------------------------------------------------


def handshake() -> tuple[NoiseIK, NoiseIK, StaticKeyPair, StaticKeyPair]:
    i_static, r_static = StaticKeyPair.generate(), StaticKeyPair.generate()
    i = NoiseIK(Role.INITIATOR, i_static, remote_static=r_static.public_bytes)
    r = NoiseIK(Role.RESPONDER, r_static)
    assert r.read_handshake(i.write_handshake(b"desc-i")) == b"desc-i"
    assert i.read_handshake(r.write_handshake(b"desc-r")) == b"desc-r"
    return i, r, i_static, r_static


def test_handshake_agrees_on_hash_keys_and_identities() -> None:
    i, r, i_static, r_static = handshake()
    assert i.handshake_hash == r.handshake_hash
    assert len(i.handshake_hash) == 64  # BLAKE2b HASHLEN
    assert len(i.noise_h) == 32
    assert i.noise_h == r.noise_h
    assert i.split_keys() == r.split_keys()
    assert i.split_keys()[0] != i.split_keys()[1]
    assert (r.remote_static, i.remote_static) == (i_static.public_bytes, r_static.public_bytes)


def test_wrong_responder_static_fails_closed() -> None:
    r_static = StaticKeyPair.generate()
    i = NoiseIK(
        Role.INITIATOR,
        StaticKeyPair.generate(),
        remote_static=StaticKeyPair.generate().public_bytes,
    )
    r = NoiseIK(Role.RESPONDER, r_static)
    with pytest.raises(CryptoError, match="handshake authentication failed"):
        r.read_handshake(i.write_handshake(b"x"))


def test_handshake_order_enforced() -> None:
    i, r = (
        NoiseIK(
            Role.INITIATOR,
            StaticKeyPair.generate(),
            remote_static=StaticKeyPair.generate().public_bytes,
        ),
        NoiseIK(Role.RESPONDER, StaticKeyPair.generate()),
    )
    with pytest.raises(CryptoError, match="out of order"):
        r.write_handshake(b"x")
    with pytest.raises(CryptoError, match="not complete"):
        i.split_keys()


# --- ESP envelope -----------------------------------------------------------------

TIMELINE = uuid.UUID("5f0c6a8e-3b7d-4c4e-9a53-2f6a1d9e8b10")


def fixed_keys() -> tuple[DirectionKeys, SigningKey]:
    return DirectionKeys.from_split_key(bytes(range(32))), SigningKey.from_seed(bytes(32))


def header_for(signer: SigningKey, keys: DirectionKeys, seq: int = 7) -> Header:
    return Header(
        profile=1,
        sf_level=2,
        types_bitmap=0x000B,
        consent_flags=0x0001,
        privacy_flags=0,
        capabilities=0,
        timestamp_ns=1_727_000_000_000_000_000,
        timeline_id=TIMELINE,
        segment_seq=seq,
        dt_ms=40,
        phase=0.5,
        sender_id=signer.public_bytes,
        payload_len=0,
        nonce=deterministic_nonce(keys, TIMELINE, seq),
    )


def test_seal_open_roundtrip_and_size() -> None:
    keys, signer = fixed_keys()
    packet = seal_packet(header_for(signer, keys), b"typed latents here", keys, signer)
    assert len(packet) == 180 + len(b"typed latents here")
    opened = open_packet(packet, keys, expected_sender=signer.public_bytes, max_payload_len=1 << 20)
    assert opened.plaintext == b"typed latents here"
    assert opened.header.payload_len == 18


def test_project_golden_packet_is_deterministic() -> None:
    keys, signer = fixed_keys()
    a = seal_packet(header_for(signer, keys), b"abc", keys, signer)
    b = seal_packet(header_for(signer, keys), b"abc", keys, signer)
    assert a == b  # Ed25519 and ChaCha20-Poly1305 are deterministic
    golden = json.loads(
        (
            Path(__file__).resolve().parents[2] / "vectors" / "crypto" / "packet_valid.json"
        ).read_text()
    )
    assert golden["vectors"][0]["packet_hex"] == a.hex()


def test_critical_every_header_bit_flip_fails_authentication() -> None:
    keys, signer = fixed_keys()
    packet = seal_packet(header_for(signer, keys), b"payload", keys, signer)
    for bit in range(100 * 8):
        tampered = bytearray(packet)
        tampered[bit // 8] ^= 1 << (bit % 8)
        with pytest.raises((CryptoError, WireError)):
            open_packet(
                bytes(tampered), keys, expected_sender=signer.public_bytes, max_payload_len=1 << 20
            )


@pytest.mark.parametrize("region", ["ciphertext", "tag", "signature"])
def test_body_tamper_detected(region: str) -> None:
    keys, signer = fixed_keys()
    packet = bytearray(seal_packet(header_for(signer, keys), b"payload", keys, signer))
    index = {"ciphertext": 100, "tag": 107, "signature": 123}[region]
    packet[index] ^= 0x01
    with pytest.raises(CryptoError):
        open_packet(
            bytes(packet), keys, expected_sender=signer.public_bytes, max_payload_len=1 << 20
        )


def test_wrong_signature_key_and_wrong_sender() -> None:
    keys, signer = fixed_keys()
    other = SigningKey.from_seed(b"\x01" * 32)
    with pytest.raises(CryptoError, match="sender_id must equal"):
        seal_packet(header_for(signer, keys), b"x", keys, other)
    packet = seal_packet(header_for(signer, keys), b"x", keys, signer)
    with pytest.raises(CryptoError, match="unexpected sender"):
        open_packet(packet, keys, expected_sender=other.public_bytes, max_payload_len=1 << 20)
    forged = packet[:-64] + other.sign(packet[:-64])
    with pytest.raises(CryptoError, match="signature"):
        open_packet(forged, keys, expected_sender=signer.public_bytes, max_payload_len=1 << 20)


def test_wrong_associated_data_or_key_fails() -> None:
    keys, signer = fixed_keys()
    packet = seal_packet(header_for(signer, keys), b"x", keys, signer)
    other_keys = DirectionKeys.from_split_key(b"\x02" * 32)
    with pytest.raises(CryptoError, match="AEAD"):
        open_packet(
            packet, other_keys, expected_sender=signer.public_bytes, max_payload_len=1 << 20
        )
    # re-signing a modified header defeats the signature check but not the AEAD (AAD = header)
    header = Header.decode(packet[:100])
    modified = dataclasses.replace(header, dt_ms=41).encode()
    body = packet[100:-64]
    resigned = modified + body + signer.sign(modified + body)
    with pytest.raises(CryptoError, match="AEAD"):
        open_packet(resigned, keys, expected_sender=signer.public_bytes, max_payload_len=1 << 20)


def test_length_and_size_bounds_checked_before_crypto() -> None:
    keys, signer = fixed_keys()
    packet = seal_packet(header_for(signer, keys), b"x" * 50, keys, signer)
    with pytest.raises(WireError, match="exceeds max_payload_len"):
        open_packet(packet, keys, expected_sender=signer.public_bytes, max_payload_len=10)
    with pytest.raises(WireError, match="does not match payload_len"):
        open_packet(
            packet + b"\x00", keys, expected_sender=signer.public_bytes, max_payload_len=1 << 20
        )
    with pytest.raises(WireError, match="shorter"):
        open_packet(
            packet[:150], keys, expected_sender=signer.public_bytes, max_payload_len=1 << 20
        )


def test_nonce_derivation_injective_and_tag_collision_guard() -> None:
    keys, _ = fixed_keys()
    nonces = {deterministic_nonce(keys, TIMELINE, s) for s in range(10_000)}
    assert len(nonces) == 10_000
    assert deterministic_nonce(keys, TIMELINE, 1)[:8] == deterministic_nonce(keys, TIMELINE, 2)[:8]
    registry = TimelineTagRegistry()
    registry.register(keys, TIMELINE)
    registry.register(keys, TIMELINE)  # idempotent
    other_direction = DirectionKeys.from_split_key(b"\x09" * 32)
    assert deterministic_nonce(keys, TIMELINE, 0) != deterministic_nonce(
        other_direction, TIMELINE, 0
    )


def test_key_material_not_in_repr() -> None:
    keys, signer = fixed_keys()
    assert keys.aead.hex() not in repr(keys)
    assert "redacted" in repr(keys)
    assert "SigningKey(pk=" in repr(signer)


def test_signed_tlv_covers_type_length_and_body() -> None:
    signer = SigningKey.from_seed(b"\x05" * 32)
    tlv = sign_tlv(0x22, b"\x01" + b"\xaa" * 20, signer)
    assert len(tlv.value) == 21 + 64
    assert verify_signed_tlv(tlv, signer.public_bytes) == b"\x01" + b"\xaa" * 20
    for mutated in (
        Tlv(0x23, tlv.value),  # other type code -> other domain and bytes
        Tlv(0x22, tlv.value[:5] + b"\xab" + tlv.value[6:]),
    ):
        with pytest.raises(CryptoError):
            verify_signed_tlv(mutated, signer.public_bytes)
    with pytest.raises(CryptoError):
        verify_signed_tlv(tlv, SigningKey.from_seed(b"\x06" * 32).public_bytes)
    with pytest.raises(WireError, match="not a canonical signed object"):
        verify_signed_tlv(Tlv(0x60, tlv.value), signer.public_bytes)


pytestmark = pytest.mark.security
