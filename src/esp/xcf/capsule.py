# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""XCF v1 Experience Capsules (WP-068; V13 section "Decentralized Memory").

Layout (big endian, packed)::

    XCFv1_header (148 B) ‖ key_envelope ‖ ciphertext ‖ auth_tag (16) ‖ capsule_sig (64)

- a fresh 256-bit CEK per capsule; ChaCha20-Poly1305 over the private body
  with AAD = header ‖ key_envelope;
- ``PER_CAPSULE`` (default): public ``policy_ref`` / ``timeline_ref`` are
  keyed BLAKE2b-128 tags under ``K_ref = HKDF-SHA512(salt=nonce, IKM=CEK,
  info="esp/xcf/v1/ref-tags", 32)``; the true UUIDs live only in the
  encrypted body. ``LINEAGE_PSEUDONYM`` may carry the true UUIDs (linkable);
- pseudonymous Ed25519 capsule key ``pk_C`` in the key-envelope prefix;
  ``capsule_sig = Ed25519(sk_C, "esp/xcf/v1/sign" ‖ BLAKE2b-256(B))`` and
  ``CID = BLAKE2b-256("esp/xcf/v1/cid" ‖ B ‖ capsule_sig)``;
- key envelopes: ``DIRECT_HPKE`` (RFC 9180, X25519 / HKDF-SHA256 /
  ChaCha20-Poly1305) — **never advertised as cryptographic erasure** — and
  ``GATED_CEK`` (gate id + CEK wrapped under a gate secret held by a gate
  service or guardian quorum; see :mod:`esp.xcf.gate`).
"""

from __future__ import annotations

import os
import struct
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from enum import IntEnum
from typing import Final

from cryptography.hazmat.primitives import hashes, hpke
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from esp.crypto.primitives import CryptoError, SigningKey, blake2b, ed25519_verify

HEADER: Final = struct.Struct(">BHBB3s16s16s16s16s32sQIff12sIII")
HEADER_LEN: Final = 148
TAG_LEN: Final = 16
SIG_LEN: Final = 64
PREFIX_LEN: Final = 34
if HEADER.size != HEADER_LEN:  # pragma: no cover - import-time invariant
    msg = "XCF header must be 148 bytes"
    raise RuntimeError(msg)
AccessMaterial = Callable[[bytes, bytes], bytes]
"""``(cek, envelope_prefix) -> access_material`` for one envelope algorithm."""
HPKE_SUITE: Final = hpke.Suite(hpke.KEM.X25519, hpke.KDF.HKDF_SHA256, hpke.AEAD.CHACHA20_POLY1305)


class XcfError(ValueError):
    pass


class EnvelopeAlg(IntEnum):
    DIRECT_HPKE = 1
    GATED_CEK = 2
    PROFILE_DEFINED = 3


class SignerMode(IntEnum):
    PER_CAPSULE = 0
    LINEAGE_PSEUDONYM = 1


#: What each envelope may promise about revocation (V13: DIRECT_HPKE never promises erasure).
REVOCATION_GUARANTEE: Final = {
    EnvelopeAlg.DIRECT_HPKE: "policy revocation only: recipients keep decapsulation ability",
    EnvelopeAlg.GATED_CEK: "gate secret destruction prevents future first-time CEK release",
}


@dataclass(frozen=True, slots=True)
class Header:
    types_bitmap: int
    key_envelope_alg: EnvelopeAlg
    policy_ref: bytes
    timeline_ref: bytes
    encoder_id: uuid.UUID
    anchor_set_id: uuid.UUID
    parent_cid: bytes
    created_ns: int
    packets_count: int
    dp_eps_spent: float
    dp_delta: float
    nonce: bytes
    ciphertext_len: int
    key_envelope_len: int
    version: int = 1
    cipher_alg: int = 1

    def encode(self) -> bytes:
        return HEADER.pack(
            self.version,
            self.types_bitmap,
            self.cipher_alg,
            int(self.key_envelope_alg),
            bytes(3),
            self.policy_ref,
            self.timeline_ref,
            self.encoder_id.bytes,
            self.anchor_set_id.bytes,
            self.parent_cid,
            self.created_ns,
            self.packets_count,
            self.dp_eps_spent,
            self.dp_delta,
            self.nonce,
            self.ciphertext_len,
            self.key_envelope_len,
            0,
        )

    @classmethod
    def decode(cls, raw: bytes) -> Header:
        if len(raw) != HEADER_LEN:
            msg = "XCF header must be exactly 148 bytes"
            raise XcfError(msg)
        (
            ver,
            types,
            cipher,
            env,
            reserved,
            pref,
            tref,
            enc,
            anc,
            parent,
            created,
            count,
            eps,
            delta,
            nonce,
            ct_len,
            env_len,
            reserved_len,
        ) = HEADER.unpack(raw)
        if ver != 1 or cipher != 1 or reserved != bytes(3) or reserved_len != 0:
            msg = "unsupported XCF version/cipher or non-zero reserved fields"
            raise XcfError(msg)
        try:
            alg = EnvelopeAlg(env)
        except ValueError:
            msg = f"unknown key_envelope_alg {env}"
            raise XcfError(msg) from None
        return cls(
            types,
            alg,
            pref,
            tref,
            uuid.UUID(bytes=enc),
            uuid.UUID(bytes=anc),
            parent,
            created,
            count,
            eps,
            delta,
            nonce,
            ct_len,
            env_len,
        )


@dataclass(frozen=True, slots=True)
class PrivateBody:
    policy_id: uuid.UUID
    timeline_id: uuid.UUID
    payload: bytes
    policy_blob: bytes = b""
    zk_proof: bytes = b""
    sender_binding: bytes = b""

    def encode(self) -> bytes:
        out = self.policy_id.bytes + self.timeline_id.bytes
        for part in (self.payload, self.policy_blob, self.zk_proof, self.sender_binding):
            out += struct.pack(">I", len(part)) + part
        return out

    @classmethod
    def decode(cls, raw: bytes) -> PrivateBody:
        if len(raw) < 32:
            msg = "private body truncated"
            raise XcfError(msg)
        pid, tid, off = uuid.UUID(bytes=raw[:16]), uuid.UUID(bytes=raw[16:32]), 32
        parts = []
        for _ in range(4):
            if len(raw) < off + 4:
                msg = "private body truncated"
                raise XcfError(msg)
            (n,) = struct.unpack_from(">I", raw, off)
            off += 4
            if len(raw) < off + n:
                msg = "private body truncated"
                raise XcfError(msg)
            parts.append(raw[off : off + n])
            off += n
        if off != len(raw):
            msg = "trailing bytes in private body"
            raise XcfError(msg)
        return cls(pid, tid, *parts)


def ref_key(cek: bytes, nonce: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA512(), length=32, salt=nonce, info=b"esp/xcf/v1/ref-tags"
    ).derive(cek)


def ref_tag(k_ref: bytes, domain: bytes, ident: uuid.UUID) -> bytes:
    return blake2b(domain + ident.bytes, key=k_ref, digest_size=16)


def sender_binding(
    master: SigningKey, pk_c: bytes, policy_id: uuid.UUID, timeline_id: uuid.UUID, created_ns: int
) -> bytes:
    """``pk_M ‖ Ed25519(sk_M, "esp/xcf/v1/bind" ‖ pk_C ‖ policy_id ‖ timeline_id ‖ created_ns)``."""
    msg = (
        b"esp/xcf/v1/bind"
        + pk_c
        + policy_id.bytes
        + timeline_id.bytes
        + struct.pack(">Q", created_ns)
    )
    return master.public_bytes + master.sign(msg)


@dataclass(frozen=True, slots=True)
class Capsule:
    raw: bytes

    @property
    def header(self) -> Header:
        return Header.decode(self.raw[:HEADER_LEN])

    def _parts(self) -> tuple[bytes, bytes, bytes, bytes]:
        h = self.header
        env_end = HEADER_LEN + h.key_envelope_len
        ct_end = env_end + h.ciphertext_len
        if len(self.raw) != ct_end + TAG_LEN + SIG_LEN:
            msg = "capsule length does not match its header"
            raise XcfError(msg)
        return (
            self.raw[HEADER_LEN:env_end],
            self.raw[env_end:ct_end],
            self.raw[ct_end : ct_end + TAG_LEN],
            self.raw[ct_end + TAG_LEN :],
        )

    @property
    def envelope(self) -> bytes:
        return self._parts()[0]

    @property
    def signer_mode(self) -> SignerMode:
        return SignerMode(self.envelope[1])

    @property
    def signer_pk(self) -> bytes:
        return self.envelope[2:PREFIX_LEN]

    @property
    def signed_bytes(self) -> bytes:
        """``B = header ‖ key_envelope ‖ ciphertext ‖ auth_tag``."""
        return self.raw[:-SIG_LEN]

    @property
    def cid(self) -> bytes:
        return blake2b(b"esp/xcf/v1/cid" + self.raw)

    def verify_signature(self) -> None:
        env, _, _, sig = self._parts()
        if len(env) < PREFIX_LEN or env[0] != 1:
            msg = "malformed key-envelope prefix"
            raise XcfError(msg)
        ed25519_verify(env[2:PREFIX_LEN], b"esp/xcf/v1/sign" + blake2b(self.signed_bytes), sig)

    def open_with_cek(self, cek: bytes) -> PrivateBody:
        self.verify_signature()
        env, ct, tag, _ = self._parts()
        h = self.header
        try:
            body = PrivateBody.decode(
                ChaCha20Poly1305(cek).decrypt(h.nonce, ct + tag, self.raw[:HEADER_LEN] + env)
            )
        except CryptoError:
            raise
        except Exception as exc:
            msg = "capsule body authentication failed"
            raise CryptoError(msg) from exc
        if self.signer_mode is SignerMode.PER_CAPSULE:
            k = ref_key(cek, h.nonce)
            if h.policy_ref != ref_tag(k, b"policy", body.policy_id) or h.timeline_ref != ref_tag(
                k, b"timeline", body.timeline_id
            ):
                msg = "public reference tags do not match the private identifiers"
                raise XcfError(msg)
        elif (h.policy_ref, h.timeline_ref) != (body.policy_id.bytes, body.timeline_id.bytes):
            msg = "lineage references do not match the private identifiers"
            raise XcfError(msg)
        return body


@dataclass(frozen=True, slots=True)
class CapsuleSpec:
    types_bitmap: int
    encoder_id: uuid.UUID
    anchor_set_id: uuid.UUID
    created_ns: int
    packets_count: int = 1
    dp_eps_spent: float = 0.0
    dp_delta: float = 0.0
    parent_cid: bytes = bytes(32)
    signer_mode: SignerMode = SignerMode.PER_CAPSULE


def seal(
    spec: CapsuleSpec,
    body: PrivateBody,
    *,
    envelope_alg: EnvelopeAlg,
    access_material: AccessMaterial,
    capsule_key: SigningKey | None = None,
    cek: bytes | None = None,
    nonce: bytes | None = None,
) -> tuple[Capsule, bytes]:
    """Seal a capsule. ``access_material(cek, header_prefix)`` builds the algorithm-specific
    envelope remainder. Returns the capsule and the CEK (for the caller's gate/recipient setup)."""
    # fixed cek/nonce exist only for golden vectors; production callers leave them random
    cek = os.urandom(32) if cek is None else cek
    nonce = os.urandom(12) if nonce is None else nonce
    if len(cek) != 32 or len(nonce) != 12:
        msg = "CEK must be 32 bytes and nonce 12 bytes"
        raise XcfError(msg)
    signer = capsule_key or SigningKey.generate()  # PER_CAPSULE: fresh pseudonym per capsule
    if spec.signer_mode is SignerMode.PER_CAPSULE:
        k = ref_key(cek, nonce)
        pref, tref = (
            ref_tag(k, b"policy", body.policy_id),
            ref_tag(k, b"timeline", body.timeline_id),
        )
    else:
        pref, tref = body.policy_id.bytes, body.timeline_id.bytes
    plaintext = body.encode()
    prefix = bytes([1, int(spec.signer_mode)]) + signer.public_bytes
    material = access_material(cek, prefix)
    envelope = prefix + material
    header = Header(
        types_bitmap=spec.types_bitmap,
        key_envelope_alg=envelope_alg,
        policy_ref=pref,
        timeline_ref=tref,
        encoder_id=spec.encoder_id,
        anchor_set_id=spec.anchor_set_id,
        parent_cid=spec.parent_cid,
        created_ns=spec.created_ns,
        packets_count=spec.packets_count,
        dp_eps_spent=spec.dp_eps_spent,
        dp_delta=spec.dp_delta,
        nonce=nonce,
        ciphertext_len=len(plaintext),
        key_envelope_len=len(envelope),
    ).encode()
    sealed = ChaCha20Poly1305(cek).encrypt(nonce, plaintext, header + envelope)
    b = header + envelope + sealed
    sig = signer.sign(b"esp/xcf/v1/sign" + blake2b(b))
    return Capsule(b + sig), cek


# --- DIRECT_HPKE ---------------------------------------------------------------------------------


def hpke_access(recipient: X25519PublicKey) -> AccessMaterial:
    def material(cek: bytes, prefix: bytes) -> bytes:
        return HPKE_SUITE.encrypt(cek, recipient, info=b"esp/xcf/v1/hpke" + prefix)

    return material


def hpke_unwrap(capsule: Capsule, recipient: X25519PrivateKey) -> bytes:
    if capsule.header.key_envelope_alg is not EnvelopeAlg.DIRECT_HPKE:
        msg = "not a DIRECT_HPKE capsule"
        raise XcfError(msg)
    env = capsule.envelope
    try:
        return HPKE_SUITE.decrypt(
            env[PREFIX_LEN:], recipient, info=b"esp/xcf/v1/hpke" + env[:PREFIX_LEN]
        )
    except Exception as exc:
        msg = "HPKE unwrap failed"
        raise CryptoError(msg) from exc
