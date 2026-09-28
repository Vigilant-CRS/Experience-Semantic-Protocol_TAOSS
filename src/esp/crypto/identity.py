# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Per-session pseudonymous identities and their bindings (V13 sections 9.3-9.4).

- A sender holds a long-term master key ``sk_M``; every session uses an
  *independently generated* Ed25519 key ``(sk_S, pk_S)`` from the CSPRNG,
  never derived from ``sk_M``. The header carries only ``pk_S``.
- ``TLV_IDENTITY_PROOF`` (0x20, V13) links ``pk_S`` to ``pk_M`` for authorized
  recipients: ``Ed25519(sk_M, "esp/v1/identity-proof" || pk_S || noise_h || epoch)``.
  At most once per session, encrypted, never in cleartext.
- ``SESSION_BINDING`` (0x85, ADR-0013) proves possession of ``sk_S`` for this
  Noise transcript. ``STATIC_KEY_BINDING`` (0x84) cross-signs a Noise static key.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Final, Protocol

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv
from esp.crypto.primitives import CryptoError, SigningKey, ed25519_verify
from esp.crypto.signed import sign_tlv, verify_signed_tlv

IDENTITY_PROOF_CODE: Final = 0x20
STATIC_KEY_BINDING_CODE: Final = 0x84
SESSION_BINDING_CODE: Final = 0x85
IDENTITY_PROOF_DOMAIN: Final = b"esp/v1/identity-proof"
_PROOF_LEN: Final = 32 + 32 + 8 + 64


class MasterSigner(Protocol):
    """Long-term identity key. May be hardware-backed (WP-072)."""

    @property
    def public_bytes(self) -> bytes: ...

    def sign(self, message: bytes) -> bytes: ...


def new_session_identity() -> SigningKey:
    """Fresh per-session pseudonym from the OS CSPRNG (V13 eq. seed_S)."""
    return SigningKey.generate()


@dataclass(frozen=True, slots=True)
class IdentityProof:
    pk_master: bytes
    noise_h: bytes
    epoch: int

    def encode(self, master: MasterSigner, pk_session: bytes) -> Tlv:
        if master.public_bytes != self.pk_master:
            msg = "proof must be signed by its own master key"
            raise CryptoError(msg)
        signature = master.sign(_proof_message(pk_session, self.noise_h, self.epoch))
        body = self.pk_master + self.noise_h + struct.pack(">Q", self.epoch) + signature
        return Tlv(IDENTITY_PROOF_CODE, body)

    @classmethod
    def verify(cls, tlv: Tlv, *, pk_session: bytes, noise_h: bytes) -> IdentityProof:
        """Verify a received proof against *this* session's key and transcript."""
        if tlv.code != IDENTITY_PROOF_CODE or len(tlv.value) != _PROOF_LEN:
            msg = "malformed identity proof"
            raise WireError(msg)
        pk_master, proof_h = tlv.value[:32], tlv.value[32:64]
        (epoch,) = struct.unpack(">Q", tlv.value[64:72])
        if proof_h != noise_h:
            msg = "identity proof bound to another transcript"
            raise CryptoError(msg)
        ed25519_verify(pk_master, _proof_message(pk_session, noise_h, epoch), tlv.value[72:])
        return cls(pk_master=pk_master, noise_h=noise_h, epoch=epoch)


def _proof_message(pk_session: bytes, noise_h: bytes, epoch: int) -> bytes:
    if len(pk_session) != 32 or len(noise_h) != 32:
        msg = "pk_S and noise_h must be 32 bytes"
        raise CryptoError(msg)
    return IDENTITY_PROOF_DOMAIN + pk_session + noise_h + struct.pack(">Q", epoch)


@dataclass(slots=True)
class IdentityProofGuard:
    """Enforces "at most once per session" on both sides."""

    _seen: bool = field(default=False)

    def admit(self) -> None:
        if self._seen:
            msg = "identity proof already sent/received in this session"
            raise CryptoError(msg)
        self._seen = True


def session_binding(session_key: SigningKey, noise_h: bytes) -> Tlv:
    if len(noise_h) != 32:
        msg = "noise_h must be 32 bytes"
        raise CryptoError(msg)
    return sign_tlv(SESSION_BINDING_CODE, b"\x01" + session_key.public_bytes + noise_h, session_key)


def verify_session_binding(tlv: Tlv, *, noise_h: bytes) -> bytes:
    """Return the peer's session public key (``sender_id``) bound to ``noise_h``."""
    if tlv.code != SESSION_BINDING_CODE or len(tlv.value) != 1 + 32 + 32 + 64:
        msg = "malformed session binding"
        raise WireError(msg)
    pk_session = tlv.value[1:33]
    body = verify_signed_tlv(tlv, pk_session)
    if body[0] != 1:
        msg = "unsupported session binding version"
        raise WireError(msg)
    if body[33:65] != noise_h:
        msg = "session binding belongs to another transcript"
        raise CryptoError(msg)
    return pk_session


def static_key_binding(identity: MasterSigner, x25519_pk: bytes, valid_until_ns: int) -> Tlv:
    if len(x25519_pk) != 32:
        msg = "x25519 key must be 32 bytes"
        raise CryptoError(msg)
    body = b"\x01" + x25519_pk + identity.public_bytes + struct.pack(">Q", valid_until_ns)
    return sign_tlv(STATIC_KEY_BINDING_CODE, body, identity)


def verify_static_key_binding(
    tlv: Tlv, *, x25519_pk: bytes, identity_pk: bytes, now_ns: int
) -> None:
    if tlv.code != STATIC_KEY_BINDING_CODE or len(tlv.value) != 1 + 32 + 32 + 8 + 64:
        msg = "malformed static key binding"
        raise WireError(msg)
    body = verify_signed_tlv(tlv, identity_pk)
    if body[1:33] != x25519_pk or body[33:65] != identity_pk:
        msg = "static key binding names other keys"
        raise CryptoError(msg)
    (valid_until,) = struct.unpack(">Q", body[65:73])
    if now_ns > valid_until:
        msg = "static key binding expired"
        raise CryptoError(msg)
