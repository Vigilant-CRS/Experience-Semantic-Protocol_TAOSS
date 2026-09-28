# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Noise IK session establishment (V13 section 9.2; ADR-0012, ADR-0013).

Protocol: ``Noise_IK_25519_ChaChaPoly_BLAKE2b`` with prologue ``esp/v1``.

Establishment flow (GAP-025):

1. I -> R  handshake message 1, payload = initiator session descriptor
2. R -> I  handshake message 2, payload = responder session descriptor
3. both    handshake complete: ``noise_h`` and split keys known
4. R -> I  first transport message: SESSION_BINDING, ReceiverCapability (bound to ``noise_h``)
5. I -> R  first transport message: SESSION_BINDING, SenderCapability, optional identity proof
6. ESP application packets, keyed by :class:`~esp.crypto.keys.DirectionKeys`

Objects that must sign the *final* transcript hash cannot live inside the
handshake messages (the hash covers them), hence steps 4-5.
"""

from __future__ import annotations

import warnings
from enum import Enum
from typing import Final

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)
from noise.connection import Keypair, NoiseConnection
from noise.exceptions import NoiseInvalidMessage

from esp.crypto.primitives import CryptoError

PROTOCOL_NAME: Final = b"Noise_IK_25519_ChaChaPoly_BLAKE2b"
PROLOGUE: Final = b"esp/v1"
MAX_NOISE_MESSAGE: Final = 65535


class Role(Enum):
    INITIATOR = "initiator"
    RESPONDER = "responder"


class StaticKeyPair:
    """X25519 static key pair for Noise."""

    __slots__ = ("_sk",)

    def __init__(self, sk: X25519PrivateKey) -> None:
        self._sk = sk

    @classmethod
    def generate(cls) -> StaticKeyPair:
        return cls(X25519PrivateKey.generate())

    @classmethod
    def from_private_bytes(cls, raw: bytes) -> StaticKeyPair:
        return cls(X25519PrivateKey.from_private_bytes(raw))

    @property
    def public_bytes(self) -> bytes:
        return self._sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def private_bytes(self) -> bytes:
        return self._sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())

    def __repr__(self) -> str:
        return f"StaticKeyPair(pk={self.public_bytes.hex()[:16]}…)"


class NoiseIK:
    """One side of a Noise IK handshake plus its transport cipher states."""

    def __init__(
        self,
        role: Role,
        static: StaticKeyPair,
        *,
        remote_static: bytes | None = None,
        prologue: bytes = PROLOGUE,
        _test_ephemeral: bytes | None = None,
    ) -> None:
        if (role is Role.INITIATOR) != (remote_static is not None):
            msg = "the initiator (and only the initiator) must know the responder static key"
            raise CryptoError(msg)
        self.role = role
        self._conn = NoiseConnection.from_name(PROTOCOL_NAME)
        if role is Role.INITIATOR:
            self._conn.set_as_initiator()
        else:
            self._conn.set_as_responder()
        self._conn.set_prologue(prologue)
        self._conn.set_keypair_from_private_bytes(Keypair.STATIC, static.private_bytes())
        if remote_static is not None:
            self._conn.set_keypair_from_public_bytes(Keypair.REMOTE_STATIC, remote_static)
        if _test_ephemeral is None:
            self._conn.start_handshake()
        else:  # fixed ephemeral key: official test vectors only, never production
            self._conn.set_keypair_from_private_bytes(Keypair.EPHEMERAL, _test_ephemeral)
            with warnings.catch_warnings():
                warnings.filterwarnings("ignore", "One of ephemeral keypairs", UserWarning)
                self._conn.start_handshake()
        self._messages = 0
        self._remote_static: bytes | None = remote_static

    # --- handshake ------------------------------------------------------------

    def write_handshake(self, payload: bytes) -> bytes:
        self._expect_turn(writing=True)
        message: bytes = self._conn.write_message(payload)
        self._messages += 1
        return message

    def read_handshake(self, message: bytes) -> bytes:
        self._expect_turn(writing=False)
        if len(message) > MAX_NOISE_MESSAGE:
            msg = "handshake message too long"
            raise CryptoError(msg)
        try:
            payload: bytes = self._conn.read_message(message)
        except (NoiseInvalidMessage, InvalidTag, ValueError) as exc:
            msg = "handshake authentication failed"
            raise CryptoError(msg) from exc
        self._messages += 1
        if self._remote_static is None:
            # Responder learns the initiator static key from message 1 (IK "s" token).
            learned: bytes = self._conn.noise_protocol.handshake_state.rs.public_bytes
            self._remote_static = learned
        return payload

    def _expect_turn(self, *, writing: bool) -> None:
        if self.complete:
            msg = "handshake already complete"
            raise CryptoError(msg)
        initiator_turn = self._messages == 0
        mine = initiator_turn == (self.role is Role.INITIATOR)
        if mine != writing:
            msg = "handshake message out of order"
            raise CryptoError(msg)

    @property
    def complete(self) -> bool:
        return bool(self._conn.handshake_finished)

    @property
    def handshake_hash(self) -> bytes:
        self._require_complete()
        h: bytes = self._conn.get_handshake_hash()
        return h

    @property
    def remote_static(self) -> bytes:
        """The authenticated X25519 static key of the peer."""
        self._require_complete()
        if self._remote_static is None:  # pragma: no cover - set during the handshake
            msg = "remote static key unknown"
            raise CryptoError(msg)
        return self._remote_static

    def split_keys(self) -> tuple[bytes, bytes]:
        """``(k_i2r, k_r2i)`` — the raw Noise ``Split()`` keys (ADR-0009 derives from them)."""
        self._require_complete()
        enc = self._conn.noise_protocol.cipher_state_encrypt.k
        dec = self._conn.noise_protocol.cipher_state_decrypt.k
        return (enc, dec) if self.role is Role.INITIATOR else (dec, enc)

    # --- establishment transport messages -------------------------------------

    def send(self, payload: bytes) -> bytes:
        self._require_complete()
        out: bytes = self._conn.encrypt(payload)
        return out

    def receive(self, message: bytes) -> bytes:
        self._require_complete()
        try:
            out: bytes = self._conn.decrypt(message)
        except (NoiseInvalidMessage, InvalidTag, ValueError) as exc:
            msg = "transport message authentication failed"
            raise CryptoError(msg) from exc
        return out

    def _require_complete(self) -> None:
        if not self.complete:
            msg = "handshake not complete"
            raise CryptoError(msg)
