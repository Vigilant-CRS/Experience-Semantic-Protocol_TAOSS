# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Thin, typed wrappers around audited primitives."""

from __future__ import annotations

import hashlib
from typing import Final

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from esp.core.errors import ErrorCode, EspError

KEY_LEN: Final = 32
NONCE_LEN: Final = 12
TAG_LEN: Final = 16
SIG_LEN: Final = 64


class CryptoError(EspError):
    """Authentication or key failure. Deliberately uninformative towards peers."""

    code = ErrorCode.CRYPTO_AUTH_FAILED


def blake2b(data: bytes, *, key: bytes = b"", digest_size: int = 32) -> bytes:
    """BLAKE2b (RFC 7693), optionally keyed."""
    return hashlib.blake2b(data, key=key, digest_size=digest_size).digest()


def aead_seal(key: bytes, nonce: bytes, aad: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
    """ChaCha20-Poly1305 (RFC 8439). Returns ``(ciphertext, tag)``."""
    _check_len("key", key, KEY_LEN)
    _check_len("nonce", nonce, NONCE_LEN)
    out = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    return out[:-TAG_LEN], out[-TAG_LEN:]


def aead_open(key: bytes, nonce: bytes, aad: bytes, ciphertext: bytes, tag: bytes) -> bytes:
    _check_len("key", key, KEY_LEN)
    _check_len("nonce", nonce, NONCE_LEN)
    _check_len("tag", tag, TAG_LEN)
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext + tag, aad)
    except InvalidTag:
        msg = "AEAD authentication failed"
        raise CryptoError(msg) from None


class SigningKey:
    """Ed25519 signing key (RFC 8032)."""

    __slots__ = ("_sk",)

    def __init__(self, sk: Ed25519PrivateKey) -> None:
        self._sk = sk

    @classmethod
    def generate(cls) -> SigningKey:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> SigningKey:
        _check_len("seed", seed, KEY_LEN)
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    @property
    def public_bytes(self) -> bytes:
        return self._sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    def sign(self, message: bytes) -> bytes:
        return self._sk.sign(message)

    def __repr__(self) -> str:
        return f"SigningKey(pk={self.public_bytes.hex()[:16]}…)"


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> None:
    """Raise :class:`CryptoError` unless ``signature`` is valid."""
    _check_len("public key", public_key, KEY_LEN)
    if len(signature) != SIG_LEN:
        msg = "signature verification failed"
        raise CryptoError(msg)
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        msg = "signature verification failed"
        raise CryptoError(msg) from None


def _check_len(name: str, value: bytes, n: int) -> None:
    if not isinstance(value, bytes) or len(value) != n:
        msg = f"{name} must be {n} bytes"
        raise CryptoError(msg)
