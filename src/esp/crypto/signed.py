# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Canonical signed TLV objects (V13 section 9.2, ADR-0015).

For every TLV whose schema signs "all previous fields", the signature input
is ``domain || tlv_bytes[: total_length - 64]`` — every byte as transmitted,
including ``t`` and ``length`` (which already counts the 64-byte signature).
"""

from __future__ import annotations

import struct
from typing import Final, Protocol

from esp.codec.errors import WireError
from esp.codec.tlv import TLV_HEADER_LEN, Tlv
from esp.crypto.primitives import SIG_LEN, ed25519_verify

#: Domain separators of V13 v1 signed objects (V13 section 8.4 / 9).
DOMAINS: Final = {
    0x21: b"esp/v1/receiver-capability",
    0x22: b"esp/v1/capability",
    0x23: b"esp/v1/revocation",
    0x24: b"esp/v1/deletion-attestation",
    0x41: b"esp/v1/key-revoked",
    0x70: b"esp/v1/hive-grant",
    0x84: b"esp/v1/static-binding",
    0x85: b"esp/v1/session-binding",
}


class Signer(Protocol):
    """Anything that produces Ed25519 signatures (software key or hardware)."""

    def sign(self, message: bytes) -> bytes: ...


def _prefix(code: int, body_without_sig: bytes) -> bytes:
    return struct.pack(">BI", code, len(body_without_sig) + SIG_LEN) + body_without_sig


def sign_tlv(code: int, body_without_sig: bytes, signer: Signer) -> Tlv:
    """Build a signed TLV whose last 64 value bytes are the Ed25519 signature."""
    domain = DOMAINS[code]
    signature = signer.sign(domain + _prefix(code, body_without_sig))
    return Tlv(code, body_without_sig + signature)


def verify_signed_tlv(tlv: Tlv, public_key: bytes) -> bytes:
    """Verify and return the body without the signature.

    Raises :class:`~esp.crypto.primitives.CryptoError` on a bad signature.
    """
    if tlv.code not in DOMAINS:
        msg = f"TLV 0x{tlv.code:02x} is not a canonical signed object"
        raise WireError(msg)
    if len(tlv.value) < SIG_LEN:
        msg = "signed TLV shorter than its signature"
        raise WireError(msg)
    body, signature = tlv.value[:-SIG_LEN], tlv.value[-SIG_LEN:]
    signed = DOMAINS[tlv.code] + tlv.encode()[: TLV_HEADER_LEN + len(body)]
    ed25519_verify(public_key, signed, signature)
    return body
