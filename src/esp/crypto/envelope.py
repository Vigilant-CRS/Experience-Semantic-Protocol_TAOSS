# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Packet envelope: ``header(100) || ciphertext || tag(16) || signature(64)``.

- AEAD: ChaCha20-Poly1305; associated data = the 100-byte header as transmitted.
- Signature: Ed25519 by the per-session key ``sender_id`` over
  ``header || ciphertext || tag`` (V13 section 9.2).
- ``payload_len`` = ciphertext length (ADR-0010).

:func:`open_packet` checks, in order: size bounds, header syntax, the
length formula, that ``sender_id`` is the expected peer, the signature, and
finally AEAD. Nothing is decrypted for an unauthenticated sender.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass

from esp.codec.errors import WireError
from esp.codec.header import HEADER_LEN, PACKET_OVERHEAD, SIGNATURE_LEN, TAG_LEN, Header
from esp.crypto.keys import DirectionKeys
from esp.crypto.primitives import CryptoError, SigningKey, aead_open, aead_seal, ed25519_verify


@dataclass(frozen=True, slots=True)
class OpenedPacket:
    header: Header
    plaintext: bytes
    raw: bytes


def seal_packet(header: Header, plaintext: bytes, keys: DirectionKeys, signer: SigningKey) -> bytes:
    """Encrypt and sign. ``header.payload_len`` and ``sender_id`` are set here."""
    if header.sender_id != signer.public_bytes:
        msg = "header sender_id must equal the session signing key"
        raise CryptoError(msg)
    final = dataclasses.replace(header, payload_len=len(plaintext))
    raw_header = final.encode()
    ciphertext, tag = aead_seal(keys.aead, final.nonce, raw_header, plaintext)
    signature = signer.sign(raw_header + ciphertext + tag)
    return raw_header + ciphertext + tag + signature


def open_packet(
    packet: bytes,
    keys: DirectionKeys,
    *,
    expected_sender: bytes,
    max_payload_len: int,
) -> OpenedPacket:
    """Verify and decrypt one packet. Raises :class:`WireError` or :class:`CryptoError`."""
    if len(packet) < PACKET_OVERHEAD:
        msg = "packet shorter than the fixed overhead"
        raise WireError(msg)
    if len(packet) > PACKET_OVERHEAD + max_payload_len:
        msg = "packet exceeds max_payload_len"
        raise WireError(msg)
    header = Header.decode(packet[:HEADER_LEN])
    if header.payload_len > max_payload_len:
        msg = "payload_len exceeds max_payload_len"
        raise WireError(msg)
    if len(packet) != header.packet_len:
        msg = "packet length does not match payload_len"
        raise WireError(msg)
    if header.sender_id != expected_sender:
        msg = "unexpected sender"
        raise CryptoError(msg)
    body_end = HEADER_LEN + header.payload_len
    ciphertext = packet[HEADER_LEN:body_end]
    tag = packet[body_end : body_end + TAG_LEN]
    signature = packet[body_end + TAG_LEN :]
    if len(signature) != SIGNATURE_LEN:  # pragma: no cover - implied by the length check
        msg = "bad signature length"
        raise WireError(msg)
    ed25519_verify(header.sender_id, packet[: body_end + TAG_LEN], signature)
    plaintext = aead_open(keys.aead, header.nonce, packet[:HEADER_LEN], ciphertext, tag)
    return OpenedPacket(header=header, plaintext=plaintext, raw=packet)
