# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""ESP traffic keys and deterministic nonces (ADR-0009)."""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field

from esp.crypto.primitives import KEY_LEN, CryptoError, blake2b


@dataclass(frozen=True, slots=True, repr=False)
class DirectionKeys:
    """Keys for one direction of a session."""

    aead: bytes
    nonce: bytes

    @classmethod
    def from_split_key(cls, k_split: bytes) -> DirectionKeys:
        if len(k_split) != KEY_LEN:
            msg = "split key must be 32 bytes"
            raise CryptoError(msg)
        return cls(
            aead=blake2b(b"esp/v1/aead-key", key=k_split),
            nonce=blake2b(b"esp/v1/nonce-key", key=k_split),
        )

    def __repr__(self) -> str:
        return "DirectionKeys(<redacted>)"


def timeline_tag(keys: DirectionKeys, timeline_id: uuid.UUID) -> bytes:
    return blake2b(b"esp/v1/timeline-tag" + timeline_id.bytes, key=keys.nonce, digest_size=8)


def deterministic_nonce(keys: DirectionKeys, timeline_id: uuid.UUID, segment_seq: int) -> bytes:
    """``timeline_tag(8) || segment_seq_be32`` — injective in ``segment_seq``."""
    if not 0 <= segment_seq <= 2**32 - 1:
        msg = "segment_seq out of range"
        raise CryptoError(msg)
    return timeline_tag(keys, timeline_id) + struct.pack(">I", segment_seq)


@dataclass(slots=True)
class TimelineTagRegistry:
    """Sender-side guard: distinct timelines under one key must have distinct tags."""

    _tags: dict[bytes, uuid.UUID] = field(default_factory=dict)

    def register(self, keys: DirectionKeys, timeline_id: uuid.UUID) -> None:
        tag = timeline_tag(keys, timeline_id)
        owner = self._tags.setdefault(tag, timeline_id)
        if owner != timeline_id:
            msg = "timeline tag collision under this key; open a new session"
            raise CryptoError(msg)
