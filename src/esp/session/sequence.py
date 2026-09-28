# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sender sequence state and nonce-reuse prevention (V13 section 9.2; ADR-0009, ADR-0016).

Invariants:

(i)   a retransmission reuses the *identical* packet bytes; a different
      plaintext under an already used ``segment_seq`` is refused;
(ii)  ``segment_seq`` never rewinds; the next value is persisted *before* a
      packet is released (fail closed). Missing, corrupt or foreign state
      means the session must terminate and a new one be established;
(iii) in the random-nonce profile every nonce is checked against the set of
      nonces used under the key, and duplicates are redrawn before encryption.
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Final

from esp.core.errors import ErrorCode, EspError

#: Last usable sequence number (ADR-0016): 2^32 - 1 is never used.
MAX_SEQUENCE: Final = 2**32 - 2


class SessionTerminatedError(EspError):
    """Sender state is lost or exhausted; a fresh session is mandatory."""

    code = ErrorCode.SESSION_STATE


class NonceReuseError(EspError):
    """An attempt to protect a different plaintext under a used (key, nonce)."""

    code = ErrorCode.CRYPTO_AUTH_FAILED


@dataclass(slots=True)
class SequenceStore:
    """Durable next-sequence storage for one (session key, timeline).

    The file holds ``{"session": <fingerprint>, "next": <int>}``. Updates are
    atomic (write temp + fsync + rename + fsync directory).
    """

    path: Path
    session_fingerprint: str

    def initialize(self) -> None:
        if self.path.exists():
            msg = "sequence state already exists for a new session"
            raise SessionTerminatedError(msg)
        self._write(0)

    def load(self) -> int:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            msg = "sender sequence state lost or corrupt"
            raise SessionTerminatedError(msg) from exc
        if not isinstance(data, dict) or data.get("session") != self.session_fingerprint:
            msg = "sequence state belongs to another session"
            raise SessionTerminatedError(msg)
        value = data.get("next")
        if (
            not isinstance(value, int)
            or isinstance(value, bool)
            or not 0 <= value <= MAX_SEQUENCE + 1
        ):
            msg = "sequence state corrupt"
            raise SessionTerminatedError(msg)
        return value

    def store(self, next_seq: int) -> None:
        self._write(next_seq)

    def _write(self, next_seq: int) -> None:
        payload = json.dumps({"session": self.session_fingerprint, "next": next_seq}).encode()
        directory = self.path.parent
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".seq-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            Path(tmp).replace(self.path)
            try:
                dir_fd = os.open(directory, os.O_RDONLY)
            except OSError:  # pragma: no cover - platforms without directory fds
                return
            try:
                os.fsync(dir_fd)
            except OSError:  # pragma: no cover - some filesystems refuse dir fsync
                pass
            finally:
                os.close(dir_fd)
        finally:
            Path(tmp).unlink(missing_ok=True)


def session_fingerprint(aead_key: bytes) -> str:
    """Non-secret identifier of a session key (for state files)."""
    return hashlib.blake2b(b"esp/v1/state-fingerprint" + aead_key, digest_size=16).hexdigest()


@dataclass(slots=True)
class SenderSequencer:
    """Allocates sequence numbers and guards against nonce reuse.

    ``sent`` caches the exact packet bytes per sequence for retransmission.
    """

    store: SequenceStore
    _next: int = field(init=False)
    _plaintext_digest: dict[int, bytes] = field(default_factory=dict, init=False)
    _sent: dict[int, bytes] = field(default_factory=dict, init=False)

    def __post_init__(self) -> None:
        self._next = self.store.load()

    @property
    def next_sequence(self) -> int:
        return self._next

    def reserve(self, plaintext: bytes) -> int:
        """Reserve the next sequence for ``plaintext``; persisted before return."""
        seq = self._next
        if seq > MAX_SEQUENCE:
            msg = "segment_seq exhausted; establish a new session (ADR-0016)"
            raise SessionTerminatedError(msg)
        self.store.store(seq + 1)  # fail closed: persist first
        self._next = seq + 1
        self._plaintext_digest[seq] = hashlib.blake2b(plaintext, digest_size=32).digest()
        return seq

    def record_sent(self, seq: int, plaintext: bytes, packet: bytes) -> None:
        digest = hashlib.blake2b(plaintext, digest_size=32).digest()
        if self._plaintext_digest.get(seq) != digest:
            msg = f"segment_seq {seq} was reserved for a different plaintext"
            raise NonceReuseError(msg)
        if seq in self._sent:
            msg = f"segment_seq {seq} already sent"
            raise NonceReuseError(msg)
        self._sent[seq] = packet

    def retransmit(self, seq: int) -> bytes:
        """The identical bytes of an earlier packet (never re-encrypted)."""
        try:
            return self._sent[seq]
        except KeyError:
            msg = f"no packet sent with segment_seq {seq}"
            raise NonceReuseError(msg) from None

    def forget(self, seq: int) -> None:
        """Drop a retransmission buffer entry once acknowledged."""
        self._sent.pop(seq, None)


@dataclass(slots=True)
class RandomNonceSource:
    """Random-nonce profile: uniqueness is enforced *before* encryption (rule iii)."""

    max_nonces: int = 2**32
    _used: set[bytes] = field(default_factory=set)
    _random: Callable[[int], bytes] = secrets.token_bytes

    def next_nonce(self) -> bytes:
        if len(self._used) >= self.max_nonces:
            msg = "random-nonce budget of this key exhausted"
            raise SessionTerminatedError(msg)
        for _ in range(64):
            nonce = self._random(12)
            if nonce not in self._used:
                self._used.add(nonce)
                return nonce
        msg = "random nonce source repeatedly produced duplicates"  # pragma: no cover
        raise SessionTerminatedError(msg)  # pragma: no cover
