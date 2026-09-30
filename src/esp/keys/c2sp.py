# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""C2SP signed notes, checkpoints and witness cosignatures for the ESP log (ADR-0023, GAP-019).

The ESP transparency log (:mod:`esp.keys.transparency`) keeps its own
``esp/v1/tree-head`` format. To be cosigned by *public* transparency witnesses,
the same tree (same RFC 9162 = RFC 6962 root and size) is also published in the
formats the witness ecosystem speaks:

- ``c2sp.org/signed-note``: text, a blank line, then signature lines
  ``— <key name> base64(key ID || signature)``. Key ID is
  ``SHA-256(key name || 0x0A || type || public key)[:4]``; type ``0x01`` is an
  Ed25519 signature over the note text;
- ``c2sp.org/tlog-checkpoint``: the note text is ``origin``, tree size (decimal,
  no leading zeroes), base64 root hash, then optional non-empty extension lines;
- ``c2sp.org/tlog-cosignature``: an Ed25519 witness cosignature (type ``0x04``).
  Its signature is ``u64 timestamp || Ed25519 signature`` over
  ``"cosignature/v1\\n" || "time <timestamp>\\n" || checkpoint note text``.

Verification follows the spec:

- signatures from unknown keys (name *and* ID must match) are ignored;
- a failing signature from a known key rejects the whole note;
- a note without any verified signature is rejected.

For checkpoints, the log signature must verify and a quorum of distinct,
independent witnesses (the log key never counts) must cosign.

Formats taken from the C2SP editor's copies (signed-note, tlog-checkpoint,
tlog-cosignature at github.com/C2SP/C2SP). The tests reproduce the vectors of
``c2sp.org/signed-note`` and ``golang.org/x/mod/sumdb/note`` byte-exactly.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

from esp.crypto.primitives import CryptoError, SigningKey, ed25519_verify
from esp.keys.transparency import TransparencyLog, TreeHead

SIG_ED25519: Final = 0x01
SIG_COSIGNATURE_V1: Final = 0x04
EM_DASH: Final = "—"
MAX_SIGNATURES: Final = 100
"""Upper bound on signature lines (the spec requires accepting at least 16)."""
MAX_NOTE_BYTES: Final = 1 << 20
MAX_TIMESTAMP: Final = 2**63 - 1
_DECIMAL: Final = re.compile(r"^(0|[1-9][0-9]*)$")


class NoteError(CryptoError):
    """Malformed or unverifiable signed note, checkpoint or cosignature."""


def _b64decode(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        msg = "invalid base64"
        raise NoteError(msg) from exc


def _b64encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def check_key_name(name: str) -> None:
    """Key names are non-empty and contain no Unicode space and no ``+``."""
    if not name or "+" in name or any(ch.isspace() for ch in name):
        msg = f"invalid key name {name!r}"
        raise NoteError(msg)


def key_id(name: str, sig_type: int, public_key: bytes) -> int:
    """``SHA-256(name || 0x0A || type || public key)[:4]`` as a big-endian uint32."""
    check_key_name(name)
    digest = hashlib.sha256(name.encode() + b"\n" + bytes([sig_type]) + public_key).digest()
    return int(struct.unpack(">I", digest[:4])[0])


# --- keys -------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NoteVerifier:
    name: str
    sig_type: int
    public_key: bytes

    def __post_init__(self) -> None:
        check_key_name(self.name)
        if self.sig_type not in (SIG_ED25519, SIG_COSIGNATURE_V1) or len(self.public_key) != 32:
            msg = "only Ed25519 note (0x01) and cosignature v1 (0x04) keys are supported"
            raise NoteError(msg)

    @property
    def key_id(self) -> int:
        return key_id(self.name, self.sig_type, self.public_key)

    def vkey(self) -> str:
        """``<name>+hex(key ID)+base64(type || public key)`` (signed-note verifier key)."""
        return (
            f"{self.name}+{self.key_id:08x}+{_b64encode(bytes([self.sig_type]) + self.public_key)}"
        )

    @classmethod
    def from_vkey(cls, vkey: str) -> NoteVerifier:
        parts = vkey.split("+", 2)  # the base64 part may itself contain "+"
        if len(parts) != 3 or not re.fullmatch(r"[0-9a-f]{8}", parts[1]):
            msg = "malformed verifier key"
            raise NoteError(msg)
        material = _b64decode(parts[2])
        if len(material) < 1:
            msg = "malformed verifier key"
            raise NoteError(msg)
        v = cls(parts[0], material[0], material[1:])
        if v.key_id != int(parts[1], 16):
            msg = "verifier key ID does not match name and key"
            raise NoteError(msg)
        return v


@dataclass(frozen=True, slots=True)
class NoteSigner:
    name: str
    sig_type: int
    key: SigningKey

    @property
    def verifier(self) -> NoteVerifier:
        return NoteVerifier(self.name, self.sig_type, self.key.public_bytes)

    @classmethod
    def from_go_skey(cls, skey: str) -> NoteSigner:
        """``PRIVATE+KEY+<name>+<hex id>+base64(0x01 || seed)`` (golang.org/x/mod/sumdb/note)."""
        parts = skey.split("+", 4)  # the base64 part may itself contain "+"
        if len(parts) != 5 or parts[:2] != ["PRIVATE", "KEY"]:
            msg = "malformed signer key"
            raise NoteError(msg)
        material = _b64decode(parts[4])
        if len(material) != 33 or material[0] != SIG_ED25519:
            msg = "only Ed25519 signer keys are supported"
            raise NoteError(msg)
        signer = cls(parts[2], SIG_ED25519, SigningKey.from_seed(material[1:]))
        if signer.verifier.key_id != int(parts[3], 16):
            msg = "signer key ID does not match"
            raise NoteError(msg)
        return signer


# --- signed notes ------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class NoteSignature:
    name: str
    key_id: int
    signature: bytes
    """The bytes after the 4-byte key ID."""

    def line(self) -> str:
        blob = struct.pack(">I", self.key_id) + self.signature
        return f"{EM_DASH} {self.name} {_b64encode(blob)}\n"


def _check_text(data: str) -> None:
    if any(ord(ch) < 0x20 and ch != "\n" for ch in data):
        msg = "notes must not contain control characters other than newline"
        raise NoteError(msg)


def split_note(note: bytes) -> tuple[str, list[NoteSignature]]:
    """Parse a signed note into its text (with final newline) and signature lines."""
    if len(note) > MAX_NOTE_BYTES:
        msg = "note too large"
        raise NoteError(msg)
    try:
        data = note.decode("utf-8")
    except UnicodeDecodeError as exc:
        msg = "notes must be UTF-8"
        raise NoteError(msg) from exc
    _check_text(data)
    cut = data.rfind("\n\n")
    if cut < 0 or not data.endswith("\n"):
        msg = "malformed note: no blank line before the signatures"
        raise NoteError(msg)
    text, sig_block = data[: cut + 1], data[cut + 2 :]
    lines = sig_block.split("\n")[:-1]
    if not lines or len(lines) > MAX_SIGNATURES:
        msg = "malformed note: missing or too many signatures"
        raise NoteError(msg)
    sigs = []
    for line in lines:
        parts = line.split(" ")
        if len(parts) != 3 or parts[0] != EM_DASH:
            msg = "malformed signature line"
            raise NoteError(msg)
        check_key_name(parts[1])
        blob = _b64decode(parts[2])
        if len(blob) < 5:
            msg = "signature too short"
            raise NoteError(msg)
        sigs.append(NoteSignature(parts[1], int(struct.unpack(">I", blob[:4])[0]), blob[4:]))
    return text, sigs


def _check_note_text(text: str) -> None:
    _check_text(text)
    if not text.endswith("\n"):
        msg = "note text must end in a newline"
        raise NoteError(msg)


def sign_note(text: str, signers: Sequence[NoteSigner]) -> bytes:
    """A signed note with Ed25519 (0x01) signatures over ``text``."""
    _check_note_text(text)
    lines = []
    for s in signers:
        if s.sig_type != SIG_ED25519:
            msg = "use cosign_checkpoint for cosignatures"
            raise NoteError(msg)
        lines.append(NoteSignature(s.name, s.verifier.key_id, s.key.sign(text.encode())).line())
    if not lines:
        msg = "a note needs at least one signature"
        raise NoteError(msg)
    return (text + "\n" + "".join(lines)).encode()


def _unique(verifiers: Sequence[NoteVerifier]) -> dict[tuple[str, int], NoteVerifier]:
    known: dict[tuple[str, int], NoteVerifier] = {}
    for v in verifiers:
        k = (v.name, v.key_id)
        if k in known and known[k] != v:
            msg = f"ambiguous key {v.name}+{v.key_id:08x}"
            raise NoteError(msg)
        known[k] = v
    return known


def open_note(note: bytes, verifiers: Sequence[NoteVerifier]) -> tuple[str, list[NoteVerifier]]:
    """Verify Ed25519 note signatures: return the text and the keys that verified it."""
    text, sigs = split_note(note)
    known = _unique([v for v in verifiers if v.sig_type == SIG_ED25519])
    verified = []
    for s in sigs:
        v = known.get((s.name, s.key_id))
        if v is None:
            continue  # unknown keys are ignored (the name AND the ID must match)
        if len(s.signature) != 64:
            msg = f"malformed signature from known key {s.name}"
            raise NoteError(msg)
        try:
            ed25519_verify(v.public_key, text.encode(), s.signature)
        except CryptoError as exc:
            msg = f"signature from known key {s.name} does not verify"
            raise NoteError(msg) from exc
        verified.append(v)
    if not verified:
        msg = "note has no verifiable signatures"
        raise NoteError(msg)
    return text, verified


# --- checkpoints ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Checkpoint:
    origin: str
    tree_size: int
    root: bytes
    extensions: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not self.origin or "\n" in self.origin:
            msg = "origin must be a non-empty single line"
            raise NoteError(msg)
        if not 0 <= self.tree_size < 2**64:
            msg = "tree size out of range"
            raise NoteError(msg)
        if len(self.root) != 32:
            msg = "root hash must be 32 bytes (SHA-256)"
            raise NoteError(msg)
        if any(not e or "\n" in e for e in self.extensions):
            msg = "extension lines must be non-empty single lines"
            raise NoteError(msg)

    def body(self) -> str:
        lines = [self.origin, str(self.tree_size), _b64encode(self.root), *self.extensions]
        text = "\n".join(lines) + "\n"
        _check_note_text(text)
        return text

    @classmethod
    def parse(cls, text: str) -> Checkpoint:
        if not text.endswith("\n"):
            msg = "checkpoint must end in a newline"
            raise NoteError(msg)
        lines = text[:-1].split("\n")
        if len(lines) < 3 or any(not line for line in lines):
            msg = "checkpoint needs at least three non-empty lines"
            raise NoteError(msg)
        if not _DECIMAL.fullmatch(lines[1]):
            msg = "tree size must be decimal without leading zeroes"
            raise NoteError(msg)
        return cls(lines[0], int(lines[1]), _b64decode(lines[2]), tuple(lines[3:]))


def checkpoint_from_log(log: TransparencyLog, origin: str) -> Checkpoint:
    return Checkpoint(origin, log.size, log.root())


def checkpoint_for_tree_head(head: TreeHead, origin: str) -> Checkpoint:
    """The C2SP view of an ESP tree head: same size, same RFC 9162 root."""
    return Checkpoint(origin, head.tree_size, head.root)


def sign_checkpoint(cp: Checkpoint, log: NoteSigner) -> bytes:
    """The log signs its checkpoint; its key name must equal the origin line (ESP profile)."""
    if log.name != cp.origin:
        msg = "the log key name must match the checkpoint origin"
        raise NoteError(msg)
    return sign_note(cp.body(), [log])


# --- witness cosignatures (c2sp.org/tlog-cosignature, Ed25519 v1) --------------------------------


def cosignature_message(timestamp: int, body: str) -> bytes:
    if not 0 <= timestamp <= MAX_TIMESTAMP:
        msg = "cosignature timestamp out of range"
        raise NoteError(msg)
    return b"cosignature/v1\ntime " + str(timestamp).encode() + b"\n" + body.encode()


def cosign_checkpoint(note: bytes, witness: NoteSigner, timestamp: int) -> bytes:
    """Append a witness's cosignature/v1 line (the witness has checked consistency)."""
    if witness.sig_type != SIG_COSIGNATURE_V1:
        msg = "witness keys use signature type 0x04"
        raise NoteError(msg)
    text, sigs = split_note(note)
    Checkpoint.parse(text)
    sig = struct.pack(">Q", timestamp) + witness.key.sign(cosignature_message(timestamp, text))
    line = NoteSignature(witness.name, witness.verifier.key_id, sig)
    return (text + "\n" + "".join(s.line() for s in sigs) + line.line()).encode()


def cosignature_timestamp(signature: bytes) -> int:
    """Timestamp of a cosignature/v1 signature blob (after the key ID): 8 + 64 bytes."""
    if len(signature) != 72:
        msg = "not an Ed25519 cosignature/v1 signature"
        raise NoteError(msg)
    ts = int(struct.unpack(">Q", signature[:8])[0])
    if ts > MAX_TIMESTAMP:
        msg = "cosignature timestamp out of range"
        raise NoteError(msg)
    return ts


@dataclass(frozen=True, slots=True)
class VerifiedCheckpoint:
    checkpoint: Checkpoint
    witnesses: tuple[tuple[str, int], ...]
    """``(witness name, cosignature timestamp)`` of every verified independent cosigner."""


def verify_checkpoint(
    note: bytes,
    log: NoteVerifier,
    witnesses: Sequence[NoteVerifier],
    *,
    quorum: int,
    now_s: int | None = None,
    max_future_s: int = 300,
) -> VerifiedCheckpoint:
    """Log signature plus at least ``quorum`` distinct, independent, known witnesses."""
    if quorum < 0:
        msg = "quorum must be non-negative"
        raise NoteError(msg)
    text, sigs = split_note(note)
    cp = Checkpoint.parse(text)
    if log.name != cp.origin:
        msg = "the log key name must match the checkpoint origin"
        raise NoteError(msg)
    open_note(note, [log])  # the log's own Ed25519 signature must verify
    known = _unique([w for w in witnesses if w.sig_type == SIG_COSIGNATURE_V1])
    good: dict[bytes, tuple[str, int]] = {}
    for s in sigs:
        w = known.get((s.name, s.key_id))
        if w is None:
            continue  # unknown cosigner: ignored
        ts = cosignature_timestamp(s.signature)
        try:
            ed25519_verify(w.public_key, cosignature_message(ts, text), s.signature[8:])
        except CryptoError as exc:
            msg = f"cosignature from known witness {w.name} does not verify"
            raise NoteError(msg) from exc
        if now_s is not None and ts > now_s + max_future_s:
            msg = f"cosignature from {w.name} is dated in the future"
            raise NoteError(msg)
        if w.public_key == log.public_key:
            continue  # the log key never counts as its own witness
        good[w.public_key] = (w.name, ts)
    if len(good) < quorum:
        msg = f"checkpoint has {len(good)} valid independent cosignatures, need {quorum}"
        raise NoteError(msg)
    return VerifiedCheckpoint(cp, tuple(sorted(good.values())))
