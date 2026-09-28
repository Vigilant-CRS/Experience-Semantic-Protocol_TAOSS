# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Reference evidence verifiers for rotation bindings (V13 section 9.6).

The evidence must authenticate the rotation core ``(mode, old_pk, new_pk,
effective_ns)`` — evidence for a different tuple is invalid even if its bytes
hash to the advertised digest.

- ``PRE_REGISTERED``: the successor was registered in a transparency log
  *before* the rotation. Evidence = ``index u64 || tree_size u64 ||
  n u8 || path[n] (32 bytes each)``; it is checked against a caller-supplied,
  witness-verified tree head whose timestamp precedes ``effective_ns``.
- ``WITNESS_QUORUM``: ``n u8 || n * (witness_pk[32] || sig[64])`` where each
  signature covers the rotation core; at least ``quorum`` distinct trusted
  witnesses must verify.
- ``HW_ATTESTED``: interface only; rejected unless a platform verifier is given.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence

from esp.crypto.primitives import CryptoError, SigningKey, blake2b, ed25519_verify
from esp.keys.lineage import (
    BindingMode,
    EvidenceVerifier,
    rotation_core,
    successor_pre_registration,
)
from esp.keys.transparency import TreeHead, leaf_hash, verify_inclusion


def encode_inclusion_evidence(index: int, tree_size: int, path: Sequence[bytes]) -> bytes:
    if len(path) > 255:
        msg = "inclusion path too long"
        raise ValueError(msg)
    return struct.pack(">QQB", index, tree_size, len(path)) + b"".join(path)


def encode_witness_evidence(signatures: Sequence[tuple[bytes, bytes]]) -> bytes:
    return bytes([len(signatures)]) + b"".join(pk + sig for pk, sig in signatures)


def witness_sign(
    witness: SigningKey, *, mode: BindingMode, old_pk: bytes, new_pk: bytes, effective_ns: int
) -> tuple[bytes, bytes]:
    """A witness signs the rotation core *without* evidence digest (it is the evidence)."""
    core = rotation_core(
        version=1,
        mode=mode,
        old_pk=old_pk,
        new_pk=new_pk,
        effective_ns=effective_ns,
        digest=bytes(32),
    )
    return witness.public_bytes, witness.sign(core)


def make_verifier(
    *,
    trusted_head: TreeHead | None = None,
    witnesses: Sequence[bytes] = (),
    quorum: int = 0,
) -> EvidenceVerifier:
    """Build an evidence verifier for the lineage from trusted inputs."""

    def verify(
        mode: BindingMode, old_pk: bytes, new_pk: bytes, effective_ns: int, evidence: bytes
    ) -> bool:
        if mode is BindingMode.PRE_REGISTERED:
            return _pre_registered(trusted_head, old_pk, new_pk, effective_ns, evidence)
        if mode is BindingMode.WITNESS_QUORUM:
            return _witness_quorum(
                witnesses, quorum, old_pk, new_pk, effective_ns, evidence=evidence
            )
        return False  # HW_ATTESTED needs a platform-specific verifier

    return verify


def _pre_registered(
    head: TreeHead | None, old_pk: bytes, new_pk: bytes, effective_ns: int, evidence: bytes
) -> bool:
    if head is None or len(evidence) < 17:
        return False
    index, size, n = struct.unpack_from(">QQB", evidence, 0)
    if len(evidence) != 17 + 32 * n or size != head.tree_size:
        return False
    if head.timestamp_ns >= effective_ns:
        return False  # registration must precede the rotation
    path = [evidence[17 + 32 * i : 49 + 32 * i] for i in range(n)]
    entry = leaf_hash(successor_pre_registration(old_pk, new_pk))
    return verify_inclusion(entry, index, size, path, head.root)


def _witness_quorum(
    witnesses: Sequence[bytes],
    quorum: int,
    old_pk: bytes,
    new_pk: bytes,
    effective_ns: int,
    *,
    evidence: bytes,
) -> bool:
    if quorum < 1 or not evidence:
        return False
    n = evidence[0]
    if len(evidence) != 1 + 96 * n:
        return False
    core = rotation_core(
        version=1,
        mode=BindingMode.WITNESS_QUORUM,
        old_pk=old_pk,
        new_pk=new_pk,
        effective_ns=effective_ns,
        digest=bytes(32),
    )
    good: set[bytes] = set()
    for i in range(n):
        pk = evidence[1 + 96 * i : 33 + 96 * i]
        sig = evidence[33 + 96 * i : 97 + 96 * i]
        if pk not in witnesses or pk in (old_pk, new_pk):
            continue
        try:
            ed25519_verify(pk, core, sig)
        except CryptoError:
            continue
        good.add(pk)
    return len(good) >= quorum


def evidence_digest(evidence: bytes) -> bytes:
    return blake2b(evidence)
