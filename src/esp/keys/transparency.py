# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Append-only transparency log with RFC 9162 Merkle hashing (ADR-0023 reference).

V13 section 9.6 requires rotation receipts (and, for multi-recipient
profiles, DP ledger checkpoints) in a Certificate-Transparency-style log.
This reference log uses exactly the RFC 9162 section 2.1 tree:

- leaf hash ``SHA-256(0x00 || entry)``, node hash ``SHA-256(0x01 || left || right)``;
- inclusion proofs (section 2.1.3) and consistency proofs (section 2.1.4) with
  the RFC verification algorithms;
- signed tree heads by the log key plus independent witness cosignatures.

A log operated by the sender is *not* sufficient on its own (V13): witnesses
must be independent. This module provides the mechanism, not the operation.
"""

from __future__ import annotations

import hashlib
import struct
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Final

from esp.crypto.primitives import CryptoError, SigningKey, ed25519_verify

STH_DOMAIN: Final = b"esp/v1/tree-head"


def leaf_hash(entry: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + entry).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def _largest_power_of_two_below(n: int) -> int:
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


def merkle_root(leaves: Sequence[bytes]) -> bytes:
    """MTH over leaf hashes (RFC 9162 section 2.1.1)."""
    n = len(leaves)
    if n == 0:
        return hashlib.sha256(b"").digest()
    if n == 1:
        return leaves[0]
    k = _largest_power_of_two_below(n)
    return node_hash(merkle_root(leaves[:k]), merkle_root(leaves[k:]))


def inclusion_path(index: int, leaves: Sequence[bytes]) -> list[bytes]:
    """PATH(m, D[n]) (RFC 9162 section 2.1.3.1)."""
    n = len(leaves)
    if n <= 1:
        return []
    k = _largest_power_of_two_below(n)
    if index < k:
        return [*inclusion_path(index, leaves[:k]), merkle_root(leaves[k:])]
    return [*inclusion_path(index - k, leaves[k:]), merkle_root(leaves[:k])]


def verify_inclusion(
    leaf: bytes, index: int, tree_size: int, path: Sequence[bytes], root: bytes
) -> bool:
    """RFC 9162 section 2.1.3.2 verification."""
    if index >= tree_size:
        return False
    fn, sn, r = index, tree_size - 1, leaf
    for p in path:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def _subproof(m: int, leaves: Sequence[bytes], complete: bool) -> list[bytes]:
    n = len(leaves)
    if m == n:
        return [] if complete else [merkle_root(leaves)]
    k = _largest_power_of_two_below(n)
    if m <= k:
        return [*_subproof(m, leaves[:k], complete), merkle_root(leaves[k:])]
    return [*_subproof(m - k, leaves[k:], False), merkle_root(leaves[:k])]


def consistency_proof(old_size: int, leaves: Sequence[bytes]) -> list[bytes]:
    """PROOF(m, D[n]) (RFC 9162 section 2.1.4.1)."""
    if not 0 < old_size <= len(leaves):
        msg = "consistency proof needs 0 < old_size <= new_size"
        raise ValueError(msg)
    return _subproof(old_size, leaves, True)


def verify_consistency(
    old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: Sequence[bytes]
) -> bool:
    """RFC 9162 section 2.1.4.2 verification."""
    if old_size == new_size:
        return old_root == new_root and not proof
    if not 0 < old_size < new_size:
        return False
    path = list(proof)
    if old_size & (old_size - 1) == 0:  # power of two: prepend first_hash
        path = [old_root, *path]
    if not path:
        return False
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while fn and not fn & 1:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0


@dataclass(frozen=True, slots=True)
class TreeHead:
    tree_size: int
    root: bytes
    timestamp_ns: int
    log_pk: bytes
    signature: bytes
    cosignatures: tuple[tuple[bytes, bytes], ...] = ()
    """``(witness_pk, signature)`` pairs over the same message."""

    def message(self) -> bytes:
        return STH_DOMAIN + struct.pack(">QQ", self.tree_size, self.timestamp_ns) + self.root

    def verify(self, *, witnesses: Sequence[bytes], quorum: int) -> None:
        """Log signature plus at least ``quorum`` distinct known witnesses."""
        ed25519_verify(self.log_pk, self.message(), self.signature)
        ok: set[bytes] = set()
        for pk, sig in self.cosignatures:
            if pk in witnesses and pk != self.log_pk:
                try:
                    ed25519_verify(pk, self.message(), sig)
                except CryptoError:
                    continue
                ok.add(pk)
        if len(ok) < quorum:
            msg = f"tree head has {len(ok)} valid witness cosignatures, need {quorum}"
            raise CryptoError(msg)


@dataclass(slots=True)
class TransparencyLog:
    log_key: SigningKey
    _leaves: list[bytes] = field(default_factory=list)
    _entries: list[bytes] = field(default_factory=list)

    def append(self, entry: bytes) -> int:
        self._entries.append(entry)
        self._leaves.append(leaf_hash(entry))
        return len(self._leaves) - 1

    @property
    def size(self) -> int:
        return len(self._leaves)

    def entry(self, index: int) -> bytes:
        return self._entries[index]

    def root(self, size: int | None = None) -> bytes:
        n = self.size if size is None else size
        return merkle_root(self._leaves[:n])

    def tree_head(self, timestamp_ns: int) -> TreeHead:
        root = self.root()
        unsigned = TreeHead(self.size, root, timestamp_ns, self.log_key.public_bytes, b"")
        return TreeHead(
            self.size,
            root,
            timestamp_ns,
            self.log_key.public_bytes,
            self.log_key.sign(unsigned.message()),
        )

    def inclusion(self, index: int, size: int | None = None) -> list[bytes]:
        n = self.size if size is None else size
        return inclusion_path(index, self._leaves[:n])

    def consistency(self, old_size: int, new_size: int | None = None) -> list[bytes]:
        n = self.size if new_size is None else new_size
        return consistency_proof(old_size, self._leaves[:n])


def cosign(head: TreeHead, witness: SigningKey) -> TreeHead:
    return TreeHead(
        head.tree_size,
        head.root,
        head.timestamp_ns,
        head.log_pk,
        head.signature,
        (*head.cosignatures, (witness.public_bytes, witness.sign(head.message()))),
    )
