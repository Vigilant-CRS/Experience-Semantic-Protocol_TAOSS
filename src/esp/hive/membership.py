# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Hive membership: IDENTIFIED member references and the ANONYMOUS credential interface.

**IDENTIFIED** (V13): the episode verifier knows the authenticated member
record, which is the master key ``pk_M`` of the base Capability. A member uses
a per-episode key, bound by ``Ed25519(sk_M, "esp/v1/hive-member-key" ||
episode_id || member_pk)``, so contributions do not need the master key online:

- ``member_ref = BLAKE2b-256("esp/v1/hive-member" || episode_id || member_pk)``;
- ``proof = member_pk || Ed25519(member_sk, domain || signed fields)``.

**ANONYMOUS**: V13 names Semaphore V4 as the reference construction for
membership proofs with scope-bound nullifiers, and forbids replacing it with
an ad-hoc hash. This reference does **not** implement Semaphore. It defines
the :class:`CredentialSuite` interface that such a suite plugs into, and
ships :class:`TransparentTestSuite` (``esp-hive-transparent-test-v0``). That
suite proves Merkle membership and one-per-episode uniqueness, but it
**reveals the credential key**, so it provides **no anonymity**
(``provides_anonymity = False``). An episode refuses to run ANONYMOUS mode on
it unless explicitly told it is a test, and it then reports the missing
anonymity instead of claiming it.
"""

from __future__ import annotations

import hashlib
import struct
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Final, Protocol

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv
from esp.consent.capability import SenderCapability
from esp.crypto.primitives import SigningKey, ed25519_verify
from esp.hive.tlv import (
    HiveContribution,
    HiveError,
    HiveExit,
    HiveGrant,
    MembershipMode,
    verify_grant,
)
from esp.keys.transparency import inclusion_path, leaf_hash, merkle_root, verify_inclusion

CONTRIBUTION_AUTH: Final = b"esp/v1/hive-contribution-auth"
EXIT_AUTH: Final = b"esp/v1/hive-exit-auth"
MEMBER_KEY_BINDING: Final = b"esp/v1/hive-member-key"
ENROLL_BINDING: Final = b"esp/v1/hive-enroll"

HiveObject = HiveContribution | HiveExit


def _b2(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def _domain(obj: HiveObject) -> bytes:
    return CONTRIBUTION_AUTH if isinstance(obj, HiveContribution) else EXIT_AUTH


# --- IDENTIFIED ----------------------------------------------------------------------------------


def identified_ref(episode_id: uuid.UUID, member_pk: bytes) -> bytes:
    return _b2(b"esp/v1/hive-member" + episode_id.bytes + member_pk)


def member_key_binding(master: SigningKey, episode_id: uuid.UUID, member_pk: bytes) -> bytes:
    return master.sign(MEMBER_KEY_BINDING + episode_id.bytes + member_pk)


def identified_proof(member: SigningKey, obj: HiveObject) -> bytes:
    return member.public_bytes + member.sign(_domain(obj) + obj.signed_fields())


def verify_identified(obj: HiveObject, expected_member_pk: bytes) -> None:
    """Check an IDENTIFIED proof against the member key recorded at join."""
    if len(obj.proof) != 96 or obj.proof[:32] != expected_member_pk:
        msg = "IDENTIFIED proof must carry the joined member key"
        raise HiveError(msg)
    if identified_ref(obj.episode_id, expected_member_pk) != obj.member_ref:
        msg = "member_ref does not belong to this member key"
        raise HiveError(msg)
    ed25519_verify(expected_member_pk, _domain(obj) + obj.signed_fields(), obj.proof[32:])


# --- ANONYMOUS credential interface --------------------------------------------------------------


class CredentialSuite(Protocol):
    """Registry-pinned anonymous-credential/ZK suite (V13: Semaphore V4 is the reference)."""

    suite_id: str
    provides_anonymity: bool

    def verify(self, obj: HiveObject, root: bytes) -> None:
        """Raise unless ``obj.proof`` proves membership under ``root`` and a correct nullifier."""
        ...


def _cred_leaf(cred_pk: bytes) -> bytes:
    return leaf_hash(b"esp/v1/hive-credential" + cred_pk)


def transparent_nullifier(episode_id: uuid.UUID, cred_pk: bytes) -> bytes:
    """Test-suite nullifier: checkable by anyone, hence **linkable**, hence not anonymous."""
    return _b2(b"esp/v1/hive-nullifier" + episode_id.bytes + cred_pk)


@dataclass(frozen=True, slots=True)
class TransparentTestSuite:
    """``esp-hive-transparent-test-v0``: Merkle membership + nullifier, **no anonymity**.

    ``proof = cred_pk[32] || index u32 || tree_size u32 || n u8 || path[32·n] || sig[64]``,
    with ``sig = Ed25519(cred_sk, domain || signed fields)``.
    """

    suite_id: str = "esp-hive-transparent-test-v0"
    provides_anonymity: bool = False

    @staticmethod
    def prove(cred: SigningKey, obj: HiveObject, index: int, leaves: Sequence[bytes]) -> bytes:
        path = inclusion_path(index, list(leaves))
        head = cred.public_bytes + struct.pack(">IIB", index, len(leaves), len(path))
        return head + b"".join(path) + cred.sign(_domain(obj) + obj.signed_fields())

    def verify(self, obj: HiveObject, root: bytes) -> None:
        p = obj.proof
        if len(p) < 41:
            msg = "credential proof truncated"
            raise WireError(msg)
        cred_pk = p[:32]
        index, size, n = struct.unpack_from(">IIB", p, 32)
        if len(p) != 41 + 32 * n + 64:
            msg = "credential proof length mismatch"
            raise WireError(msg)
        path = [p[41 + 32 * k : 73 + 32 * k] for k in range(n)]
        if not verify_inclusion(_cred_leaf(cred_pk), index, size, path, root):
            msg = "credential is not enrolled under the membership root"
            raise HiveError(msg)
        if transparent_nullifier(obj.episode_id, cred_pk) != obj.member_ref:
            msg = "nullifier is not derived from the enrolled credential"
            raise HiveError(msg)
        ed25519_verify(cred_pk, _domain(obj) + obj.signed_fields(), p[-64:])


@dataclass
class Registrar:
    """ANONYMOUS enrollment (V13 Join): verifies Capability + signed Grant, never forwards them.

    Phase 1 registers one credential per master key (``register``). ``close``
    fixes the registration root, which members put into ``membership_root`` of
    their grants. ``authorize`` verifies each grant against the base capability
    and the episode policy. Only authorized credentials enter the
    ``authorized_root`` that the episode verifier checks against. The registrar
    learns eligibility; issuer-to-episode unlinkability would need blind
    issuance (V13), which this reference does not provide.
    """

    episode_id: uuid.UUID
    policy: Callable[[HiveGrant], None]
    """Raises if a grant does not satisfy the episode policy."""
    _creds: dict[bytes, bytes] = field(default_factory=dict)
    _order: list[bytes] = field(default_factory=list)
    _authorized: set[bytes] = field(default_factory=set)
    _root: bytes | None = None

    def register(self, base_tlv: Tlv, cred_pk: bytes, binding_sig: bytes) -> None:
        if self._root is not None:
            msg = "registration closed"
            raise HiveError(msg)
        base = SenderCapability.verify(base_tlv)
        ed25519_verify(
            base.issuer_pk, ENROLL_BINDING + self.episode_id.bytes + cred_pk, binding_sig
        )
        if base.issuer_pk in self._creds:
            msg = "one credential per master key (duplicate enrollment)"
            raise HiveError(msg)
        self._creds[base.issuer_pk] = cred_pk
        self._order.append(cred_pk)

    def close(self) -> bytes:
        if not self._order:
            msg = "no credentials registered"
            raise HiveError(msg)
        self._root = merkle_root([_cred_leaf(c) for c in self._order])
        return self._root

    def authorize(self, base_tlv: Tlv, grant_tlv: Tlv, *, now_ns: int) -> None:
        if self._root is None:
            msg = "close registration first"
            raise HiveError(msg)
        base = SenderCapability.verify(base_tlv)
        grant = verify_grant(grant_tlv, base, now_ns=now_ns)
        if grant.membership_mode is not MembershipMode.ANONYMOUS:
            msg = "registrar enrolls ANONYMOUS grants only"
            raise HiveError(msg)
        if grant.episode_id != self.episode_id or grant.membership_root != self._root:
            msg = "grant is for another episode or membership root"
            raise HiveError(msg)
        self.policy(grant)
        cred = self._creds.get(base.issuer_pk)
        if cred is None:
            msg = "no credential registered for this master key"
            raise HiveError(msg)
        self._authorized.add(cred)

    @property
    def authorized_leaves(self) -> list[bytes]:
        return [_cred_leaf(c) for c in self._order if c in self._authorized]

    def authorized_root(self) -> bytes:
        leaves = self.authorized_leaves
        if not leaves:
            msg = "no authorized credentials"
            raise HiveError(msg)
        return merkle_root(leaves)

    def index_of(self, cred_pk: bytes) -> int:
        return self.authorized_leaves.index(_cred_leaf(cred_pk))


def enroll_binding(master: SigningKey, episode_id: uuid.UUID, cred_pk: bytes) -> bytes:
    return master.sign(ENROLL_BINDING + episode_id.bytes + cred_pk)


def member_ref_root(refs: Sequence[bytes]) -> bytes:
    """Commitment to the accepted member_ref set (sorted, RFC 9162 Merkle root)."""
    if len(set(refs)) != len(refs):
        msg = "duplicate member references"
        raise HiveError(msg)
    return merkle_root([leaf_hash(r) for r in sorted(refs)])
