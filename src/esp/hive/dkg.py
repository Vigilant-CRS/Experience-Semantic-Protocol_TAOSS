# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Distributed key generation for FROST(Ed25519, SHA-512) (GAP-017; replaces the trusted dealer).

Pedersen DKG with proofs of knowledge, as in the FROST paper (Komlo and Goldberg,
SAC 2020, Figure 1, "KeyGen"). RFC 9591 leaves DKG out of scope. The output
shares are ordinary :class:`~esp.hive.frost.KeyShare` objects, so RFC 9591
signing works unchanged, and the group signature verifies as plain Ed25519.

**Round 1.** Participant ``i`` draws a random polynomial ``f_i`` of degree
``t-1``. It broadcasts the commitments ``C_ij = a_ij·G`` and a Schnorr proof
of knowledge of ``a_i0``: ``R = k·G``, ``c = H(i ‖ ctx ‖ C_i0 ‖ R)``,
``mu = k + a_i0·c``. Every receiver checks ``mu·G == R + c·C_i0``. The proof
stops rogue-key attacks.

**Round 2.** Participant ``i`` sends ``f_i(l)`` privately to each ``l``.
Receiver ``l`` checks ``f_i(l)·G == Σ_k l^k · C_ik``.

**Finish.** ``s_l = Σ_i f_i(l)``, ``PK_l = s_l·G`` and ``PK = Σ_i C_i0``.
Every participant computes the same ``PK_j`` for all ``j`` from the public
commitments.

Any failed check raises :class:`DkgComplaint`, which names the misbehaving
participant. The protocol then aborts; this reference has no robust
recovery. The private channels of round 2 are the caller's responsibility (for
example Noise sessions). The arithmetic is not constant time, as in ``frost``.
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from esp.hive.frost import (
    IDENTITY,
    FrostError,
    GroupInfo,
    KeyShare,
    L,
    Point,
    _add,
    _eq,
    _mul,
    base_mult,
    deserialize_element,
    serialize_element,
    serialize_scalar,
)

DOMAIN: Final = b"esp/v1/hive-frost-dkg"


class DkgComplaint(FrostError):  # noqa: N818 - a protocol outcome
    """A participant misbehaved; ``culprit`` identifies it."""

    def __init__(self, culprit: int, reason: str) -> None:
        super().__init__(f"participant {culprit}: {reason}")
        self.culprit = culprit


def _challenge(identifier: int, context: bytes, c0: bytes, r: bytes) -> int:
    digest = hashlib.sha512(
        DOMAIN + identifier.to_bytes(2, "big") + len(context).to_bytes(2, "big") + context + c0 + r
    ).digest()
    return int.from_bytes(digest, "little") % L


@dataclass(frozen=True, slots=True)
class Round1Broadcast:
    identifier: int
    commitments: tuple[bytes, ...]
    """``C_i0 … C_i(t-1)``, serialized edwards25519 points."""
    proof_r: bytes
    proof_mu: bytes


@dataclass(frozen=True, slots=True)
class Round1Secret:
    identifier: int
    coefficients: tuple[int, ...]

    def share_for(self, recipient: int) -> int:
        """``f_i(recipient)``: sent privately to ``recipient`` in round 2."""
        return sum(c * pow(recipient, k, L) for k, c in enumerate(self.coefficients)) % L


def round1(
    identifier: int, threshold: int, max_participants: int, context: bytes
) -> tuple[Round1Secret, Round1Broadcast]:
    if not 2 <= threshold <= max_participants or not 1 <= identifier <= max_participants:
        msg = "require 2 <= threshold <= n and 1 <= identifier <= n"
        raise FrostError(msg)
    coeffs = tuple(secrets.randbelow(L - 1) + 1 for _ in range(threshold))
    commitments = tuple(serialize_element(base_mult(a)) for a in coeffs)
    k = secrets.randbelow(L - 1) + 1
    r = serialize_element(base_mult(k))
    c = _challenge(identifier, context, commitments[0], r)
    mu = (k + coeffs[0] * c) % L
    return Round1Secret(identifier, coeffs), Round1Broadcast(
        identifier, commitments, r, serialize_scalar(mu)
    )


def verify_round1(b: Round1Broadcast, threshold: int, context: bytes) -> None:
    """Check the proof of knowledge and the commitment count; raise a complaint otherwise."""
    if len(b.commitments) != threshold:
        raise DkgComplaint(b.identifier, "wrong number of commitments")
    try:
        c0 = deserialize_element(b.commitments[0])
        r = deserialize_element(b.proof_r)
        for extra in b.commitments[1:]:
            deserialize_element(extra)
    except FrostError as exc:
        raise DkgComplaint(b.identifier, "invalid commitment encoding") from exc
    mu = int.from_bytes(b.proof_mu, "little")
    if mu >= L:
        raise DkgComplaint(b.identifier, "proof scalar out of range")
    c = _challenge(b.identifier, context, b.commitments[0], b.proof_r)
    if not _eq(base_mult(mu), _add(r, _mul(c, c0))):
        raise DkgComplaint(b.identifier, "proof of knowledge does not verify")


def _eval_commitments(commitments: Sequence[bytes], x: int) -> Point:
    acc = IDENTITY
    for k, c in enumerate(commitments):
        acc = _add(acc, _mul(pow(x, k, L), deserialize_element(c)))
    return acc


def verify_share(sender: Round1Broadcast, recipient: int, share: int) -> None:
    """Receiver side of round 2: ``share·G == Σ_k recipient^k · C_sender,k``."""
    if not 0 < share < L or not _eq(
        base_mult(share), _eval_commitments(sender.commitments, recipient)
    ):
        raise DkgComplaint(sender.identifier, f"share for participant {recipient} is invalid")


def finish(
    identifier: int,
    threshold: int,
    broadcasts: Sequence[Round1Broadcast],
    received_shares: Mapping[int, int],
    context: bytes,
) -> tuple[GroupInfo, KeyShare]:
    """Verify everything this participant received and derive its key share and the group info."""
    ids = sorted(b.identifier for b in broadcasts)
    if len(set(ids)) != len(ids) or ids != list(range(1, len(ids) + 1)):
        msg = "participants must be numbered 1..n without duplicates"
        raise FrostError(msg)
    if set(received_shares) != set(ids):
        msg = "a share from every participant (including oneself) is required"
        raise FrostError(msg)
    for b in broadcasts:
        verify_round1(b, threshold, context)
        verify_share(b, identifier, received_shares[b.identifier])
    secret = sum(received_shares.values()) % L
    group = IDENTITY
    for b in broadcasts:
        group = _add(group, deserialize_element(b.commitments[0]))
    publics = {}
    for j in ids:
        pk_j = IDENTITY
        for b in broadcasts:
            pk_j = _add(pk_j, _eval_commitments(b.commitments, j))
        publics[j] = serialize_element(pk_j)
    group_public = serialize_element(group)
    own = serialize_element(base_mult(secret))
    if own != publics[identifier]:  # pragma: no cover - implied by the share checks
        msg = "derived public share does not match the commitments"
        raise FrostError(msg)
    info = GroupInfo(group_public, publics, threshold)
    return info, KeyShare(identifier, secret, own, group_public)


def run_local(
    max_participants: int, threshold: int, context: bytes
) -> tuple[GroupInfo, list[KeyShare]]:
    """All participants in one process (tests and simulations); every check still runs."""
    rounds = [
        round1(i, threshold, max_participants, context) for i in range(1, max_participants + 1)
    ]
    broadcasts = [b for _, b in rounds]
    infos, shares = [], []
    for i in range(1, max_participants + 1):
        received = {s.identifier: s.share_for(i) for s, _ in rounds}
        info, share = finish(i, threshold, broadcasts, received, context)
        infos.append(info)
        shares.append(share)
    if any(inf != infos[0] for inf in infos):  # pragma: no cover - deterministic from broadcasts
        msg = "participants derived different group information"
        raise FrostError(msg)
    return infos[0], shares
