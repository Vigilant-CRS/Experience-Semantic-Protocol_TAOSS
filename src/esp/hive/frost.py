# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""FROST(Ed25519, SHA-512) two-round threshold signing (RFC 9591; WP-070).

The quorum signature of a ``COLLECTIVE_INTENT`` (0x73) is a FROST signature
that verifies as a **plain Ed25519 signature** under the group public key
(RFC 9591 section 6.1). This is a pure-Python reference over edwards25519
(RFC 8032 arithmetic), checked byte-exactly against the RFC 9591 Appendix
E.1 test vectors.

Limitations (documented in ADR-0021):

- The arithmetic is **not constant time**. It is a reference and conformance
  implementation, not a hardened signer.
- Key setup: the RFC 9591 Appendix C trusted-dealer scheme (used for the RFC
  test vectors) or the Pedersen DKG with proofs of knowledge in
  :mod:`esp.hive.dkg` (no trusted dealer; RFC 9591 leaves DKG out of scope).
- FROST is not robust: one misbehaving signer aborts the signing session, and
  :func:`verify_signature_share` identifies it (RFC 9591 section 5.4).
"""

from __future__ import annotations

import hashlib
import secrets
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Final

from esp.crypto.primitives import CryptoError, ed25519_verify

CONTEXT: Final = b"FROST-ED25519-SHA512-v1"
P: Final = 2**255 - 19
L: Final = 2**252 + 27742317777372353535851937790883648493
_D: Final = -121665 * pow(121666, P - 2, P) % P
_SQRT_M1: Final = pow(2, (P - 1) // 4, P)


class FrostError(ValueError):
    pass


# --- edwards25519 (extended homogeneous coordinates, RFC 8032 section 5.1.4) ---------------------

Point = tuple[int, int, int, int]
IDENTITY: Final[Point] = (0, 1, 1, 0)


def _add(p: Point, q: Point) -> Point:
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * _D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s: int, p: Point) -> Point:
    q = IDENTITY
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _eq(p: Point, q: Point) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % P == 0 and (p[1] * q[2] - q[1] * p[2]) % P == 0


def _recover_x(y: int, sign: int) -> int | None:
    if y >= P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, P - 2, P) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * _SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if (x & 1) != sign:
        x = P - x
    return x


def _base() -> Point:
    y = 4 * pow(5, P - 2, P) % P
    x = _recover_x(y, 0)
    if x is None:  # pragma: no cover - constant
        raise FrostError("bad base point")
    return (x, y, 1, x * y % P)


BASE: Final[Point] = _base()


def serialize_element(p: Point) -> bytes:
    """RFC 8032 point encoding; the identity is rejected (RFC 9591 section 6.1)."""
    if _eq(p, IDENTITY):
        msg = "cannot serialize the identity element"
        raise FrostError(msg)
    zinv = pow(p[2], P - 2, P)
    x, y = p[0] * zinv % P, p[1] * zinv % P
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def deserialize_element(buf: bytes) -> Point:
    """Decode; reject non-canonical encodings, the identity and points outside the subgroup."""
    if len(buf) != 32:
        msg = "element must be 32 bytes"
        raise FrostError(msg)
    y = int.from_bytes(buf, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    if x is None:
        msg = "invalid point encoding"
        raise FrostError(msg)
    p = (x, y, 1, x * y % P)
    if _eq(p, IDENTITY) or not _eq(_mul(L, p), IDENTITY):
        msg = "identity or point outside the prime-order subgroup"
        raise FrostError(msg)
    return p


def serialize_scalar(s: int) -> bytes:
    return int.to_bytes(s % L, 32, "little")


def deserialize_scalar(buf: bytes) -> int:
    if len(buf) != 32:
        msg = "scalar must be 32 bytes"
        raise FrostError(msg)
    s = int.from_bytes(buf, "little")
    if s >= L:
        msg = "scalar out of range"
        raise FrostError(msg)
    return s


def base_mult(s: int) -> Point:
    return _mul(s % L, BASE)


# --- hash functions H1-H5 (RFC 9591 section 6.1) -----------------------------------------------


def _h(data: bytes) -> bytes:
    return hashlib.sha512(data).digest()


def _to_scalar(digest: bytes) -> int:
    return int.from_bytes(digest, "little") % L


def h1(m: bytes) -> int:
    return _to_scalar(_h(CONTEXT + b"rho" + m))


def h2(m: bytes) -> int:
    return _to_scalar(_h(m))


def h3(m: bytes) -> int:
    return _to_scalar(_h(CONTEXT + b"nonce" + m))


def h4(m: bytes) -> bytes:
    return _h(CONTEXT + b"msg" + m)


def h5(m: bytes) -> bytes:
    return _h(CONTEXT + b"com" + m)


# --- key material --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class KeyShare:
    identifier: int
    secret: int
    public: bytes
    """PK_i."""
    group_public: bytes
    """PK."""


@dataclass(frozen=True, slots=True)
class GroupInfo:
    group_public: bytes
    participant_publics: Mapping[int, bytes]
    min_participants: int


def trusted_dealer_keygen(
    max_participants: int,
    min_participants: int,
    secret: int | None = None,
    coefficients: Sequence[int] | None = None,
) -> tuple[GroupInfo, list[KeyShare]]:
    """RFC 9591 Appendix C.1. Fixed ``secret``/``coefficients`` exist only for test vectors."""
    if not 2 <= min_participants <= max_participants < L:
        msg = "require 2 <= MIN_PARTICIPANTS <= MAX_PARTICIPANTS"
        raise FrostError(msg)
    s = secrets.randbelow(L - 1) + 1 if secret is None else secret % L
    coeffs = (
        [secrets.randbelow(L) for _ in range(min_participants - 1)]
        if coefficients is None
        else [c % L for c in coefficients]
    )
    if len(coeffs) != min_participants - 1:
        msg = "need MIN_PARTICIPANTS - 1 coefficients"
        raise FrostError(msg)
    poly = [s, *coeffs]
    pk = serialize_element(base_mult(s))
    shares = []
    for i in range(1, max_participants + 1):
        sk_i = sum(c * pow(i, k, L) for k, c in enumerate(poly)) % L
        shares.append(KeyShare(i, sk_i, serialize_element(base_mult(sk_i)), pk))
    info = GroupInfo(pk, {sh.identifier: sh.public for sh in shares}, min_participants)
    return info, shares


# --- round one -----------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Commitment:
    identifier: int
    hiding: bytes
    binding: bytes


@dataclass(slots=True)
class Nonces:
    hiding: int
    binding: int
    used: bool = False


def nonce_generate(secret: int, random_bytes: bytes | None = None) -> int:
    rb = secrets.token_bytes(32) if random_bytes is None else random_bytes
    if len(rb) != 32:
        msg = "nonce randomness must be 32 bytes"
        raise FrostError(msg)
    return h3(rb + serialize_scalar(secret))


def commit(
    share: KeyShare, randomness: tuple[bytes, bytes] | None = None
) -> tuple[Nonces, Commitment]:
    """Round one. ``randomness`` is fixed only for the RFC test vectors."""
    rh, rb = randomness if randomness is not None else (None, None)
    hiding, binding = nonce_generate(share.secret, rh), nonce_generate(share.secret, rb)
    comm = Commitment(
        share.identifier,
        serialize_element(base_mult(hiding)),
        serialize_element(base_mult(binding)),
    )
    return Nonces(hiding, binding), comm


# --- helpers (RFC 9591 section 4) ----------------------------------------------------------------


def _checked(commitments: Sequence[Commitment]) -> list[Commitment]:
    ids = [c.identifier for c in commitments]
    if len(set(ids)) != len(ids) or any(not 0 < i < L for i in ids):
        msg = "commitment identifiers must be distinct non-zero scalars"
        raise FrostError(msg)
    if ids != sorted(ids):
        msg = "commitment list must be sorted by identifier"
        raise FrostError(msg)
    return list(commitments)


def derive_interpolating_value(ids: Sequence[int], x_i: int) -> int:
    if x_i not in ids or len(set(ids)) != len(ids):
        msg = "invalid parameters"
        raise FrostError(msg)
    num = den = 1
    for x_j in ids:
        if x_j == x_i:
            continue
        num = num * x_j % L
        den = den * (x_j - x_i) % L
    return num * pow(den, L - 2, L) % L


def encode_group_commitment_list(commitments: Sequence[Commitment]) -> bytes:
    return b"".join(serialize_scalar(c.identifier) + c.hiding + c.binding for c in commitments)


def binding_factor_input(
    group_public: bytes, commitments: Sequence[Commitment], msg: bytes, identifier: int
) -> bytes:
    prefix = group_public + h4(msg) + h5(encode_group_commitment_list(commitments))
    return prefix + serialize_scalar(identifier)


def compute_binding_factors(
    group_public: bytes, commitments: Sequence[Commitment], msg: bytes
) -> dict[int, int]:
    return {
        c.identifier: h1(binding_factor_input(group_public, commitments, msg, c.identifier))
        for c in commitments
    }


def compute_group_commitment(commitments: Sequence[Commitment], rho: Mapping[int, int]) -> Point:
    r = IDENTITY
    for c in commitments:
        hid, bnd = deserialize_element(c.hiding), deserialize_element(c.binding)
        r = _add(_add(r, hid), _mul(rho[c.identifier], bnd))
    return r


def compute_challenge(group_commitment: Point, group_public: bytes, msg: bytes) -> int:
    return h2(serialize_element(group_commitment) + group_public + msg)


# --- round two and aggregation -------------------------------------------------------------------


def sign(share: KeyShare, nonces: Nonces, msg: bytes, commitments: Sequence[Commitment]) -> bytes:
    """Round two: the signature share ``z_i``. Nonces are single-use (RFC 9591 section 5.2)."""
    if nonces.used:
        err = "nonces must not be reused"
        raise FrostError(err)
    commitments = _checked(commitments)
    mine = [c for c in commitments if c.identifier == share.identifier]
    own = (
        serialize_element(base_mult(nonces.hiding)),
        serialize_element(base_mult(nonces.binding)),
    )
    if len(mine) != 1 or (mine[0].hiding, mine[0].binding) != own:
        err = "own commitment missing from the commitment list"
        raise FrostError(err)
    rho = compute_binding_factors(share.group_public, commitments, msg)
    r = compute_group_commitment(commitments, rho)
    lam = derive_interpolating_value([c.identifier for c in commitments], share.identifier)
    c = compute_challenge(r, share.group_public, msg)
    nonces.used = True
    z = (nonces.hiding + nonces.binding * rho[share.identifier] + lam * share.secret * c) % L
    return serialize_scalar(z)


def verify_signature_share(
    info: GroupInfo,
    identifier: int,
    sig_share: bytes,
    commitments: Sequence[Commitment],
    msg: bytes,
) -> bool:
    commitments = _checked(commitments)
    try:
        z = deserialize_scalar(sig_share)
    except FrostError:
        return False
    rho = compute_binding_factors(info.group_public, commitments, msg)
    r = compute_group_commitment(commitments, rho)
    comm = next(c for c in commitments if c.identifier == identifier)
    share_r = _add(
        deserialize_element(comm.hiding),
        _mul(rho[identifier], deserialize_element(comm.binding)),
    )
    c = compute_challenge(r, info.group_public, msg)
    lam = derive_interpolating_value([x.identifier for x in commitments], identifier)
    pk_i = deserialize_element(info.participant_publics[identifier])
    return _eq(base_mult(z), _add(share_r, _mul(c * lam % L, pk_i)))


def aggregate(
    info: GroupInfo,
    commitments: Sequence[Commitment],
    msg: bytes,
    sig_shares: Mapping[int, bytes],
) -> bytes:
    """Aggregate to a 64-byte Ed25519 signature ``R || z``; identifies bad shares on failure."""
    commitments = _checked(commitments)
    if len(commitments) < info.min_participants:
        err = "fewer signers than MIN_PARTICIPANTS"
        raise FrostError(err)
    if set(sig_shares) != {c.identifier for c in commitments}:
        err = "signature shares do not match the commitment list"
        raise FrostError(err)
    rho = compute_binding_factors(info.group_public, commitments, msg)
    r = compute_group_commitment(commitments, rho)
    z = sum(deserialize_scalar(s) for s in sig_shares.values()) % L
    sig = serialize_element(r) + serialize_scalar(z)
    if not verify(info.group_public, msg, sig):
        bad = sorted(
            i
            for i, s in sig_shares.items()
            if not verify_signature_share(info, i, s, commitments, msg)
        )
        err = f"aggregate signature invalid; misbehaving participants {bad}"
        raise FrostError(err)
    return sig


def verify(group_public: bytes, msg: bytes, signature: bytes) -> bool:
    """Plain Ed25519 verification (``cryptography`` backend), as any Ed25519 verifier would do."""
    try:
        ed25519_verify(group_public, msg, signature)
    except (CryptoError, ValueError):
        return False
    return True


def group_key_id(group_public: bytes) -> bytes:
    """16-byte identifier of a group key (``group_key_id`` in 0x73)."""
    return hashlib.blake2b(b"esp/v1/hive-group-key" + group_public, digest_size=32).digest()[:16]
