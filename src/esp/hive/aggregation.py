# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Typed aggregation operators ``G_t`` and the reference secure-aggregation round (WP-070).

**Secure aggregation with distributed noise** (V13 distributed-noise
proposition). This is the companion-profile reference for GAP-017:

- each member clips its state to ``||x_i||_2 <= C`` and adds
  ``N(0, sigma^2/h · I)``, where ``h = n - c`` is the declared minimum number
  of honest contributors;
- the noisy vector is fixed-point encoded modulo ``2^64`` and masked with
  pairwise X25519-derived PRG masks, Bonawitz style. The masks cancel exactly
  in the sum, so the aggregator sees only masked vectors and the total;
- a round **aborts** if fewer than ``h`` qualifying contributions complete.
  A missing member also aborts the round, because this reference has no
  dropout recovery. Secure aggregation alone is not DP;
- accounting: Gaussian RDP ``rho(alpha) = (2C)^2 alpha / (2 sigma^2)``,
  converted with the ESP alpha-grid accountant.

The fixed-point floats and the numpy Gaussian are the same documented
limitation as errata E-11: this is not a discrete-Gaussian guarantee.

**EMO** is released only as a DP histogram over anchor bins, above the
minimum group size. There is deliberately no centroid operator.

**KNO/CTX** use covariance intersection by default. Inverse-variance fusion
is allowed only with declared independence (V13 correlation-floor proposition).

**INT** uses a declared social-choice rule: binary majority or the
exponential mechanism.
"""

from __future__ import annotations

import hashlib
import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

import numpy as np
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from numpy.typing import NDArray

from esp.hive.tlv import HiveError
from esp.privacy.dp import epsilon_rdp_grid

F64 = NDArray[np.float64]
U64 = NDArray[np.uint64]
FIXED_BITS: Final = 24
_SCALE: Final = float(1 << FIXED_BITS)
_MOD: Final = 1 << 64


class RoundAborted(HiveError):  # noqa: N818 - a protocol outcome
    """A round cannot release: too few qualifying contributions or a missing member."""


# --- clipping, fixed point, masks ----------------------------------------------------------------


def clip(x: F64, c: float) -> F64:
    x = np.asarray(x, dtype=np.float64)
    norm = float(np.linalg.norm(x))
    return x if norm <= c else x * (c / norm)


def to_fixed(x: F64) -> U64:
    q = np.round(np.asarray(x, dtype=np.float64) * _SCALE).astype(np.int64)
    return q.astype(np.uint64)  # two's complement wrap = mod 2^64


def from_fixed(q: U64) -> F64:
    return q.astype(np.int64).astype(np.float64) / _SCALE


def _prg(seed: bytes, dim: int) -> U64:
    out = bytearray()
    counter = 0
    while len(out) < 8 * dim:
        out += hashlib.blake2b(
            counter.to_bytes(8, "big"), key=seed, digest_size=64, person=b"esp-hive-mask"
        ).digest()
        counter += 1
    return np.frombuffer(bytes(out[: 8 * dim]), dtype=">u8").astype(np.uint64)


@dataclass
class SecAggMember:
    """One participant of a masked-sum round."""

    index: int
    dh: X25519PrivateKey = field(default_factory=X25519PrivateKey.generate)

    @property
    def public(self) -> bytes:
        return self.dh.public_key().public_bytes_raw()

    def mask(self, value: U64, peers: Mapping[int, bytes], round_id: bytes) -> U64:
        """``enc(y_i) + sum_{j>i} PRG(s_ij) - sum_{j<i} PRG(s_ij)`` modulo ``2^64``."""
        out = value.copy()
        for j, pk in peers.items():
            if j == self.index:
                continue
            shared = self.dh.exchange(X25519PublicKey.from_public_bytes(pk))
            seed = hashlib.blake2b(round_id + shared, digest_size=32).digest()
            m = _prg(seed, value.size)
            with np.errstate(over="ignore"):
                out = out + m if j > self.index else out - m
        return out


def masked_sum(masked: Mapping[int, U64], roster: Sequence[int]) -> U64:
    if set(masked) != set(roster):
        msg = "a rostered member did not complete the round (no dropout recovery in the reference)"
        raise RoundAborted(msg)
    total = np.zeros_like(next(iter(masked.values())))
    with np.errstate(over="ignore"):
        for v in masked.values():
            total = total + v
    return total


@dataclass(frozen=True, slots=True)
class MemberInput:
    index: int
    state: F64
    adds_noise: bool = True
    """Declared honest-noise participation. Colluding or noise-revealing members count as False."""


@dataclass(frozen=True, slots=True)
class RoundRelease:
    mean: F64
    n: int
    honest: int
    epsilon: float
    delta: float
    sigma: float
    clip: float


def rdp_epsilon(clip_norm: float, sigma: float, delta: float) -> float:
    """``(eps, delta)`` of one sum release with residual honest noise ``sigma``.

    Member adjacency: one member's complete contribution changes.
    """
    c = (2.0 * clip_norm) ** 2 / (2.0 * sigma**2)
    return epsilon_rdp_grid(c, delta)


def secure_round(
    inputs: Sequence[MemberInput],
    *,
    clip_norm: float,
    sigma: float,
    honest_min: int,
    delta: float,
    rng: np.random.Generator,
    round_id: bytes,
    min_group: int,
    completed: Sequence[int] | None = None,
) -> RoundRelease:
    """One distributed-noise secure-aggregation release of the member mean."""
    n = len(inputs)
    if n < min_group:
        msg = f"group of {n} below the minimum group size {min_group}"
        raise RoundAborted(msg)
    if not 1 <= honest_min <= n:
        msg = "honest_min must lie in [1, n]"
        raise HiveError(msg)
    done = {i.index for i in inputs} if completed is None else set(completed)
    honest = sum(1 for i in inputs if i.adds_noise and i.index in done)
    if honest < honest_min:
        msg = f"only {honest} qualifying noise contributions, {honest_min} required"
        raise RoundAborted(msg)
    members = {i.index: SecAggMember(i.index) for i in inputs}
    publics = {k: m.public for k, m in members.items()}
    masked: dict[int, U64] = {}
    for inp in inputs:
        if inp.index not in done:
            continue
        y = clip(inp.state, clip_norm)
        if inp.adds_noise:
            y = y + rng.normal(0.0, sigma / math.sqrt(honest_min), size=y.shape)
        masked[inp.index] = members[inp.index].mask(to_fixed(y), publics, round_id)
    total = from_fixed(masked_sum(masked, list(members)))
    return RoundRelease(
        mean=total / n,
        n=n,
        honest=honest,
        epsilon=rdp_epsilon(clip_norm, sigma, delta),
        delta=delta,
        sigma=sigma,
        clip=clip_norm,
    )


# --- EMO: DP histogram over anchor bins ----------------------------------------------------------


@dataclass(frozen=True, slots=True)
class AffectDistribution:
    """Collective affect as a distribution. There is intentionally no mean/centroid (V13)."""

    anchors: tuple[str, ...]
    counts: tuple[float, ...]
    epsilon: float
    n_members: int

    def shares(self) -> tuple[float, ...]:
        total = sum(self.counts)
        return tuple(c / total if total > 0 else 0.0 for c in self.counts)


def emo_histogram(
    coords: Sequence[F64],
    anchors: Sequence[str],
    *,
    epsilon: float,
    min_group: int,
    rng: np.random.Generator,
) -> AffectDistribution:
    """Each member votes for its dominant anchor; Laplace noise, replace-one L1 sensitivity 2."""
    n = len(coords)
    if n < min_group:
        msg = f"EMO distribution needs at least {min_group} members, got {n}"
        raise RoundAborted(msg)
    if epsilon <= 0.0:
        msg = "EMO histogram needs a positive epsilon"
        raise HiveError(msg)
    counts = np.zeros(len(anchors))
    for c in coords:
        v = np.asarray(c, dtype=np.float64)
        if v.shape != (len(anchors),):
            msg = "EMO coordinates must have one entry per anchor"
            raise HiveError(msg)
        counts[int(np.argmax(v))] += 1.0
    noisy = np.maximum(counts + rng.laplace(0.0, 2.0 / epsilon, size=counts.shape), 0.0)
    return AffectDistribution(tuple(anchors), tuple(float(x) for x in noisy), epsilon, n)


# --- KNO / CTX fusion ----------------------------------------------------------------------------


def inverse_variance(means: Sequence[F64], covs: Sequence[F64]) -> tuple[F64, F64]:
    """Optimal only for independent evidence; overconfident under coupling (use CI instead)."""
    infos = [np.linalg.inv(c) for c in covs]
    cov = np.linalg.inv(sum(infos))
    mean = cov @ sum(i @ m for i, m in zip(infos, means, strict=True))
    return mean, cov


def covariance_intersection(means: Sequence[F64], covs: Sequence[F64]) -> tuple[F64, F64]:
    """Conservative fusion with unknown cross-covariance (sequential two-way CI, trace-optimal).

    The weight search is a golden-section search on ``omega in [0, 1]``.
    """
    mean, cov = np.asarray(means[0], float), np.asarray(covs[0], float)
    for m2, c2 in zip(means[1:], covs[1:], strict=True):
        a_inv, b_inv = np.linalg.inv(cov), np.linalg.inv(np.asarray(c2, float))

        def fused(w: float, a_inv: F64 = a_inv, b_inv: F64 = b_inv) -> F64:
            return np.linalg.inv(w * a_inv + (1.0 - w) * b_inv)

        lo, hi = 0.0, 1.0
        g = (math.sqrt(5.0) - 1.0) / 2.0
        for _ in range(60):
            x1, x2 = hi - g * (hi - lo), lo + g * (hi - lo)
            if np.trace(fused(x1)) <= np.trace(fused(x2)):
                hi = x2
            else:
                lo = x1
        w = (lo + hi) / 2.0
        new_cov = fused(w)
        mean = new_cov @ (w * a_inv @ mean + (1.0 - w) * b_inv @ np.asarray(m2, float))
        cov = new_cov
    return mean, cov


# --- INT social choice ---------------------------------------------------------------------------


def majority_binary(votes: Sequence[bool]) -> bool:
    """May's-theorem baseline; ties are *not* adopted (status quo). Not DP (epsilon_used = 0)."""
    yes = sum(1 for v in votes if v)
    return yes * 2 > len(votes)


def exponential_mechanism(
    scores: Mapping[str, float],
    *,
    epsilon: float,
    sensitivity: float,
    rng: np.random.Generator,
) -> str:
    """``Pr[o] ∝ exp(eps · s(o) / (2 Δs))``, which is eps-DP (V13 INT hive)."""
    if epsilon <= 0.0 or sensitivity <= 0.0:
        msg = "exponential mechanism needs positive epsilon and sensitivity"
        raise HiveError(msg)
    options = sorted(scores)
    s = np.array([scores[o] for o in options], dtype=np.float64)
    logits = epsilon * s / (2.0 * sensitivity)
    p = np.exp(logits - logits.max())
    p /= p.sum()
    return options[int(rng.choice(len(options), p=p))]
