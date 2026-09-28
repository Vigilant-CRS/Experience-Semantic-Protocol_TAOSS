# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Trust vector for capsule recall (WP-069; V13 appendix "Trust Vector").

``τ(c) = (τ_sig, τ_anchor, τ_drift, τ_privacy, τ_lineage) ∈ [0, 1]^5``:

- ``τ_sig``: 1 if every signature verifies, else 0 (never fractional);
- ``τ_anchor``: 0 without a validated anchor set, else ``2^(-age / half_life)``;
- ``τ_drift = exp(-max_t MMD_t / κ)``;
- ``τ_privacy = 1{I_max <= iota_max} · (1 - ε_spent / ε_budget)^+``;
- ``τ_lineage``: genesis ⇒ 1 (given ``τ_sig = 1``); otherwise verified parent links /
  chain depth, and 0 if any tombstone appears in the lineage.

The optional scalar ``T = Σ λ_j τ_j`` exists **only** inside :class:`TrustScore`,
which always carries the vector (V13: a scalar without its components is
misleading). Recall is admissible iff ``T ≥ θ_T`` and ``τ_sig = τ_lineage = 1``.
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass

from esp.crypto.primitives import CryptoError
from esp.xcf.capsule import Capsule

COMPONENTS = ("sig", "anchor", "drift", "privacy", "lineage")


@dataclass(frozen=True, slots=True)
class TrustVector:
    sig: float
    anchor: float
    drift: float
    privacy: float
    lineage: float

    def __post_init__(self) -> None:
        for name in COMPONENTS:
            v = getattr(self, name)
            if not 0.0 <= v <= 1.0:
                msg = f"tau_{name} must lie in [0, 1]"
                raise ValueError(msg)
        if self.sig not in (0.0, 1.0):
            msg = "tau_sig is binary"
            raise ValueError(msg)

    def as_tuple(self) -> tuple[float, ...]:
        return tuple(getattr(self, n) for n in COMPONENTS)


@dataclass(frozen=True, slots=True)
class TrustScore:
    """The scalar T together with the vector it summarizes."""

    vector: TrustVector
    scalar: float
    weights: tuple[float, ...]

    def admissible(self, theta: float) -> bool:
        return self.scalar >= theta and self.vector.sig == 1.0 and self.vector.lineage == 1.0

    def __str__(self) -> str:
        parts = ", ".join(
            f"{n}={v:.3f}" for n, v in zip(COMPONENTS, self.vector.as_tuple(), strict=True)
        )
        return f"T={self.scalar:.3f} (tau: {parts})"


def score(
    vector: TrustVector, weights: tuple[float, ...] = (0.2, 0.2, 0.2, 0.2, 0.2)
) -> TrustScore:
    if len(weights) != 5 or any(w < 0 for w in weights) or not math.isclose(sum(weights), 1.0):
        msg = "weights must be 5 non-negative numbers summing to 1"
        raise ValueError(msg)
    t = sum(w * v for w, v in zip(weights, vector.as_tuple(), strict=True))
    return TrustScore(vector, t, weights)


def tau_sig(capsule: Capsule) -> float:
    try:
        capsule.verify_signature()
    except (CryptoError, ValueError):
        return 0.0
    return 1.0


def tau_anchor(*, validated: bool, age_days: float, half_life_days: float = 365.0) -> float:
    return 0.0 if not validated else 2.0 ** (-max(0.0, age_days) / half_life_days)


def tau_drift(max_mmd: float, kappa: float) -> float:
    return math.exp(-max(0.0, max_mmd) / kappa)


def tau_privacy(*, i_max: float, iota_max: float, eps_spent: float, eps_budget: float) -> float:
    if i_max > iota_max or eps_budget <= 0:
        return 0.0
    return max(0.0, 1.0 - eps_spent / eps_budget)


def tau_lineage(
    capsule: Capsule, store: Mapping[bytes, Capsule], tombstoned: frozenset[bytes]
) -> float:
    """Verified parent links / chain depth; 0 on any tombstone or broken signature at the leaf."""
    if tau_sig(capsule) == 0.0 or capsule.cid in tombstoned:
        return 0.0
    parent = capsule.header.parent_cid
    if parent == bytes(32):
        return 1.0  # genesis
    depth = verified = 0
    seen: set[bytes] = set()
    while parent != bytes(32):
        depth += 1
        if parent in tombstoned or parent in seen:
            return 0.0
        seen.add(parent)
        node = store.get(parent)
        if node is None or node.cid != parent or tau_sig(node) == 0.0:
            break  # broken link: the chain above cannot be verified
        verified += 1
        parent = node.header.parent_cid
    return verified / depth
