# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Hive audit: preregistered predictive-emergence test and admissibility (V13 Hive Audit).

Whole-minus-sum criterion (after Rosas et al.)::

    Ψ_{k,k+lag}(V) = I(V_k; V_{k+lag}) - Σ_j I(X^j_k; V_{k+lag})

- The estimator is ``gaussian-mi-v1``: Gaussian (log-det) mutual information
  on pooled ``(k, k+lag)`` pairs from held-out episodes.
- The null is a time-shuffle surrogate. The future macro is permuted across
  samples, which breaks temporal predictability and keeps the marginals. The
  statistic is ``Ψ_obs - mean Ψ_null``, which removes estimator bias.
- Uncertainty comes from an episode bootstrap: episodes are the resampling
  unit. The lower confidence bound is taken at ``alpha/|E|`` (Bonferroni over the
  emergence-audited types).
- Criterion (i) passes iff that lower bound is above zero.

The criterion is conservative (redundancy is subtracted repeatedly). ``Ψ <= 0``
does not prove absence of emergence, and a positive Ψ is emergence
*relative to the chosen micro-representation*.

The audit refuses to run unless its configuration digest equals the
preregistered digest and the audit episodes are disjoint from the fit
episodes.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass

import numpy as np
from numpy.typing import NDArray

from esp.core.taoss_types import TaossType
from esp.hive.tlv import HiveError

F64 = NDArray[np.float64]
Macro = Callable[[F64], F64]
"""``G_t``: member states ``(n, d)`` -> macro variable ``(m,)``."""


@dataclass(frozen=True, slots=True)
class EmergencePrereg:
    primary_type: TaossType
    emergence_types: tuple[TaossType, ...]
    lag: int
    task: str
    fit_episodes: tuple[str, ...]
    audit_episodes: tuple[str, ...]
    estimator: str = "gaussian-mi-v1"
    alpha: float = 0.05
    n_boot: int = 200
    n_null: int = 20
    seed: int = 0

    def __post_init__(self) -> None:
        if self.primary_type not in self.emergence_types:
            msg = "the primary emergence type must be emergence-audited"
            raise HiveError(msg)
        if self.lag < 1 or not 0.0 < self.alpha < 1.0:
            msg = "lag >= 1 and alpha in (0, 1) required"
            raise HiveError(msg)
        if set(self.fit_episodes) & set(self.audit_episodes):
            msg = "fit and audit episodes must be disjoint (held-out audit)"
            raise HiveError(msg)
        if not self.audit_episodes:
            msg = "audit episodes required"
            raise HiveError(msg)
        if self.estimator != "gaussian-mi-v1":
            msg = f"unknown estimator {self.estimator}"
            raise HiveError(msg)

    def digest(self) -> str:
        d = asdict(self)
        d["primary_type"] = self.primary_type.name
        d["emergence_types"] = [t.name for t in self.emergence_types]
        blob = json.dumps(d, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.blake2b(b"esp/v1/hive-prereg" + blob, digest_size=32).hexdigest()


def gaussian_mi(a: F64, b: F64, ridge: float = 1e-9) -> float:
    """``I(A;B)`` in nats under a joint Gaussian fit (samples in rows)."""
    a = np.asarray(a, dtype=np.float64).reshape(len(a), -1)
    b = np.asarray(b, dtype=np.float64).reshape(len(b), -1)
    joint = np.cov(np.hstack([a, b]), rowvar=False)
    joint = np.atleast_2d(joint) + ridge * np.eye(joint.shape[0] if joint.ndim else 1)
    da = a.shape[1]
    _, la = np.linalg.slogdet(joint[:da, :da])
    _, lb = np.linalg.slogdet(joint[da:, da:])
    _, lj = np.linalg.slogdet(joint)
    return max(0.0, 0.5 * float(la + lb - lj))


def _pairs(episodes: Sequence[F64], macro: Macro, lag: int) -> tuple[F64, F64, F64]:
    """Pool (X_k, V_k, V_{k+lag}) over episodes. Each episode has shape (T, n, d)."""
    xs, vs, vf = [], [], []
    for raw in episodes:
        ep = np.asarray(raw, dtype=np.float64)
        v = np.stack([np.atleast_1d(macro(ep[k])) for k in range(ep.shape[0])])
        xs.append(ep[:-lag])
        vs.append(v[:-lag])
        vf.append(v[lag:])
    return np.concatenate(xs), np.concatenate(vs), np.concatenate(vf)


def psi(x: F64, v: F64, v_future: F64) -> float:
    whole = gaussian_mi(v, v_future)
    parts = sum(gaussian_mi(x[:, j, :], v_future) for j in range(x.shape[1]))
    return whole - parts


@dataclass(frozen=True, slots=True)
class EmergenceResult:
    type: TaossType
    psi: float
    psi_null_mean: float
    lower_bound: float
    passed: bool


def emergence_test(
    prereg: EmergencePrereg,
    registered_digest: str,
    t: TaossType,
    episodes: Mapping[str, F64],
    macro: Macro,
) -> EmergenceResult:
    if prereg.digest() != registered_digest:
        msg = "audit configuration differs from the preregistration"
        raise HiveError(msg)
    if t not in prereg.emergence_types:
        msg = f"{t.name} was not preregistered for the emergence audit"
        raise HiveError(msg)
    if set(episodes) & set(prereg.fit_episodes):
        msg = "fit episodes must not be used for the audit"
        raise HiveError(msg)
    if set(episodes) != set(prereg.audit_episodes):
        msg = "audit must use exactly the preregistered held-out episodes"
        raise HiveError(msg)
    rng = np.random.default_rng(prereg.seed)
    names = sorted(episodes)
    eps = [episodes[k] for k in names]

    def stat(sample: Sequence[F64]) -> tuple[float, float]:
        x, v, vf = _pairs(sample, macro, prereg.lag)
        obs = psi(x, v, vf)
        nulls = [psi(x, v, vf[rng.permutation(len(vf))]) for _ in range(prereg.n_null)]
        return obs, float(np.mean(nulls))

    obs, null_mean = stat(eps)
    boots = []
    for _ in range(prereg.n_boot):
        idx = rng.integers(0, len(eps), size=len(eps))
        o, nm = stat([eps[i] for i in idx])
        boots.append(o - nm)
    q = prereg.alpha / len(prereg.emergence_types)
    lower = float(np.quantile(boots, q))
    return EmergenceResult(t, obs, null_mean, lower, lower > 0.0)


# --- admissibility (V13 definition "admissible typed hive") ---------------------------------------


@dataclass(frozen=True, slots=True)
class Thresholds:
    d_min: float = 0.2
    a_min: float = 0.5
    pi_max: float = 0.5


@dataclass(frozen=True, slots=True)
class TypeAudit:
    type: TaossType
    emergence: EmergenceResult | None
    normalized_diversity: float | None
    min_autonomy: float
    max_social_power: float
    privacy_ok: bool
    emo_mixing: float


@dataclass(frozen=True, slots=True)
class AuditReport:
    types: tuple[TypeAudit, ...]
    thresholds: Thresholds
    label: str
    """``"hive"`` only if (i)-(v) hold; otherwise ``"collective"``."""
    flags: tuple[str, ...]
    anonymity: str

    def as_dict(self) -> dict[str, object]:
        return {
            "label": self.label,
            "flags": list(self.flags),
            "anonymity": self.anonymity,
            "types": [
                {
                    "type": ta.type.name,
                    "psi": None if ta.emergence is None else ta.emergence.psi,
                    "psi_lower_bound": None if ta.emergence is None else ta.emergence.lower_bound,
                    "normalized_diversity": ta.normalized_diversity,
                    "min_autonomy": ta.min_autonomy,
                    "max_social_power": ta.max_social_power,
                    "privacy_ok": ta.privacy_ok,
                    "emo_mixing": ta.emo_mixing,
                }
                for ta in self.types
            ],
        }


def admissibility(
    audits: Sequence[TypeAudit],
    emergence_types: Sequence[TaossType],
    thresholds: Thresholds,
    anonymity: str,
) -> AuditReport:
    flags: list[str] = []
    emergence_ok = all(
        ta.emergence is not None and ta.emergence.passed
        for ta in audits
        if ta.type in emergence_types
    ) and any(ta.type in emergence_types for ta in audits)
    if not emergence_ok:
        flags.append("no-emergence")  # (i) failed: a collective episode, not a demonstrated hive
    for ta in audits:
        if ta.normalized_diversity is not None and ta.normalized_diversity < thresholds.d_min:
            flags.append(f"monoculture:{ta.type.name}")  # (ii)
        if ta.min_autonomy < thresholds.a_min - 1e-12:
            flags.append(f"autonomy-breach:{ta.type.name}")  # (iii)
        if ta.max_social_power > thresholds.pi_max + 1e-12:
            flags.append(f"captured:{ta.type.name}")  # (iv)
        if not ta.privacy_ok:
            flags.append(f"privacy:{ta.type.name}")  # (v)
        if ta.type is TaossType.EMO and ta.emo_mixing != 0.0:
            flags.append("emo-mixing")
    label = "hive" if not flags else "collective"
    return AuditReport(tuple(audits), thresholds, label, tuple(flags), anonymity)
