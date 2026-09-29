# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Runtime differential privacy under typed adjacency (V13 section 12; WP-055).

Mechanism (local DP, at the sender, before transmission)::

    E_clip = E * min(1, C_t / ||E||_2)          E_DP = E_clip + N(0, sigma_t^2 I)

Calibration (classical Gaussian, valid for eps in (0, 1) only)::

    sigma = Delta_2 * sqrt(2 ln(1.25 / delta)) / eps,   Delta_2 = 2 C  (replace-one)

Accounting (v1 mandated: RDP optimal alpha). The Gaussian RDP curve is linear
in alpha, ``rho(alpha) = c * alpha`` with ``c = sum over releases and types of
(2 C_t)^2 / (2 sigma_t^2)``, so ``eps(delta) = c + 2 sqrt(c ln(1/delta))`` at
``alpha* = 1 + sqrt(ln(1/delta) / c)``. A grid accountant over V13's alpha grid is
provided for non-Gaussian mechanisms.

Known limitation: noise is sampled with floating-point arithmetic from a
securely seeded generator. Floating-point samplers can leak through
low-order bits (Mironov 2012); certified profiles need a discrete Gaussian
sampler (ADR-0018). ``DP_LEVEL = NONE`` channels are never differentially
private, and user-facing text must never say so (:func:`consent_text`).
"""

from __future__ import annotations

import json
import math
import os
import secrets
import sqlite3
import struct
import tempfile
import uuid
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag, unique
from pathlib import Path
from typing import Final

import numpy as np
from numpy.typing import NDArray

from esp.codec.errors import WireError
from esp.codec.header import DpLevel
from esp.codec.tlv import Tlv
from esp.core.errors import ErrorCode, EspError
from esp.core.taoss_types import TaossType, bitmap_to_types, types_to_bitmap

DP_PARAMS_CODE: Final = 0x30
#: V13 alpha grid for grid accountants (1.25 ... 64).
ALPHA_GRID: Final = (1.25, 1.5, 1.75, *[float(a) for a in range(2, 65)])
REFERENCE_DELTA_PER_RELEASE: Final = 1e-8
REFERENCE_DELTA_TOTAL: Final = 1e-6


class PrivacyBudgetError(EspError):
    code = ErrorCode.CONSENT_DENIED


@unique
class Adjacency(IntEnum):
    FRAME = 0
    SEGMENT = 1
    SUBJECT = 2  # subject / profile-defined


@unique
class Accountant(IntEnum):
    RDP_OPTIMAL_ALPHA = 0
    ADVANCED = 1
    PRV = 2
    ANALYTIC_GAUSSIAN = 3


class DpFlags(IntFlag):
    AGGREGATED = 1 << 0


NO_FLAGS: Final = DpFlags(0)


def classical_sigma(clip_norm: float, eps: float, delta: float) -> float:
    """Classical Gaussian calibration with replace-one sensitivity 2C. Only eps in (0, 1)."""
    if not 0.0 < eps < 1.0:
        msg = "classical Gaussian calibration is only valid for 0 < eps < 1 (V13 section 12)"
        raise ValueError(msg)
    if not 0.0 < delta < 1.0 or clip_norm <= 0.0:
        msg = "delta must be in (0, 1) and the clip norm positive"
        raise ValueError(msg)
    return 2.0 * clip_norm * math.sqrt(2.0 * math.log(1.25 / delta)) / eps


#: V13 reference profiles (C = 1): ``DP_LEVEL -> (eps_p, sigma)``.
REFERENCE_PROFILES: Final[Mapping[DpLevel, tuple[float, float]]] = {
    DpLevel.L1_BALANCED_REF: (0.5, classical_sigma(1.0, 0.5, REFERENCE_DELTA_PER_RELEASE)),
    DpLevel.L1_PRIVATE_REF: (0.1, classical_sigma(1.0, 0.1, REFERENCE_DELTA_PER_RELEASE)),
}


def rdp_coefficient(
    clip_norms: Mapping[TaossType, float], sigmas: Mapping[TaossType, float]
) -> float:
    """``c`` of one release: ``sum_t (2 C_t)^2 / (2 sigma_t^2)`` (Gaussian RDP is ``c * alpha``)."""
    if set(clip_norms) != set(sigmas):
        msg = "clip norms and sigmas must cover the same types"
        raise ValueError(msg)
    return sum((2.0 * clip_norms[t]) ** 2 / (2.0 * sigmas[t] ** 2) for t in clip_norms)


def epsilon_rdp(c_total: float, delta: float) -> tuple[float, float]:
    """Closed-form RDP -> (eps, alpha*) for a linear RDP curve ``c * alpha``."""
    if c_total <= 0.0:
        return 0.0, math.inf
    log_inv = math.log(1.0 / delta)
    return c_total + 2.0 * math.sqrt(c_total * log_inv), 1.0 + math.sqrt(log_inv / c_total)


def epsilon_rdp_grid(c_total: float, delta: float, grid: tuple[float, ...] = ALPHA_GRID) -> float:
    """Grid-search accountant over the logged V13 alpha grid (>= the closed form)."""
    log_inv = math.log(1.0 / delta)
    return min(c_total * a + log_inv / (a - 1.0) for a in grid)


def effective_information_bits(dim: int, clip_norm: float, sigma: float) -> float:
    """Upper bound on bits per release of one type (V13 effective information rate)."""
    return dim / 2.0 * math.log2(1.0 + clip_norm**2 / (dim * sigma**2))


def clip_and_noise(
    latent: NDArray[np.float64], clip_norm: float, sigma: float, rng: np.random.Generator
) -> NDArray[np.float64]:
    """V13 clip + Gaussian noise on one (standardized) typed latent."""
    x = np.asarray(latent, dtype=np.float64)
    norm = float(np.linalg.norm(x))
    clipped = x if norm <= clip_norm else x * (clip_norm / norm)
    return clipped + rng.normal(0.0, sigma, size=x.shape)


def secure_rng() -> np.random.Generator:
    """Generator seeded from the OS CSPRNG (see the module's known limitation)."""
    return np.random.default_rng(secrets.randbits(256))


# --- TLV_DP_PARAMS ---------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DpParams:
    capability_id: uuid.UUID
    adjacency: Adjacency
    segment_window: int
    clip_norms: Mapping[TaossType, float]
    sigmas: Mapping[TaossType, float]
    composition_k: int
    epsilon_spent: float
    delta_target: float
    accountant: Accountant = Accountant.RDP_OPTIMAL_ALPHA
    flags: DpFlags = NO_FLAGS

    def encode(self) -> Tlv:
        types = sorted(self.clip_norms)
        if set(types) != set(self.sigmas) or not types:
            msg = "clip norms and sigmas must cover the same, non-empty type set"
            raise WireError(msg)
        body = self.capability_id.bytes + struct.pack(
            ">BHHB", self.adjacency, self.segment_window, types_to_bitmap(types), len(types)
        )
        body += struct.pack(f">{len(types)}f", *(self.clip_norms[t] for t in types))
        body += struct.pack(f">{len(types)}f", *(self.sigmas[t] for t in types))
        body += struct.pack(
            ">IffBB",
            self.composition_k,
            self.epsilon_spent,
            self.delta_target,
            self.accountant,
            int(self.flags),
        )
        return Tlv(DP_PARAMS_CODE, body + bytes(6))

    @classmethod
    def decode(cls, tlv: Tlv) -> DpParams:
        v = tlv.value
        try:
            cap = uuid.UUID(bytes=v[:16])
            adjacency, window, clipped, n = struct.unpack_from(">BHHB", v, 16)
            types = bitmap_to_types(clipped)
            if n != len(types) or n == 0:
                msg = "n_types must equal popcount(types_clipped)"
                raise WireError(msg)
            off = 22
            clips = struct.unpack_from(f">{n}f", v, off)
            sigmas = struct.unpack_from(f">{n}f", v, off + 4 * n)
            off += 8 * n
            k, eps, delta, accountant, flags = struct.unpack_from(">IffBB", v, off)
            reserved = v[off + 14 :]
            if len(reserved) != 6 or any(reserved):
                msg = "reserved bytes must be six zero bytes"
                raise WireError(msg)
            if flags & ~1:
                msg = "DP flags bits 1-7 must be zero"
                raise WireError(msg)
            params = cls(
                capability_id=cap,
                adjacency=Adjacency(adjacency),
                segment_window=window,
                clip_norms=dict(zip(types, clips, strict=True)),
                sigmas=dict(zip(types, sigmas, strict=True)),
                composition_k=k,
                epsilon_spent=eps,
                delta_target=delta,
                accountant=Accountant(accountant),
                flags=DpFlags(flags),
            )
        except (struct.error, ValueError) as exc:
            if isinstance(exc, WireError):
                raise
            msg = f"malformed TLV_DP_PARAMS: {exc}"
            raise WireError(msg) from None
        if tlv.code != DP_PARAMS_CODE:
            msg = "not a TLV_DP_PARAMS"
            raise WireError(msg)
        if not all(math.isfinite(x) and x > 0 for x in (*clips, *sigmas)):
            msg = "clip norms and sigmas must be finite and positive"
            raise WireError(msg)
        if not (math.isfinite(eps) and eps >= 0.0 and 0.0 < delta < 1.0):
            msg = "epsilon_spent / delta_target out of range"
            raise WireError(msg)
        return params

    @property
    def release_coefficient(self) -> float:
        return rdp_coefficient(self.clip_norms, self.sigmas)


# --- persistent ledger (sender) --------------------------------------------------------


@dataclass(slots=True)
class PrivacyLedger:
    """Monotone, persistent privacy budget per capability (V13 section 9.7).

    Global over *independent privatized releases* under the capability (not
    per session, not per recipient). Updated and fsynced **before** a release
    leaves the sender; retransmitting the same privatized sample is free.
    """

    path: Path
    capability_id: uuid.UUID
    ceiling: float
    delta_target: float = REFERENCE_DELTA_TOTAL
    k: int = field(default=0, init=False)
    c_total: float = field(default=0.0, init=False)

    def __post_init__(self) -> None:
        if not math.isfinite(self.ceiling) or self.ceiling < 0 or not 0 < self.delta_target < 1:
            msg = "ledger ceiling and delta_target must be finite and in range"
            raise PrivacyBudgetError(msg)
        with self._locked():
            if self.path.exists():
                self._load()
            else:
                self._persist(0, 0.0)

    @contextmanager
    def _locked(self) -> Iterator[None]:
        # SQLite supplies OS-backed, process-safe locks on Unix and Windows;
        # the JSON file remains the durable accounting record. A stable sidecar
        # is necessary because atomic replacement changes the JSON file's inode.
        conn = sqlite3.connect(str(self.path) + ".lock", timeout=30)
        try:
            conn.execute("BEGIN IMMEDIATE")
            yield
        finally:
            conn.rollback()
            conn.close()

    def _load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("not an object")
            if data.get("capability_id") != str(self.capability_id):
                msg = "ledger belongs to another capability"
                raise PrivacyBudgetError(msg)
            k, total = data["k"], data["c_total"]
            if (
                type(k) is not int
                or not 0 <= k < 2**32
                or type(total) not in (int, float)
                or not math.isfinite(total)
                or total < 0
                or (k == 0) != (total == 0)
            ):
                raise ValueError("invalid counters")
            # Legacy ledgers used the reference delta; never reinterpret their
            # accumulated RDP under a different delta or a larger persisted cap.
            if data.get("delta_target", REFERENCE_DELTA_TOTAL) != self.delta_target:
                raise ValueError("delta_target changed")
            if self.ceiling > data.get("ceiling", self.ceiling):
                raise ValueError("ceiling increased")
        except (OSError, ValueError, KeyError, TypeError) as exc:
            msg = "privacy ledger lost, corrupt or policy changed"
            raise PrivacyBudgetError(msg) from exc
        self.k, self.c_total = k, float(total)

    @property
    def epsilon_spent(self) -> float:
        return epsilon_rdp(self.c_total, self.delta_target)[0]

    def charge(self, release_coefficient: float) -> tuple[int, float]:
        """Serialize read/check/write across instances; fsync before releasing data."""
        if not math.isfinite(release_coefficient) or release_coefficient <= 0:
            msg = "release coefficient must be finite and positive"
            raise PrivacyBudgetError(msg)
        with self._locked():
            self._load()  # never account against a stale in-memory snapshot
            c_after = self.c_total + release_coefficient
            eps_after = epsilon_rdp(c_after, self.delta_target)[0]
            if not math.isfinite(eps_after) or eps_after > self.ceiling or self.k >= 2**32 - 1:
                msg = f"release would exceed the DP ceiling ({eps_after:.3f} > {self.ceiling})"
                raise PrivacyBudgetError(msg)
            self._persist(self.k + 1, c_after)
            self.k, self.c_total = self.k + 1, c_after
            return self.k, eps_after

    def _persist(self, k: int, c_total: float) -> None:
        payload = json.dumps(
            {
                "capability_id": str(self.capability_id),
                "k": k,
                "c_total": c_total,
                "ceiling": self.ceiling,
                "delta_target": self.delta_target,
            }
        ).encode()
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".ledger-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(payload)
                fh.flush()
                os.fsync(fh.fileno())
            Path(tmp).replace(self.path)
            if os.name == "posix":
                directory_fd = os.open(self.path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            Path(tmp).unlink(missing_ok=True)


# --- receiver audit --------------------------------------------------------------------------


@dataclass(slots=True)
class DpAuditor:
    """Receiver-side audit: *accounting* becomes receiver-checkable (not execution)."""

    ceiling: float
    tolerance: float = 1e-4
    last_epsilon: dict[bytes, float] = field(default_factory=dict)
    last_k: dict[bytes, int] = field(default_factory=dict)
    last_delta: dict[bytes, float] = field(default_factory=dict)
    releases: dict[bytes, tuple[DpLevel, DpParams]] = field(default_factory=dict)
    max_cached_releases: int = 8192

    def audit(  # noqa: PLR0912 - one branch per audited invariant, kept flat on purpose
        self,
        level: DpLevel,
        params: DpParams | None,
        present: frozenset[TaossType],
        *,
        release_id: bytes | None = None,
    ) -> float:
        """Return the declared cumulative epsilon if consistent; raise otherwise."""
        if level is DpLevel.NONE:
            if params is not None:
                msg = "DP_LEVEL NONE must not carry TLV_DP_PARAMS"
                raise WireError(msg)
            return self.last_epsilon.get(b"", 0.0)
        if params is None:
            msg = "non-NONE DP_LEVEL requires TLV_DP_PARAMS"
            raise WireError(msg)
        if not present <= set(params.clip_norms):
            msg = "a transmitted latent type was not clipped and noised"
            raise PrivacyBudgetError(msg)
        if level in REFERENCE_PROFILES:
            _, sigma_ref = REFERENCE_PROFILES[level]
            for t, sigma in params.sigmas.items():
                if sigma < sigma_ref * params.clip_norms[t] * (1 - self.tolerance):
                    msg = f"{t.name} noise below the {level.name} reference"
                    raise PrivacyBudgetError(msg)
        if params.accountant is not Accountant.RDP_OPTIMAL_ALPHA:
            msg = "v1 receivers audit only the mandated RDP optimal-alpha accountant"
            raise PrivacyBudgetError(msg)
        if params.epsilon_spent > self.ceiling:
            msg = "declared epsilon exceeds the capability ceiling"
            raise PrivacyBudgetError(msg)
        if release_id is not None and release_id in self.releases:
            if self.releases[release_id] != (level, params):
                msg = "release identity reused with different DP parameters"
                raise PrivacyBudgetError(msg)
            return params.epsilon_spent  # an identical authenticated sample costs nothing new
        key = params.capability_id.bytes
        if params.composition_k <= self.last_k.get(
            key, 0
        ) or params.epsilon_spent + self.tolerance < self.last_epsilon.get(key, 0.0):
            msg = "privacy ledger rollback detected"
            raise PrivacyBudgetError(msg)
        if key in self.last_delta and not math.isclose(
            params.delta_target, self.last_delta[key], rel_tol=1e-6
        ):
            msg = "privacy ledger delta_target changed"
            raise PrivacyBudgetError(msg)
        # k counts releases, not types. Their costs may differ. Reconstruct
        # the previously declared cumulative RDP coefficient and add this
        # observed release. Missing history cannot be proved from the v1 TLV;
        # never pretend that all k releases had today's cost (ADR-0033).
        previous_eps = self.last_epsilon.get(key, 0.0)
        log_inv = math.log(1.0 / params.delta_target)
        prior_c = (previous_eps / (math.sqrt(log_inv + previous_eps) + math.sqrt(log_inv))) ** 2
        implied = epsilon_rdp(prior_c + params.release_coefficient, params.delta_target)[0]
        if params.epsilon_spent < implied * (1 - self.tolerance) - self.tolerance:
            msg = (
                f"declared epsilon {params.epsilon_spent} below the accountant value {implied:.4f}"
            )
            raise PrivacyBudgetError(msg)
        self.last_k[key] = params.composition_k
        self.last_epsilon[key] = params.epsilon_spent
        self.last_delta[key] = params.delta_target
        if release_id is not None:
            self.releases[release_id] = (level, params)
            while len(self.releases) > self.max_cached_releases:
                self.releases.pop(next(iter(self.releases)))
        return params.epsilon_spent


def consent_text(level: DpLevel) -> str:
    """User-facing description. NONE is never called differentially private."""
    if level is DpLevel.NONE:
        return (
            "No runtime noise is added. Privacy relies on typed masking, consent, "
            "encryption and audits; this channel is not differentially private."
        )
    eps_p = REFERENCE_PROFILES[level][0] if level in REFERENCE_PROFILES else None
    detail = f" (per-release epsilon {eps_p})" if eps_p is not None else ""
    return f"Local differential privacy is applied before sending{detail}."


@dataclass(frozen=True, slots=True)
class DpConfig:
    """Sender runtime-DP configuration for one capability."""

    level: DpLevel
    clip_norm: float
    sigma: float
    ledger: PrivacyLedger
    adjacency: Adjacency = Adjacency.FRAME

    def __post_init__(self) -> None:
        if self.level is DpLevel.NONE:
            msg = "DpConfig is only for non-NONE DP levels"
            raise ValueError(msg)
        if not all(math.isfinite(x) and x > 0 for x in (self.clip_norm, self.sigma)):
            msg = "clip norm and sigma must be finite and positive"
            raise ValueError(msg)
        if self.level in REFERENCE_PROFILES:
            sigma_ref = REFERENCE_PROFILES[self.level][1] * self.clip_norm
            if self.sigma < sigma_ref * (1 - 1e-9):
                msg = f"sigma below the {self.level.name} reference ({sigma_ref:.2f})"
                raise ValueError(msg)
