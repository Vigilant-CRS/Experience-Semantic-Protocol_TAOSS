# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Covert-channel hardening profile ``esp-covert-hardening-v1`` (GAP-015; V13 covert budget).

V13 names the hardening constraints but gives no values. This module makes them a
pinned, digestible profile and derives the defaults **experimentally**
(``scripts/calibrate_hardening.py``), from honest encoder streams:

- **TEM band:** per-coordinate band ``[lo_i, hi_i]`` = empirical quantiles
  of honest TEM latents, widened by a margin;
- **forbidden TEM codebook patterns** on the transmitted INT8 codes:
  - ``all_zero``: a frame whose codes are all zero;
  - ``repeating_phase``: the code vector repeats with a period
    ``2 <= p <= max_period`` for ``run`` consecutive frames;
  - ``structured_offset``: a constant, non-zero per-frame code delta for
    ``run`` consecutive frames.

  A constant TEM (period 1, delta 0) is **allowed**, because a paused
  stream is legitimate;
- **gating sparsity band** per type: share of near-zero coordinates per frame;
- **randomized quantization strength** ``sigma_steps``: Gaussian noise in
  units of the INT8 step before rounding, chosen as the smallest value that
  drives a sub-step code to chance.

These constraints raise the cost of steganography; they do not establish
safety. Only the V-information audit (``esp.audit.suite``) can attest that.
In-band, low-amplitude codes pass the bands by construction and are left to
the audit.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Final

import numpy as np
from numpy.typing import NDArray

F64 = NDArray[np.float64]
I64 = NDArray[np.int64]
PROFILE_NAME: Final = "esp-covert-hardening-v1"


@dataclass(frozen=True, slots=True)
class CovertHardeningProfile:
    tem_lo: tuple[float, ...]
    tem_hi: tuple[float, ...]
    sparsity_bands: Mapping[str, tuple[float, float]]
    """Type name -> admitted share of near-zero coordinates per frame."""
    sigma_steps: float
    max_period: int = 4
    run: int = 8
    eps: float = 1e-6
    provenance: Mapping[str, str] = field(default_factory=dict)
    name: str = PROFILE_NAME
    version: str = "1.0.0"

    def __post_init__(self) -> None:
        if len(self.tem_lo) != len(self.tem_hi) or not self.tem_lo:
            msg = "TEM band needs matching, non-empty lo/hi vectors"
            raise ValueError(msg)
        if any(lo >= hi for lo, hi in zip(self.tem_lo, self.tem_hi, strict=True)):
            msg = "every TEM band must satisfy lo < hi"
            raise ValueError(msg)
        for t, (lo, hi) in self.sparsity_bands.items():
            if not 0.0 <= lo <= hi <= 1.0:
                msg = f"sparsity band for {t} must satisfy 0 <= lo <= hi <= 1"
                raise ValueError(msg)
        if self.sigma_steps < 0 or self.max_period < 2 or self.run < 3:
            msg = "sigma_steps >= 0, max_period >= 2 and run >= 3 are required"
            raise ValueError(msg)

    def to_json(self) -> str:
        d = asdict(self)
        d["sparsity_bands"] = {k: list(v) for k, v in sorted(self.sparsity_bands.items())}
        d["provenance"] = dict(sorted(self.provenance.items()))
        return json.dumps(d, sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        return hashlib.blake2b(self.to_json().encode(), digest_size=32).hexdigest()

    @classmethod
    def from_json(cls, raw: str) -> CovertHardeningProfile:
        d = json.loads(raw)
        d["tem_lo"], d["tem_hi"] = tuple(d["tem_lo"]), tuple(d["tem_hi"])
        d["sparsity_bands"] = {
            k: (float(v[0]), float(v[1])) for k, v in d["sparsity_bands"].items()
        }
        return cls(**d)


# --- checks -------------------------------------------------------------------------------------


def int8_codes(x: F64) -> I64:
    """Per-frame INT8_SYM codes as transmitted (scale = peak / 127, round half to even)."""
    peak = np.max(np.abs(x), axis=1, keepdims=True)
    s = np.maximum(peak / 127.0, 2.0**-24)
    return np.clip(np.rint(x / s), -127, 127).astype(np.int64)


def _runs(flags: NDArray[np.bool_], run: int) -> NDArray[np.bool_]:
    """Mark every frame that belongs to a run of >= ``run`` consecutive True flags."""
    out = np.zeros_like(flags)
    start = None
    for i, f in enumerate([*flags.tolist(), False]):
        if f and start is None:
            start = i
        elif not f and start is not None:
            if i - start >= run:
                out[start:i] = True
            start = None
    return out


def tem_pattern_violations(
    codes: I64, *, max_period: int, run: int
) -> dict[str, NDArray[np.bool_]]:
    """Per-frame flags for each forbidden pattern on INT8 TEM codes, shape (T, d)."""
    n = codes.shape[0]
    all_zero = np.all(codes == 0, axis=1)
    phase = np.zeros(n, dtype=bool)
    for p in range(2, max_period + 1):
        if n <= p:
            break
        same = np.zeros(n, dtype=bool)
        same[p:] = np.all(codes[p:] == codes[:-p], axis=1)
        # a genuine period p excludes shorter periods that are really constant runs
        not_const = np.zeros(n, dtype=bool)
        not_const[1:] = np.any(codes[1:] != codes[:-1], axis=1)
        phase |= _runs(same & not_const, run)
    offset = np.zeros(n, dtype=bool)
    if n > 2:
        d = np.diff(codes, axis=0)
        const = np.zeros(n, dtype=bool)
        const[2:] = np.all(d[1:] == d[:-1], axis=1) & np.any(d[1:] != 0, axis=1)
        offset = _runs(const, run)
    return {"all_zero": all_zero, "repeating_phase": phase, "structured_offset": offset}


@dataclass(frozen=True, slots=True)
class HardeningReport:
    frames: int
    tem_band: NDArray[np.bool_]
    patterns: Mapping[str, NDArray[np.bool_]]
    sparsity: Mapping[str, NDArray[np.bool_]]

    def flagged(self) -> NDArray[np.bool_]:
        out = self.tem_band.copy()
        for v in (*self.patterns.values(), *self.sparsity.values()):
            out |= v
        return out

    def summary(self) -> dict[str, int]:
        s = {"tem_band": int(self.tem_band.sum())}
        s |= {f"pattern:{k}": int(v.sum()) for k, v in self.patterns.items()}
        s |= {f"sparsity:{k}": int(v.sum()) for k, v in self.sparsity.items()}
        return s


def check_stream(
    profile: CovertHardeningProfile, latents: Mapping[str, F64], tem_key: str = "TEM"
) -> HardeningReport:
    """Apply every hardening check to a time-ordered stream of frames (one row per frame)."""
    tem = latents[tem_key]
    lo, hi = np.asarray(profile.tem_lo), np.asarray(profile.tem_hi)
    if tem.shape[1] != lo.size:
        msg = "TEM dimension does not match the profile"
        raise ValueError(msg)
    band = np.any((tem < lo) | (tem > hi), axis=1)
    patterns = tem_pattern_violations(
        int8_codes(tem), max_period=profile.max_period, run=profile.run
    )
    sparsity = {}
    for t, (slo, shi) in profile.sparsity_bands.items():
        if t in latents:
            share = np.mean(np.abs(latents[t]) <= profile.eps, axis=1)
            sparsity[t] = (share < slo) | (share > shi)
    return HardeningReport(tem.shape[0], band, patterns, sparsity)


def randomized_quantize_sigma(x: F64, sigma_steps: float, rng: np.random.Generator) -> F64:
    """V13 ``Z^q = Q(Z + xi)``, ``xi ~ N(0, (sigma_steps * s)^2)`` on the per-frame INT8 grid."""
    peak = np.max(np.abs(x), axis=1, keepdims=True)
    s = np.maximum(peak / 127.0, 2.0**-24)
    noisy = x + rng.normal(size=x.shape) * sigma_steps * s
    out: F64 = np.clip(np.rint(noisy / s), -127, 127) * s
    return out


# --- calibration --------------------------------------------------------------------------------


def calibrate(
    honest: Mapping[str, F64],
    *,
    tem_key: str = "TEM",
    quantile: float = 0.0005,
    margin: float = 0.1,
    sigma_steps: float,
    provenance: Mapping[str, str] | None = None,
    eps: float = 1e-6,
) -> CovertHardeningProfile:
    """Bands from honest frames: quantiles ``[q, 1-q]`` widened by ``margin`` x range."""
    tem = honest[tem_key]
    qlo, qhi = np.quantile(tem, quantile, axis=0), np.quantile(tem, 1 - quantile, axis=0)
    width = qhi - qlo
    bands = {}
    for t, z in honest.items():
        share = np.mean(np.abs(z) <= eps, axis=1)
        slo, shi = float(np.quantile(share, quantile)), float(np.quantile(share, 1 - quantile))
        pad = margin * max(shi - slo, 1.0 / z.shape[1])
        bands[t] = (max(0.0, slo - pad), min(1.0, shi + pad))
    return CovertHardeningProfile(
        tem_lo=tuple(float(v) for v in qlo - margin * width),
        tem_hi=tuple(float(v) for v in qhi + margin * width),
        sparsity_bands=bands,
        sigma_steps=sigma_steps,
        eps=eps,
        provenance=dict(provenance or {}),
    )


# --- frozen defaults and a streaming guard --------------------------------------------------------

_DEFAULT_PATH: Final = Path(__file__).with_name(f"{PROFILE_NAME}.json")


def default_profile() -> CovertHardeningProfile:
    """The frozen v1 defaults from ``scripts/calibrate_hardening.py`` (EXPERIMENTAL values)."""
    return CovertHardeningProfile.from_json(_DEFAULT_PATH.read_text(encoding="utf-8"))


class StreamGuard:
    """Sender-side check before transmission (V13: the encoder rejects forbidden patterns).

    Keeps just enough TEM history to detect the patterns; ``admit`` returns the
    violated checks for the new frame (empty = send).
    """

    def __init__(self, profile: CovertHardeningProfile) -> None:
        self.profile = profile
        self._tem: list[F64] = []
        self._keep = profile.run + profile.max_period + 1

    def admit(self, frame: Mapping[str, F64]) -> list[str]:
        p = self.profile
        tem = np.asarray(frame["TEM"], dtype=np.float64).reshape(1, -1)
        history = np.concatenate([*self._tem, tem]) if self._tem else tem
        rep = check_stream(p, {**{k: np.reshape(v, (1, -1)) for k, v in frame.items()}, "TEM": tem})
        out = [k for k, v in rep.summary().items() if v and not k.startswith("pattern:")]
        pats = tem_pattern_violations(int8_codes(history), max_period=p.max_period, run=p.run)
        out += [f"pattern:{k}" for k, v in pats.items() if v[-1]]
        if not out:
            self._tem = [*self._tem, tem][-self._keep :]
        return out
