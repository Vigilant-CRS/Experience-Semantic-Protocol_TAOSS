# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""FALCON H1 evaluation of the reference neural decoder through the ESP replay contract (WP-089).

EXPLORATORY: public, de-identified human intracortical data (FALCON H1, DANDI
000954, CC BY 4.0); not a preregistered study. The question is narrow: does the
path *NWB replay adapter → binned spike counts → reference ridge/Wiener decoder*
recover attempted arm velocity, and how does it behave across days?

- **within day:** fit on the held-in ``calib`` sessions, score on held-in
  ``minival`` (same days, other trials);
- **drift:** the same frozen decoder on the later held-out days, with no
  recalibration;
- **recalibration:** per held-out day, fit on the first half of that day's
  data and score on the second half. Every recalibration gets a new decoder id;
- **controls:** time-shuffled spikes (must be near 0), and a constant
  predictor (0 by definition).

R² is variance-weighted over the 7 velocity dimensions, on the benchmark's
``eval_mask`` rows. Features are cached as ``.npz`` in ``ESP_FEATURE_CACHE``
(default ``~/.cache/esp-neural``), keyed by the file's SHA-256 from the
dataset manifest, so the NWB files are read only once.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import numpy as np
from numpy.typing import NDArray

from esp.adapters.neural.mapping import RidgeDecoder, TargetKind, lagged, r2_score
from esp.adapters.neural.nwb import NwbFile, timeseries_adapter, units_binned_adapter
from esp.adapters.physio.stream import concat
from esp.observation.model import Modality

F64 = NDArray[np.float64]
BIN_S = 0.02


@dataclass(frozen=True, slots=True)
class Session:
    name: str
    day: str
    split: str
    counts: F64
    velocity: F64
    mask: NDArray[np.bool_]


def _cache_dir() -> Path:
    d = Path(os.environ.get("ESP_FEATURE_CACHE", Path.home() / ".cache" / "esp-neural"))
    d.mkdir(parents=True, exist_ok=True)
    return d


def _file_key(path: Path, manifest: dict[str, Any]) -> str:
    rel = str(path.relative_to(path.parents[1]))
    entry = manifest.get("files", {}).get(rel)
    if entry is not None:
        return str(entry["sha256"])
    return hashlib.sha256(path.read_bytes()).hexdigest()  # pragma: no cover - unmanifested


def load_session(path: Path, manifest: dict[str, Any]) -> Session:
    cache = _cache_dir() / f"falcon-h1-{_file_key(path, manifest)[:32]}.npz"
    if cache.exists():
        z = np.load(cache)
        counts, vel, mask = z["counts"], z["velocity"], z["mask"].astype(bool)
    else:
        with NwbFile(path) as f:
            counts = concat(
                units_binned_adapter(
                    f, bin_width_s=BIN_S, grid_from="OpenLoopKinematics"
                ).read_all()
            ).values
            vel = concat(
                timeseries_adapter(
                    f, "OpenLoopKinematicsVelocity", modality=Modality.MOTION
                ).read_all()
            ).values
            mask = (
                concat(timeseries_adapter(f, "eval_mask", modality=Modality.BEHAVIOR).read_all())
                .values[:, 0]
                .astype(bool)
            )
        np.savez_compressed(cache, counts=counts, velocity=vel, mask=mask)
    stem = path.stem
    day = stem.split("_ses-")[1][:8]
    split = path.parent.name.removeprefix("sub-HumanPitt-")
    return Session(stem, day, split, counts, vel, mask)


def load_all(root: Path) -> list[Session]:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    return [load_session(p, manifest) for p in sorted(root.glob("*/*.nwb"))]


def features(s: Session, *, lags: int, tau_bins: float) -> F64:
    """Causal exponential smoothing of the counts, then lagged history within this session only."""
    x = s.counts
    if tau_bins > 0:
        a = np.exp(-1.0 / tau_bins)
        out = np.empty_like(x)
        acc = np.zeros(x.shape[1])
        for t in range(x.shape[0]):
            acc = a * acc + (1 - a) * x[t]
            out[t] = acc
        x = out
    return lagged(x, lags)


def _fit(
    zs: list[F64], ys: list[F64], masks: list[NDArray[np.bool_]], alpha: float, ids: list[str]
) -> RidgeDecoder:
    z = np.concatenate([zi[m] for zi, m in zip(zs, masks, strict=True)])
    y = np.concatenate([yi[m] for yi, m in zip(ys, masks, strict=True)])
    return RidgeDecoder(TargetKind.ATTEMPTED_MOVEMENT, lags=0, alpha=alpha).fit(
        z, y, session_ids=ids
    )


def _r2(dec: RidgeDecoder, z: F64, y: F64, sel: NDArray[np.bool_]) -> float:
    return r2_score(y[sel], dec.predict(z)[sel]) if sel.sum() > 10 else float("nan")


def _halves(m: NDArray[np.bool_], frac: float) -> tuple[NDArray[np.bool_], NDArray[np.bool_]]:
    cut = int(len(m) * frac)
    first, second = m.copy(), m.copy()
    first[cut:] = False
    second[:cut] = False
    return first, second


def _date(v: str) -> date:
    return date(int(v[:4]), int(v[4:6]), int(v[6:8]))


ALPHAS = (1.0, 10.0, 100.0, 1000.0, 10000.0)


def evaluate(root: Path, *, lags: int = 4, tau_bins: float = 3.0, seed: int = 0) -> dict[str, Any]:
    sessions = load_all(root)
    calib = [s for s in sessions if s.split == "held-in-calib"]
    minival = [s for s in sessions if s.split == "held-in-minival"]
    held_out = [s for s in sessions if s.split == "held-out-calib"]
    feat = {s.name: features(s, lags=lags, tau_bins=tau_bins) for s in sessions}
    # alpha chosen on held-in calib only: first 80 % of each session trains, last 20 % validates
    val = {}
    for a in ALPHAS:
        tr = [_halves(s.mask, 0.8)[0] for s in calib]
        dec = _fit(
            [feat[s.name] for s in calib], [s.velocity for s in calib], tr, a, ["alpha-select"]
        )
        val[a] = float(
            np.nanmean([_r2(dec, feat[s.name], s.velocity, _halves(s.mask, 0.8)[1]) for s in calib])
        )
    alpha = max(val, key=lambda a: val[a])
    dec = _fit(
        [feat[s.name] for s in calib],
        [s.velocity for s in calib],
        [s.mask for s in calib],
        alpha,
        [s.name for s in calib],
    )
    within = {s.day: _r2(dec, feat[s.name], s.velocity, s.mask) for s in minival}
    drift = {s.day: _r2(dec, feat[s.name], s.velocity, s.mask) for s in held_out}
    recal, recal_ids = {}, {}
    for s in held_out:
        first, second = _halves(s.mask, 0.5)
        d = _fit(
            [feat[c.name] for c in calib] + [feat[s.name]],
            [c.velocity for c in calib] + [s.velocity],
            [c.mask for c in calib] + [first],
            alpha,
            [c.name for c in calib] + [s.name + ":first-half"],
        )
        recal[s.day] = _r2(d, feat[s.name], s.velocity, second)
        recal_ids[s.day] = d.decoder_id
    frozen_second = {
        s.day: _r2(dec, feat[s.name], s.velocity, _halves(s.mask, 0.5)[1]) for s in held_out
    }
    rng = np.random.default_rng(seed)
    shuffled = [
        _r2(dec, feat[s.name][rng.permutation(len(s.counts))], s.velocity, s.mask) for s in minival
    ]
    first_day = min(s.day for s in sessions)

    def days_after(day: str) -> int:
        return (_date(day) - _date(first_day)).days

    def mean(v: dict[str, float]) -> float:
        return round(float(np.nanmean(list(v.values()))), 4)

    return {
        "label": "EXPLORATORY: FALCON H1 public human iBCI data; not preregistered evidence",
        "dataset": "DANDI:000954 (FALCON H1), CC BY 4.0",
        "decoder": {
            "kind": "ridge/Wiener on causally smoothed binned spike counts",
            "bin_s": BIN_S,
            "lags": lags,
            "tau_bins": tau_bins,
            "alpha": alpha,
            "alpha_validation_r2": {str(k): round(v, 4) for k, v in val.items()},
            "id": dec.decoder_id,
        },
        "units": int(calib[0].counts.shape[1]),
        "train_bins_masked": int(sum(s.mask.sum() for s in calib)),
        "within_day_r2": {k: round(v, 4) for k, v in sorted(within.items())},
        "held_out_frozen_r2": {
            f"{k} (+{days_after(k)} d)": round(v, 4) for k, v in sorted(drift.items())
        },
        "held_out_second_half_frozen_r2": {
            k: round(v, 4) for k, v in sorted(frozen_second.items())
        },
        "held_out_second_half_recalibrated_r2": {k: round(v, 4) for k, v in sorted(recal.items())},
        "recalibration_decoder_ids": recal_ids,
        "shuffled_control_r2_mean": round(float(np.nanmean(shuffled)), 4),
        "summary": {
            "within_day_mean": mean(within),
            "held_out_frozen_mean": mean(drift),
            "held_out_second_half_frozen_mean": mean(frozen_second),
            "held_out_second_half_recalibrated_mean": mean(recal),
        },
    }
