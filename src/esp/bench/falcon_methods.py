# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Method development for drift-robust decoding on FALCON H1. EXPLORATORY (claims level 4 prep).

FALCON H1 has already been looked at (``neural_falcon``), so nothing here is evidence.
Its purpose is to choose, *before* the preregistered FALCON H2 study, a decoder family and
an adaptation procedure, with the same protocol that the preregistration fixes.

Protocol:

- **train:** held-in ``calib`` sessions. The last 20 % of each session is the
  validation part (early stopping, hyper-parameter choice);
- **within day:** held-in ``minival`` sessions (same days, other trials);
- **held-out days:** each ``held-out-calib`` session is split in time. The first 25 %
  is the *calibration block* and the last 75 % is the *test part*:
  - unsupervised methods may use the block's neural data but never its labels;
  - recalibration methods may also use the block's labels (a labelled budget of
    25 %);
  - every held-out score uses only the test part.

R² is variance-weighted over the 7 velocity dimensions on ``eval_mask`` rows. It is
averaged per recording day (days with two sessions are averaged first) and then
across days.
"""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np

from esp.bench.neural_decoders import (
    F64,
    Coral,
    DayStats,
    GruConfig,
    GruDecoder,
    Mask,
    Ridge,
    hardware_record,
    lag_stack,
    preprocess,
    r2_variance_weighted,
)
from esp.bench.neural_falcon import Session, load_all

VAL_FRAC = 0.8
BLOCK_FRAC = 0.25


def _cut(m: Mask, frac: float) -> tuple[Mask, Mask]:
    k = int(len(m) * frac)
    a, b = m.copy(), m.copy()
    a[k:] = False
    b[:k] = False
    return a, b


@dataclass
class Prepared:
    session: Session
    x: F64
    """Preprocessed (not yet normalised) features."""


def _day_of(sessions: list[Session]) -> dict[str, list[Session]]:
    out: dict[str, list[Session]] = {}
    for s in sessions:
        out.setdefault(s.day, []).append(s)
    return out


def _mean_by_day(scores: dict[str, list[float]]) -> tuple[dict[str, float], float]:
    per_day = {d: float(np.nanmean(v)) for d, v in sorted(scores.items())}
    return per_day, float(np.nanmean(list(per_day.values())))


def evaluate(  # noqa: PLR0915 - one flat protocol, kept readable in order
    root: Path,
    *,
    sqrt: bool = True,
    tau_bins: float = 10.0,
    lags: int = 6,
    stride: int = 3,
    alphas: tuple[float, ...] = (100.0, 1000.0, 10000.0),
    coral_shrink: float = 0.5,
    gru: GruConfig | None = None,
    run_gru: bool = True,
    seed: int = 0,
    log: Callable[[str], None] = print,
) -> dict[str, Any]:
    t0 = time.time()
    sessions = load_all(root)
    calib = [s for s in sessions if s.split == "held-in-calib"]
    minival = [s for s in sessions if s.split == "held-in-minival"]
    held_out = [s for s in sessions if s.split == "held-out-calib"]
    feat = {s.name: preprocess(s.counts, sqrt=sqrt, tau_bins=tau_bins) for s in sessions}

    # per-day statistics: training days use their calib sessions; held-out sessions use
    # only their own calibration block (unlabelled)
    day_stats: dict[str, DayStats] = {
        d: DayStats.of(np.concatenate([feat[s.name] for s in ss]))
        for d, ss in _day_of(calib).items()
    }
    block_stats = {
        s.name: DayStats.of(feat[s.name][: int(len(s.counts) * BLOCK_FRAC)]) for s in held_out
    }

    def norm(s: Session, mode: str) -> F64:
        x = feat[s.name]
        if mode == "raw":
            return x
        st = block_stats[s.name] if s.split == "held-out-calib" else day_stats[s.day]
        z = st.apply(x)
        if mode == "coral" and s.split == "held-out-calib":
            k = int(len(s.counts) * BLOCK_FRAC)
            return coral.transform(z[:k], z)
        return z

    train_z = np.concatenate([day_stats[s.day].apply(feat[s.name]) for s in calib])
    coral = Coral.fit_reference(train_z, coral_shrink)

    tr_masks = [_cut(s.mask, VAL_FRAC) for s in calib]
    results: dict[str, Any] = {}

    def score_all(predict: Callable[[Session, F64], F64], mode: str, name: str) -> None:
        within: dict[str, list[float]] = {}
        for s in minival:
            within.setdefault(s.day, []).append(
                r2_variance_weighted(s.velocity[s.mask], predict(s, norm(s, mode))[s.mask])
            )
        held: dict[str, list[float]] = {}
        for s in held_out:
            test = _cut(s.mask, BLOCK_FRAC)[1]
            held.setdefault(s.day, []).append(
                r2_variance_weighted(s.velocity[test], predict(s, norm(s, mode))[test])
            )
        w_days, w_mean = _mean_by_day(within)
        h_days, h_mean = _mean_by_day(held)
        results[name] = {
            "within_day_mean": round(w_mean, 4),
            "held_out_mean": round(h_mean, 4),
            "within_day": {k: round(v, 4) for k, v in w_days.items()},
            "held_out": {k: round(v, 4) for k, v in h_days.items()},
        }
        log(f"{name:28s} within {w_mean:.4f}  held-out {h_mean:.4f}")

    # --- ridge: alpha chosen on the held-in validation parts only -------------------------
    for mode in ("raw", "daynorm", "coral"):
        xs = [lag_stack(norm(s, mode), lags, stride) for s in calib]
        val_r2 = {}
        for a in alphas:
            r = Ridge(a).fit(
                np.concatenate([x[m[0]] for x, m in zip(xs, tr_masks, strict=True)]),
                np.concatenate([s.velocity[m[0]] for s, m in zip(calib, tr_masks, strict=True)]),
            )
            val_r2[a] = float(
                np.mean(
                    [
                        r2_variance_weighted(s.velocity[m[1]], r.predict(x)[m[1]])
                        for s, x, m in zip(calib, xs, tr_masks, strict=True)
                    ]
                )
            )
        alpha = max(val_r2, key=lambda k: val_r2[k])
        ridge = Ridge(alpha).fit(
            np.concatenate([x[s.mask] for x, s in zip(xs, calib, strict=True)]),
            np.concatenate([s.velocity[s.mask] for s in calib]),
        )

        def ridge_predict(_s: Session, x: F64, r: Ridge = ridge) -> F64:
            return r.predict(lag_stack(x, lags, stride))

        score_all(ridge_predict, mode, f"ridge_{mode}")
        results[f"ridge_{mode}"]["alpha"] = alpha
        # recalibration with the labelled block (budget 25 %), same alpha
        if mode == "daynorm":
            recal: dict[str, list[float]] = {}
            for s in held_out:
                blk, test = _cut(s.mask, BLOCK_FRAC)
                xz = lag_stack(norm(s, mode), lags, stride)
                n_train = sum(int(s2.mask.sum()) for s2 in calib)
                weights = np.concatenate(
                    [np.ones(n_train), np.full(int(blk.sum()), n_train / max(int(blk.sum()), 1))]
                )  # the labelled block weighs as much as all training days together
                rr = Ridge(alpha).fit(
                    np.concatenate(
                        [*(x[s2.mask] for x, s2 in zip(xs, calib, strict=True)), xz[blk]]
                    ),
                    np.concatenate([*(s2.velocity[s2.mask] for s2 in calib), s.velocity[blk]]),
                    weights,
                )
                recal.setdefault(s.day, []).append(
                    r2_variance_weighted(s.velocity[test], rr.predict(xz)[test])
                )
            d, m = _mean_by_day(recal)
            results["ridge_daynorm_recal25"] = {
                "held_out_mean": round(m, 4),
                "held_out": {k: round(v, 4) for k, v in d.items()},
            }
            log(f"{'ridge_daynorm_recal25':28s} held-out {m:.4f}")
            # control: time-shuffled neural input on the within-day test
            rng = np.random.default_rng(seed)
            shuf = [
                r2_variance_weighted(
                    s.velocity[s.mask],
                    ridge.predict(
                        lag_stack(norm(s, mode)[rng.permutation(len(s.counts))], lags, stride)
                    )[s.mask],
                )
                for s in minival
            ]
            results["control_shuffled_ridge_daynorm"] = round(float(np.mean(shuf)), 4)

    # --- GRU --------------------------------------------------------------------------------
    if run_gru:
        cfg = gru or GruConfig(seed=seed)
        for mode in ("raw", "daynorm"):
            xs = [norm(s, mode) for s in calib]
            dec = GruDecoder(n_in=xs[0].shape[1], n_out=7, cfg=cfg).fit(
                xs,
                [s.velocity for s in calib],
                [m[0] for m in tr_masks],
                val=(xs, [s.velocity for s in calib], [m[1] for m in tr_masks]),
            )
            modes = ("raw",) if mode == "raw" else ("daynorm", "coral")

            def gru_predict(_s: Session, x: F64, d: GruDecoder = dec) -> F64:
                return d.predict(x)

            for mode_name in modes:
                score_all(gru_predict, mode_name, f"gru_{mode_name}")
                results[f"gru_{mode_name}"]["epochs"] = len(dec.history)
            if mode == "daynorm":
                recal = {}
                for s in held_out:
                    blk, test = _cut(s.mask, BLOCK_FRAC)
                    ft = GruDecoder(
                        n_in=dec.n_in,
                        n_out=7,
                        cfg=dataclasses.replace(cfg, epochs=10, lr=cfg.lr / 4),
                    )
                    ft.fit(
                        [*xs, norm(s, mode)],
                        [*(s2.velocity for s2 in calib), s.velocity],
                        [*(s2.mask for s2 in calib), blk],
                    )
                    recal.setdefault(s.day, []).append(
                        r2_variance_weighted(s.velocity[test], ft.predict(norm(s, mode))[test])
                    )
                d, m2 = _mean_by_day(recal)
                results["gru_daynorm_recal25"] = {
                    "held_out_mean": round(m2, 4),
                    "held_out": {k: round(v, 4) for k, v in d.items()},
                }
                log(f"{'gru_daynorm_recal25':28s} held-out {m2:.4f}")
    return {
        "label": "EXPLORATORY method development on FALCON H1 (already seen); not evidence",
        "dataset": "DANDI:000954 (FALCON H1), CC BY 4.0",
        "protocol": {
            "train": "held-in calib (last 20 % of each session = validation)",
            "within_day": "held-in minival",
            "held_out": "held-out calib: first 25 % = calibration block, last 75 % = test",
            "aggregation": "weighted R2 per session (eval_mask), mean per day, then of days",
        },
        "features": {"sqrt": sqrt, "tau_bins": tau_bins, "ridge_lags": lags, "lag_stride": stride},
        "coral_shrink": coral_shrink,
        "gru": dataclasses.asdict(gru or GruConfig(seed=seed)) if run_gru else None,
        "hardware": hardware_record(),
        "runtime_s": round(time.time() - t0, 1),
        "methods": results,
    }
