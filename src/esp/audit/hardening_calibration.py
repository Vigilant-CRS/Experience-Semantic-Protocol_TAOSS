# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Experiment that derives the ``esp-covert-hardening-v1`` defaults (GAP-015).

1. Train the reference TAOSS encoder (``esp.training``) on the synthetic world.
2. Encode **honest streams**: inputs smoothed along time with AR(1) coefficients
   ``rho`` in ``{0, 0.9, 0.98}`` (white to very smooth); first half = calibration,
   second half = evaluation.
3. :func:`~esp.audit.hardening_profile.calibrate` the bands on the calibration halves.
4. Measure the per-frame and per-window false-positive rate on the evaluation halves.
5. Run five **covert senders** that carry one bit per window on top of an honest
   stream and measure the window detection rate:

   - ``out_of_band``: an excursion outside the honest TEM range;
   - ``sparsity``: on/off gating of half the KNO coordinates;
   - ``phase``: a period-2 TEM codebook;
   - ``offset``: a constant-step TEM code ramp;
   - ``sub_step``: code parity (less than one INT8 step, in band).

   The bands cannot see ``sub_step`` by construction. For that sender, the experiment
   measures bit recovery after randomized quantization and picks the smallest
   ``sigma_steps`` that drives it to chance.

The results describe a synthetic world and a small CPU encoder. The defaults are
therefore starting values to be re-derived for every production encoder.
"""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
import torch

from esp.audit.hardening_profile import (
    F64,
    CovertHardeningProfile,
    calibrate,
    check_stream,
    int8_codes,
    randomized_quantize_sigma,
)
from esp.training.encoder import type_name
from esp.training.harness import DataConfig, TrainConfig, Trainer

RHOS = (0.0, 0.9, 0.98)
SIGMAS = (0.0, 0.1, 0.25, 0.5, 0.75, 1.0)
CHANCE_TOLERANCE = 0.05


@dataclass(frozen=True, slots=True)
class CalibrationConfig:
    n: int = 6000
    steps: int = 200
    seed: int = 0
    window: int = 16
    quantile: float = 0.0005
    margin: float = 0.1


def _ar1(x: F64, rho: float) -> F64:
    out = np.empty_like(x)
    out[0] = x[0]
    c = np.sqrt(1 - rho**2)
    for t in range(1, x.shape[0]):
        out[t] = rho * out[t - 1] + c * x[t]
    return out


def honest_streams(trainer: Trainer) -> dict[float, dict[str, F64]]:
    trainer.model.eval()
    out = {}
    with torch.no_grad():
        for rho in RHOS:
            inputs = {
                m: torch.from_numpy(_ar1(x.numpy().astype(np.float64), rho).astype(np.float32))
                for m, x in trainer.data.inputs.items()
            }
            lat = trainer.model(inputs)
            out[rho] = {type_name(t): z.numpy().astype(np.float64) for t, z in lat.items()}
    return out


def _windows_flagged(flags: np.ndarray, window: int) -> np.ndarray:
    n = flags.size // window
    return flags[: n * window].reshape(n, window).any(axis=1)


def _bits(n_windows: int, rng: np.random.Generator) -> np.ndarray:
    return rng.integers(0, 2, size=n_windows).astype(bool)


def covert_sender(
    kind: str,
    stream: dict[str, F64],
    profile: CovertHardeningProfile,
    bits: np.ndarray,
    window: int,
) -> dict[str, F64]:
    """Honest stream with one bit per window embedded by the given covert technique."""
    s = {k: v.copy() for k, v in stream.items()}
    tem = s["TEM"]
    lo, hi = np.asarray(profile.tem_lo), np.asarray(profile.tem_hi)
    for w, bit in enumerate(bits):
        if not bit:
            continue
        sl = slice(w * window, (w + 1) * window)
        if kind == "out_of_band":
            tem[sl, 0] = hi[0] + 0.5 * (hi[0] - lo[0])
        elif kind == "sparsity":
            kno = s["KNO"]
            kno[sl, : kno.shape[1] // 2] = 0.0
        elif kind == "phase":
            a, b = tem[sl.start].copy(), tem[sl.start + 1].copy()
            tem[sl] = np.where((np.arange(window) % 2 == 0)[:, None], a, b)
        elif kind == "offset":
            # codes controlled directly: a fixed peak keeps the INT8 scale constant
            peak = float(np.max(np.abs(tem[sl.start])))
            step = peak / 127.0
            base = np.rint(tem[sl.start] / step)
            base[0] = 127.0
            ramp = base + np.arange(window)[:, None] * np.r_[0.0, np.ones(tem.shape[1] - 1)]
            ramp[:, 1:] = np.clip(ramp[:, 1:], -100, 100)
            tem[sl] = ramp * step
        else:
            msg = f"unknown covert sender {kind}"
            raise ValueError(msg)
    return s


def sub_step_recovery(tem: F64, sigma_steps: float, rng: np.random.Generator) -> float:
    """Accuracy of a sub-step parity code (one bit per frame) after randomized quantization."""
    bits = rng.integers(0, 2, size=tem.shape[0])
    peak = np.max(np.abs(tem), axis=1, keepdims=True)
    s = np.maximum(peak / 127.0, 2.0**-24)
    codes = int8_codes(tem)
    parity = np.sum(codes, axis=1) % 2
    # move one non-peak coordinate by one step towards the desired parity
    idx = np.argmin(np.abs(tem), axis=1)
    fix = parity != bits
    direction = np.where(tem[np.arange(tem.shape[0]), idx] >= 0, -1, 1)
    codes[np.arange(tem.shape[0]), idx] += np.where(fix, direction, 0)
    stego = codes.astype(np.float64) * s
    received = randomized_quantize_sigma(stego, sigma_steps, rng)
    recovered = np.sum(np.rint(received / s), axis=1).astype(np.int64) % 2
    return float(np.mean(recovered == bits))


def run(cfg: CalibrationConfig) -> tuple[CovertHardeningProfile, dict[str, Any]]:
    """Train, calibrate on honest streams, evaluate FPR and covert-sender detection."""
    with tempfile.TemporaryDirectory() as out:
        trainer = Trainer(
            TrainConfig(
                steps=cfg.steps,
                seed=cfg.seed,
                checkpoint_every=10**9,
                data=DataConfig(n=cfg.n, seed=cfg.seed + 1),
            ),
            Path(out),
        )
        trainer.train()
        streams = honest_streams(trainer)
    half = cfg.n // 2
    calib = {k: np.concatenate([streams[r][k][:half] for r in RHOS]) for k in streams[RHOS[0]]}
    rng = np.random.default_rng(cfg.seed)
    tem_eval = streams[0.9]["TEM"][half:]
    recovery = {sig: sub_step_recovery(tem_eval, sig, rng) for sig in SIGMAS}
    sigma = next(
        (sig for sig in SIGMAS if abs(recovery[sig] - 0.5) <= CHANCE_TOLERANCE), SIGMAS[-1]
    )
    utility_cost = {
        sig: float(
            np.mean((randomized_quantize_sigma(tem_eval, sig, rng) - tem_eval) ** 2)
            / np.mean(tem_eval**2)
        )
        for sig in SIGMAS
    }
    profile = calibrate(
        calib,
        quantile=cfg.quantile,
        margin=cfg.margin,
        sigma_steps=sigma,
        provenance={
            "experiment": "esp.audit.hardening_calibration",
            "encoder": "esp.training reference encoder (synthetic world, CPU)",
            "config": f"n={cfg.n} steps={cfg.steps} seed={cfg.seed} rhos={list(RHOS)}",
            "status": "EXPERIMENTAL defaults; re-derive per production encoder",
        },
    )
    fpr = {}
    for rho in RHOS:
        ev = {k: v[half:] for k, v in streams[rho].items()}
        rep = check_stream(profile, ev)
        flags = rep.flagged()
        fpr[str(rho)] = {
            "frame_fpr": float(flags.mean()),
            "window_fpr": float(_windows_flagged(flags, cfg.window).mean()),
            "by_check": rep.summary(),
        }
    base = {k: v[half:] for k, v in streams[0.9].items()}
    n_windows = base["TEM"].shape[0] // cfg.window
    detection = {}
    for kind in ("out_of_band", "sparsity", "phase", "offset"):
        bits = _bits(n_windows, rng)
        flags = _windows_flagged(
            check_stream(profile, covert_sender(kind, base, profile, bits, cfg.window)).flagged(),
            cfg.window,
        )
        detection[kind] = {
            "detected_bit1_windows": float(flags[bits].mean()),
            "flagged_bit0_windows": float(flags[~bits].mean()),
        }
    report = {
        "label": "EXPLORATORY: synthetic world, small CPU encoder; not evidence of safety",
        "config": {
            "n": cfg.n,
            "steps": cfg.steps,
            "seed": cfg.seed,
            "window": cfg.window,
            "quantile": cfg.quantile,
            "margin": cfg.margin,
            "rhos": list(RHOS),
        },
        "honest_false_positives": fpr,
        "covert_detection": detection,
        "sub_step": {
            "bit_recovery_by_sigma_steps": {str(k): v for k, v in recovery.items()},
            "relative_mse_by_sigma_steps": {str(k): v for k, v in utility_cost.items()},
            "chosen_sigma_steps": sigma,
            "note": "in-band codes pass every band by construction; left to the V-information "
            "audit and to randomized quantization in the trusted sender stack",
        },
        "profile": json.loads(profile.to_json()),
        "profile_digest": profile.digest(),
    }
    return profile, report
