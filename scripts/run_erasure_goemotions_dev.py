# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Typing plus erasure on GoEmotions train -> dev. EXPLORATORY.

Usage: python scripts/run_erasure_goemotions_dev.py [--out <json>]

The official GoEmotions test split was used once for the preregistered H2 study and is
**not** used here at all. Only train (fitting) and dev (evaluation) labels are read. The
encoders are the frozen H2 configuration (``TAOSS_CONFIG``); the monolithic encoder uses the
same architecture and budget.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

import numpy as np  # noqa: E402

from esp.bench.erasure_methods import VARIANTS, variants  # noqa: E402
from esp.bench.goemotions_study import (  # noqa: E402
    TAOSS_CONFIG,
    ProbeConfig,
    Released,
    device_name,
    embed,
    encode,
    evaluate_released,
    labels,
    load,
    mean_released,
    summarize,
    train_encoder,
)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--out", type=Path, default=ROOT / "artifacts/research/erasure_goemotions_dev.json"
    )
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    args = ap.parse_args(argv)
    root = Path(os.environ.get("ESP_DATA_DIR", ROOT / "data" / "external")) / "goemotions"
    cache = Path(os.environ.get("ESP_FEATURE_CACHE", Path.home() / ".cache" / "esp-neural"))
    device = device_name()
    t0 = time.time()
    data = load(root, unblind=False)  # the test split stays unlabelled and is never used
    train, dev = data["train"], data["dev"]
    x_tr, x_dev = embed(train.texts, cache, device), embed(dev.texts, cache, device)
    emo_tr, ctx_tr = labels(train)
    emo_dev, ctx_dev = labels(dev)
    n_ctx = int(ctx_tr.max()) + 1
    d = TAOSS_CONFIG.d_released
    per: dict[str, list[Released]] = {v: [] for v in VARIANTS}
    for seed in args.seeds:
        enc_t = train_encoder(
            x_tr, emo_tr, ctx_tr, n_ctx, typed=True, cfg=TAOSS_CONFIG, seed=seed, device=device
        )
        enc_m = train_encoder(
            x_tr, emo_tr, ctx_tr, n_ctx, typed=False, cfg=TAOSS_CONFIG, seed=seed, device=device
        )
        typed = (encode(enc_t, x_tr, device)[:, :d], encode(enc_t, x_dev, device)[:, :d])
        mono = (encode(enc_m, x_tr, device)[:, :d], encode(enc_m, x_dev, device)[:, :d])
        reps = variants(
            typed,
            mono,
            (x_tr, x_dev),
            emo_tr,
            np.where(ctx_tr >= 0, ctx_tr, 0),
            seed=seed,
            training_data_id="goemotions:train",
        )
        for v, (r_tr, r_ev) in reps.items():
            per[v].append(
                evaluate_released(
                    r_tr,
                    r_ev,
                    train,
                    x_tr,
                    x_dev,
                    n_ctx,
                    cfg=ProbeConfig(),
                    seed=seed,
                    device=device,
                )
            )
        print("seed", seed, "done", round(time.time() - t0), "s", flush=True)
    results = {v: summarize(mean_released(r), emo_dev, ctx_dev) for v, r in per.items()}
    out = {
        "label": "EXPLORATORY: typing plus erasure, GoEmotions train -> dev; test split unused",
        "device": device,
        "seeds": args.seeds,
        "encoder": "TAOSS_CONFIG of the GoEmotions H2 preregistration (frozen)",
        "results": results,
        "runtime_s": round(time.time() - t0, 1),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    for v, r in results.items():
        leak, acc, fid = r["leak_auroc"], r["ctx_acc"], r["fidelity_r2"]
        print(f"{v:14s} leak {leak:.3f}  ctx {acc:.3f}  fidelity {fid:.3f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
