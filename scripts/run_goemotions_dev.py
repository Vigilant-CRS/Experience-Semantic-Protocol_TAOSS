# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GoEmotions H2 method development on train → dev. EXPLORATORY; the test split stays blinded.

Usage: python scripts/run_goemotions_dev.py [--out artifacts/research/goemotions_dev.json]

Embeds all three splits (test texts only as unlabelled inputs) and compares every method
on the official dev split. It also selects the TAOSS penalty setting by a fixed rule:
the lowest dev leakage among settings whose dev subreddit accuracy is within
``DELTA`` of the monolithic baseline. The selected setting is then frozen as
``TAOSS_CONFIG`` in the preregistration.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from esp.bench.goemotions_study import (  # noqa: E402
    DELTA,
    EncoderConfig,
    device_name,
    dry_run,
    embed,
    labels,
    load,
    run_methods,
    summarize,
)

GRID = ((0.0, 0.0), (1.0, 0.0), (0.0, 1.0), (1.0, 1.0), (1.0, 3.0), (3.0, 3.0))
"""(lam_cov, lam_adv) settings explored on dev."""


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=ROOT / "artifacts/research/goemotions_dev.json")
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    args = ap.parse_args(argv)
    root = Path(os.environ.get("ESP_DATA_DIR", ROOT / "data" / "external")) / "goemotions"
    cache = Path(os.environ.get("ESP_FEATURE_CACHE", Path.home() / ".cache" / "esp-neural"))
    device = device_name()
    t0 = time.time()
    print(json.dumps(dry_run(root), indent=1))
    data = load(root, unblind=False)
    x = {s: embed(d.texts, cache, device) for s, d in data.items()}
    train, dev = data["train"], data["dev"]
    emo_dev, ctx_dev = labels(dev)
    n_ctx = int(labels(train)[1].max()) + 1
    base = run_methods(
        train,
        dev,
        x["train"],
        x["dev"],
        n_ctx,
        enc_cfg=EncoderConfig(),
        device=device,
        seeds=args.seeds,
        methods=("mono", "mono_leace", "mono_filter", "raw"),
    )
    results = {m: summarize(r, emo_dev, ctx_dev) for m, r in base.items()}
    grid = {}
    for lam_cov, lam_adv in GRID:
        cfg = dataclasses.replace(EncoderConfig(), lam_cov=lam_cov, lam_adv=lam_adv)
        r = run_methods(
            train,
            dev,
            x["train"],
            x["dev"],
            n_ctx,
            enc_cfg=cfg,
            device=device,
            seeds=args.seeds,
            methods=("taoss",),
        )["taoss"]
        grid[f"cov={lam_cov},adv={lam_adv}"] = summarize(r, emo_dev, ctx_dev)
        print(lam_cov, lam_adv, grid[f"cov={lam_cov},adv={lam_adv}"], flush=True)
    floor = results["mono"]["ctx_acc"] - DELTA
    admissible = {k: v for k, v in grid.items() if v["ctx_acc"] >= floor}
    chosen = min(admissible, key=lambda k: admissible[k]["leak_auroc"]) if admissible else None
    out = {
        "label": "EXPLORATORY method development on GoEmotions train -> dev; test split blinded",
        "device": device,
        "seeds": args.seeds,
        "baselines": results,
        "taoss_grid": grid,
        "selection_rule": f"lowest dev leak_auroc with ctx_acc >= mono ctx_acc - {DELTA}",
        "chosen": chosen,
        "runtime_s": round(time.time() - t0, 1),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"baselines": results, "chosen": chosen}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
