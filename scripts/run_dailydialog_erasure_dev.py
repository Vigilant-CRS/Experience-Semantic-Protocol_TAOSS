# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Typing plus erasure on DailyDialog train -> validation. EXPLORATORY; test stays blinded.

Usage: python scripts/run_dailydialog_erasure_dev.py [--out <json>]

Selection rule, fixed before running: among the typed penalty settings in ``GRID``, choose
the one with the lowest validation leakage of ``taoss_leace`` whose topic (CTX) and dialog
act (INT) accuracies are both within ``DELTA`` of ``mono_leace``. The chosen setting is then
frozen as ``CONFIG`` in ``esp.bench.dailydialog_erasure_study`` and in the preregistration.
Test texts are embedded as unlabelled inputs only; no test label is loaded.
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

from esp.bench.dailydialog_erasure_study import (  # noqa: E402
    DELTA,
    EncoderConfig,
    dry_run,
    embed,
    load,
    run,
    summarize,
)
from esp.bench.goemotions_study import device_name  # noqa: E402

GRID = ((0.0, 0.0), (1.0, 1.0), (3.0, 3.0))
"""(lam_cov, lam_adv) settings explored on validation."""
BASELINES = ("mono", "mono_leace", "mono_filter", "raw_leace")
TYPED = ("taoss", "taoss_leace")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--out", type=Path, default=ROOT / "artifacts/research/erasure_dailydialog_dev.json"
    )
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2])
    args = ap.parse_args(argv)
    root = Path(os.environ.get("ESP_DATA_DIR", ROOT / "data" / "external")) / "dailydialog"
    cache = Path(os.environ.get("ESP_FEATURE_CACHE", Path.home() / ".cache" / "esp-neural"))
    device = device_name()
    t0 = time.time()
    print(json.dumps(dry_run(root), indent=1), flush=True)
    data = load(root, unblind=False)
    x = {s: embed(d.texts, cache, device) for s, d in data.items()}
    train, val = data["train"], data["validation"]
    base = run(
        train, val, x["train"], x["validation"], device=device, seeds=args.seeds, methods=BASELINES
    )
    results = {m: summarize(s, val) for m, s in base.items()}
    print(json.dumps(results, indent=1), flush=True)
    grid = {}
    for lam_cov, lam_adv in GRID:
        cfg = dataclasses.replace(EncoderConfig(), lam_cov=lam_cov, lam_adv=lam_adv)
        typed = run(
            train,
            val,
            x["train"],
            x["validation"],
            cfg=cfg,
            device=device,
            seeds=args.seeds,
            methods=TYPED,
        )
        key = f"cov={lam_cov},adv={lam_adv}"
        grid[key] = {m: summarize(s, val) for m, s in typed.items()}
        print(key, json.dumps(grid[key]), flush=True)
    ref = results["mono_leace"]
    admissible = {
        k: v
        for k, v in grid.items()
        if v["taoss_leace"]["ctx_acc"] >= ref["ctx_acc"] - DELTA
        and v["taoss_leace"]["int_acc"] >= ref["int_acc"] - DELTA
    }
    chosen = (
        min(admissible, key=lambda k: admissible[k]["taoss_leace"]["leak_auroc"])
        if admissible
        else None
    )
    out = {
        "label": "EXPLORATORY: DailyDialog train -> validation; test split blinded",
        "device": device,
        "seeds": args.seeds,
        "baselines": results,
        "typed_grid": grid,
        "selection_rule": "lowest taoss_leace leakage with CTX and INT within DELTA of mono_leace",
        "chosen": chosen,
        "runtime_s": round(time.time() - t0, 1),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print("chosen", chosen)
    return 0


if __name__ == "__main__":
    sys.exit(main())
