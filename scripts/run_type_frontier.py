# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Type-discovery frontier and ablations (WP-074). EXPLORATORY — NOT preregistered evidence.

Usage: uv run python scripts/run_type_frontier.py [--steps N] [--n N] [--eval-n N]
       [--seeds 0 1 2] [--stable] [--out artifacts/research/type_frontier.json]

Trains TAOSS-3/-6/-8/-12 encoders on a synthetic world with planted dependence,
evaluates ``Utility_T - lambda_p * Leak_V`` (V13 eq. frontier) and the TAOSS-6
ablations (covariance-only / adversarial-only / both / neither, EMO default-masked,
pseudonyms on/off), writes JSON and prints a summary table. Results describe this
synthetic world only; they are labelled exploratory and support no H1/H2/H3 claim.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import sys
import time
from pathlib import Path
from typing import Any

from esp.training.frontier import FrontierConfig, WorldConfig, run

ROOT = Path(__file__).resolve().parent.parent


def table(result: dict[str, Any]) -> str:
    """Plain-text summary (leakage in bits per masked dimension)."""
    lines = [
        "profile   K  utility  leak_mean  leak_max  leak_joint  inherent(mean/max/joint)  scen.",
        "--------  --  -------  ---------  --------  ----------  ------------------------  -----",
    ]
    for name, p in result["profiles"].items():
        leak, inh = p["leak"], p["inherent_leak"]
        expressible = sum(p["scenarios_expressible"].values())
        lines.append(
            f"{name:8s}  {p['k']:2d}  {p['utility']:7.3f}  {leak['mean']:9.3f}"
            f"  {leak['max']:8.3f}  {leak['joint']:10.3f}"
            f"  {inh['mean']:6.3f}/{inh['max']:6.3f}/{inh['joint']:6.3f}   "
            f"  {expressible}/{len(p['scenarios_expressible'])}"
        )
    names = list(result["profiles"])
    lines += ["", "aggregate  lambda_p  best      " + "  ".join(f"{n:>8s}" for n in names)]
    for row in result["frontier"]:
        scores = "  ".join(f"{row['scores'][n]:8.3f}" for n in names)
        lines.append(f"{row['aggregate']:9s}  {row['lambda_p']:8.2f}  {row['best']:8s}  {scores}")
    ab = result["ablations"]
    lines += [
        "",
        "TAOSS-6 ablation  utility  leak_mean  leak_joint  emo_masked  R2(EMO|visible)  vis_util",
    ]
    for name, r in ab["regularization"].items():
        m = ab["emo_default_masked"][name]
        lines.append(
            f"{name:16s}  {r['utility']:7.3f}  {r['leak']['mean']:9.3f}  {r['leak']['joint']:10.3f}"
            f"  {m['emo_leak_bits_per_dim']:10.3f}  {m['emo_target_r2_from_visible_latents']:15.3f}"
            f"  {m['visible_utility']:8.3f}"
        )
    inherent = ab["emo_inherent"]
    lines.append(
        f"inherent (visible targets -> EMO): {inherent['inherent_emo_leak_bits_per_dim']:.3f}"
        f" bits/dim, R2 {inherent['emo_target_r2_from_visible_targets']:.3f}"
    )
    lines += ["", "pooled width      utility  leak_joint  emo_masked  R2(EMO|visible)"]
    for name, r in ab["rank_bottleneck"].items():
        if isinstance(r, dict):
            m = r["emo_masked"]
            r2 = m["emo_target_r2_from_visible_latents"]
            lines.append(
                f"{name:16s}  {r['utility']:7.3f}  {r['leak']['joint']:10.3f}"
                f"  {m['emo_leak_bits_per_dim']:10.3f}  {r2:15.3f}"
            )
    ps = ab["pseudonyms"]
    content = ", ".join(
        f"{k}: {v:.2f}" for k, v in ps["pseudonyms_on"]["content_accuracy_by_offset_scale"].items()
    )
    lines += [
        "",
        f"pseudonyms off: linked by id {ps['pseudonyms_off']['linked_by_id']:.2f}"
        f" | on: by id {ps['pseudonyms_on']['linked_by_id']:.2f};"
        f" by content (signature scale -> accuracy) {content}; chance {ps['chance']:.2f}",
        f"label: {result['label']} — {result['claims']}",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--steps", type=int, default=300)
    parser.add_argument("--n", type=int, default=1024, help="training samples")
    parser.add_argument("--eval-n", type=int, default=4000, help="independent evaluation draw")
    parser.add_argument("--seeds", type=int, nargs="+", default=[0])
    parser.add_argument("--stable", action="store_true", help="train with every V13 mechanism")
    parser.add_argument(
        "--emo-degrees", type=int, nargs="+", default=[1, 2], help="EMO-masked probe ladder"
    )
    parser.add_argument(
        "--out", type=Path, default=ROOT / "artifacts" / "research" / "type_frontier.json"
    )
    args = parser.parse_args(argv)
    cfg = FrontierConfig(
        steps=args.steps,
        seeds=tuple(args.seeds),
        world=dataclasses.replace(WorldConfig(), n=args.n, eval_n=args.eval_n),
        stable=args.stable,
        emo_degrees=tuple(args.emo_degrees),
    )
    t0 = time.perf_counter()
    result = run(cfg)
    result["runtime_s"] = round(time.perf_counter() - t0, 1)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(table(result))
    print(f"wrote {args.out} in {result['runtime_s']} s")
    return 0


if __name__ == "__main__":
    sys.exit(main())
