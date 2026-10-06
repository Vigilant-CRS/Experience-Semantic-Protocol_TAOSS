# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Preregistered FALCON H2 study (claims level 4). Blinded until the preregistration is public.

Usage:
  uv run python scripts/run_falcon_h2_study.py --write-prereg  # build research/prereg/...json
  uv run python scripts/run_falcon_h2_study.py --dry-run       # shapes and counts; no labels
  uv run python scripts/run_falcon_h2_study.py --unblind --prereg-commit <sha> \
      --out artifacts/research/falcon_h2_study.json

``--unblind`` refuses to run unless:
- ``<sha>`` is an ancestor of ``origin/main``, which proves the preregistration was
  published before the run;
- the preregistration file at ``<sha>`` is byte-identical to the local one;
- every data file matches its pinned SHA-256.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from dataclasses import asdict
from pathlib import Path

from esp.bench.falcon_h2_study import (
    MIN_TRIAL_S,
    N_PERM,
    SEEDS,
    TAU_BINS,
    VAL_TRIALS,
    CtcConfig,
    analyse,
    dry_run,
    load,
    verify_pins,
)
from esp.bench.prereg import Hypothesis, Preregistration, SplitUnit

ROOT = Path(__file__).resolve().parent.parent
PREREG = ROOT / "research" / "prereg" / "falcon-h2.json"


def preregistration() -> Preregistration:
    reg = json.loads((ROOT / "datasets" / "neural.json").read_text(encoding="utf-8"))
    h2 = next(d for d in reg["datasets"] if d["id"] == "falcon-h2")
    return Preregistration(
        hypothesis=Hypothesis.L4,
        primary_metric="corpus_CER_heldout_gru_daynorm_vs_within_session_permutation_null",
        threshold=0.05,
        split_unit=SplitUnit.SESSION,
        baselines=(
            "within_session_permutation_null",
            "time_shuffled_neural_input",
            "linear_ctc_daynorm",
            "gru_ctc_raw_no_daynorm",
        ),
        seeds=SEEDS,
        datasets=(f"DANDI:000950@{h2['version']}",),
        multiplicity="holm",
        alpha=0.05,
        registry_ref=(
            "github:Vigilant-CRS/Experience-Semantic-Protocol_TAOSS:research/prereg/falcon-h2.json"
        ),
        notes=json.dumps(
            {
                "analysis_code": "src/esp/bench/falcon_h2_study.py:analyse",
                "tau_bins": TAU_BINS,
                "heldout_normalisation": "per-session z-score, whole unlabelled session",
                "val_trials": VAL_TRIALS,
                "min_trial_s": MIN_TRIAL_S,
                "n_perm": N_PERM,
                "gru_config": asdict(CtcConfig()),
                "linear_config": asdict(CtcConfig(kind="linear")),
                "pinned_files": {k: v["sha256"] for k, v in sorted(h2["files"].items())},
            },
            sort_keys=True,
        ),
    )


def _published(sha: str) -> None:
    def git(*a: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["git", *a], cwd=ROOT, capture_output=True, text=True, check=False)

    git("fetch", "-q", "origin", "main")
    if git("merge-base", "--is-ancestor", sha, "origin/main").returncode != 0:
        sys.exit("refusing to unblind: the preregistration commit is not on origin/main")
    committed = git("show", f"{sha}:research/prereg/falcon-h2.json").stdout
    if committed != PREREG.read_text(encoding="utf-8"):
        sys.exit("refusing to unblind: local preregistration differs from the published one")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write-prereg", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--unblind", action="store_true")
    ap.add_argument("--prereg-commit")
    ap.add_argument("--out", type=Path, default=ROOT / "artifacts/research/falcon_h2_study.json")
    args = ap.parse_args(argv)
    data = Path(os.environ.get("ESP_DATA_DIR", ROOT / "data" / "external")) / "falcon-h2"
    if args.write_prereg:
        pr = preregistration()
        body = {"preregistration": asdict(pr), "digest": pr.digest(), "osf": pr.osf_export()}
        PREREG.parent.mkdir(parents=True, exist_ok=True)
        PREREG.write_text(
            json.dumps(body, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
        )
        print(f"wrote {PREREG.relative_to(ROOT)} digest {pr.digest()}")
        return 0
    if args.dry_run:
        print(json.dumps(dry_run(data), indent=1))
        return 0
    if args.unblind:
        if not args.prereg_commit:
            sys.exit("--unblind needs --prereg-commit")
        _published(args.prereg_commit)
        verify_pins(data, ROOT / "datasets" / "neural.json")
        pr = preregistration()
        if json.loads(PREREG.read_text(encoding="utf-8"))["digest"] != pr.digest():
            sys.exit("analysis parameters differ from the preregistration")
        t0 = time.time()
        res = analyse(load(data, unblind=True))
        res.update(
            {
                "label": "PREREGISTERED confirmatory analysis (claims level 4)",
                "prereg_commit": args.prereg_commit,
                "prereg_digest": pr.digest(),
                "runtime_s": round(time.time() - t0, 1),
            }
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps(res, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
        )
        print(
            json.dumps(
                {k: res[k] for k in ("P1_heldout_gru_daynorm", "primary_supported")}, indent=1
            )
        )
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
