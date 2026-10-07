# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Preregistered typing-plus-erasure study on DailyDialog, blinded until the prereg is public.

Usage:
  python scripts/run_dailydialog_erasure_study.py --write-prereg  # writes the prereg JSON
  python scripts/run_dailydialog_erasure_study.py --dry-run       # counts only; no test labels
  python scripts/run_dailydialog_erasure_study.py --unblind --prereg-commit <sha> \
      --out artifacts/research/dailydialog_erasure_study.json

``--unblind`` refuses to run unless:
- ``<sha>`` is an ancestor of ``origin/main``, so the preregistration was published first;
- the preregistration file at ``<sha>`` is byte-identical to the local one;
- every data file matches the SHA-256 pinned in its manifest;
- the analysis parameters reproduce the registered digest.
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

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from esp.bench.dailydialog_erasure_study import (  # noqa: E402
    config_record,
    dry_run,
    embed,
    load,
    verify_pins,
)
from esp.bench.prereg import Hypothesis, Preregistration, SplitUnit  # noqa: E402

PREREG = ROOT / "research" / "prereg" / "dailydialog-erasure.json"


def preregistration(root: Path) -> Preregistration:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    return Preregistration(
        hypothesis=Hypothesis.H2,
        primary_metric=(
            "test macro-AUROC of the strongest EMO probe on released KNO+CTX+INT: "
            "typed + LEACE erasure < monolithic + LEACE (same dimension), with topic (CTX) and "
            "dialog-act (INT) accuracy non-inferior (delta 0.02); dialog-cluster bootstrap"
        ),
        threshold=0.05,
        split_unit=SplitUnit.SESSION,
        baselines=("mono_leace", "raw_leace", "mono_learned_filter", "taoss_without_erasure"),
        seeds=(0, 1, 2),
        datasets=("dailydialog@Li-et-al-2017 (CC BY-NC-SA 4.0), official train/validation/test",),
        multiplicity="holm",
        alpha=0.05,
        registry_ref=(
            "github:Vigilant-CRS/Experience-Semantic-Protocol_TAOSS:"
            "research/prereg/dailydialog-erasure.json"
        ),
        notes=json.dumps(
            {
                "analysis_code": "src/esp/bench/dailydialog_erasure_study.py:analyse",
                "mechanism": "src/esp/privacy/erasure.py:LeaceEraser",
                "config": config_record(),
                "pinned_files": {k: v["sha256"] for k, v in sorted(manifest["files"].items())},
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
    committed = git("show", f"{sha}:research/prereg/dailydialog-erasure.json").stdout
    if committed != PREREG.read_text(encoding="utf-8"):
        sys.exit("refusing to unblind: local preregistration differs from the published one")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--write-prereg", action="store_true")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--unblind", action="store_true")
    ap.add_argument("--prereg-commit")
    ap.add_argument(
        "--out", type=Path, default=ROOT / "artifacts/research/dailydialog_erasure_study.json"
    )
    args = ap.parse_args(argv)
    root = Path(os.environ.get("ESP_DATA_DIR", ROOT / "data" / "external")) / "dailydialog"
    cache = Path(os.environ.get("ESP_FEATURE_CACHE", Path.home() / ".cache" / "esp-neural"))
    if args.write_prereg:
        pr = preregistration(root)
        body = {"preregistration": asdict(pr), "digest": pr.digest(), "osf": pr.osf_export()}
        PREREG.parent.mkdir(parents=True, exist_ok=True)
        PREREG.write_text(
            json.dumps(body, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
        )
        print(f"wrote {PREREG.relative_to(ROOT)} digest {pr.digest()}")
        return 0
    if args.dry_run:
        print(json.dumps(dry_run(root), indent=1))
        return 0
    if args.unblind:
        if not args.prereg_commit:
            sys.exit("--unblind needs --prereg-commit")
        _published(args.prereg_commit)
        verify_pins(root)
        pr = preregistration(root)
        if json.loads(PREREG.read_text(encoding="utf-8"))["digest"] != pr.digest():
            sys.exit("analysis parameters differ from the preregistration")
        from esp.bench.dailydialog_erasure_study import analyse  # noqa: PLC0415
        from esp.bench.goemotions_study import device_name  # noqa: PLC0415
        from esp.bench.neural_decoders import hardware_record  # noqa: PLC0415

        t0 = time.time()
        device = device_name()
        data = load(root, unblind=True)
        x = {s: embed(d.texts, cache, device) for s, d in data.items()}
        res = analyse(data, x, device=device)
        res.update(
            {
                "label": "PREREGISTERED confirmatory analysis (typing plus erasure, H2 follow-up)",
                "prereg_commit": args.prereg_commit,
                "prereg_digest": pr.digest(),
                "hardware": hardware_record(),
                "runtime_s": round(time.time() - t0, 1),
            }
        )
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(
            json.dumps(res, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
        )
        keys = ("P1_taoss_leace_vs_mono_leace", "primary_supported")
        print(json.dumps({k: res[k] for k in keys}, indent=1))
        return 0
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
