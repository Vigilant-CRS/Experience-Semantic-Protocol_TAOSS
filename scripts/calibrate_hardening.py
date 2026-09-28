# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Derive the ``esp-covert-hardening-v1`` defaults (GAP-015). EXPLORATORY.

Usage: uv run python scripts/calibrate_hardening.py [--n N] [--steps N] [--seed S]
       [--out artifacts/research/hardening_calibration.json]
       [--profile src/esp/audit/esp-covert-hardening-v1.json]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from esp.audit.hardening_calibration import CalibrationConfig, run

ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    d = CalibrationConfig()
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--n", type=int, default=d.n)
    ap.add_argument("--steps", type=int, default=d.steps)
    ap.add_argument("--seed", type=int, default=d.seed)
    ap.add_argument(
        "--out", type=Path, default=ROOT / "artifacts/research/hardening_calibration.json"
    )
    ap.add_argument("--profile", type=Path, default=None)
    args = ap.parse_args(argv)
    profile, report = run(CalibrationConfig(n=args.n, steps=args.steps, seed=args.seed))
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if args.profile is not None:
        args.profile.write_text(profile.to_json() + "\n", encoding="utf-8")
    print(
        json.dumps({k: report[k] for k in ("honest_false_positives", "covert_detection")}, indent=1)
    )
    print("sub-step recovery:", report["sub_step"]["bit_recovery_by_sigma_steps"])
    print(
        "chosen sigma_steps:", report["sub_step"]["chosen_sigma_steps"], "digest", profile.digest()
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
