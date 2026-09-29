# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""FALCON H1 evaluation of the reference neural decoder (WP-089). EXPLORATORY.

Usage: uv run python scripts/run_neural_eval.py [--out artifacts/research/neural_falcon_h1.json]
Needs ``scripts/fetch_dandi.py falcon-h1`` (data stays in the git-ignored data/external).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from esp.bench.neural_falcon import evaluate

ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, default=ROOT / "artifacts/research/neural_falcon_h1.json")
    args = ap.parse_args(argv)
    data = Path(os.environ.get("ESP_DATA_DIR", ROOT / "data" / "external")) / "falcon-h1"
    result = evaluate(data)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps(result["summary"], indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
