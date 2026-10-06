# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""FALCON H1 method development (exploratory; chooses the decoder of the FALCON H2 preregistration).

Usage: python scripts/run_falcon_h1_methods.py [--no-gru] [--out <json>]
GPU: run with a CUDA build of torch (a separate environment); ``ESP_DEVICE`` forces a device.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from esp.bench.falcon_methods import evaluate

ROOT = Path(__file__).resolve().parent.parent


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--no-gru", action="store_true")
    ap.add_argument("--out", type=Path, default=ROOT / "artifacts/research/falcon_h1_methods.json")
    args = ap.parse_args(argv)
    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    data = Path(os.environ.get("ESP_DATA_DIR", ROOT / "data" / "external")) / "falcon-h1"
    res = evaluate(data, run_gru=not args.no_gru)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(res, indent=1) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
