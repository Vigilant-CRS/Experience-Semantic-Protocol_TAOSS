# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Freeze the v1 conformance vectors (WP-047): ``vectors/FROZEN-<suite_version>.json``.

The manifest pins the BLAKE2b-256 digest of every frozen file, taken from
``vectors/INDEX.json``. A frozen file must never change: a change needs a new
suite version and a new manifest. Files whose normative basis is still a
PROPOSED ADR are listed as *provisional* and are not frozen.

Usage: uv run python scripts/freeze_vectors.py [--check]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VECTORS = ROOT / "vectors"
#: vector files whose layout rests on a PROPOSED ADR (not frozen in 1.0.0)
PROVISIONAL = {
    "xcf/capsules.json": "ADR-0022 (XCF gate) is PROPOSED; XCF is a v2 track",
    "hive/tlvs.json": "ADR-0021 (Typed Hive) is PROPOSED; the Hive is a v2 research track",
    "replay/watermark.json": "ADR-0030 (replay watermark) is PROPOSED",
}


def manifest() -> dict[str, object]:
    index = json.loads((VECTORS / "INDEX.json").read_text(encoding="utf-8"))
    files = index["files"]
    return {
        "suite_version": index["suite_version"],
        "license": "CC-BY-4.0",
        "hash": "BLAKE2b-256",
        "frozen": {k: v for k, v in sorted(files.items()) if k not in PROVISIONAL},
        "provisional": {k: PROVISIONAL[k] for k in sorted(files) if k in PROVISIONAL},
        "rule": "frozen files never change; any change needs a new suite version and manifest",
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="verify instead of writing")
    args = ap.parse_args(argv)
    m = manifest()
    path = VECTORS / f"FROZEN-{m['suite_version']}.json"
    if args.check:
        if not path.exists():
            print(f"missing {path.relative_to(ROOT)}")
            return 1
        frozen = json.loads(path.read_text(encoding="utf-8"))["frozen"]
        current = json.loads((VECTORS / "INDEX.json").read_text(encoding="utf-8"))["files"]
        changed = [k for k, v in frozen.items() if current.get(k) != v]
        if changed:
            print(f"frozen vectors changed or removed: {changed}")
            return 1
        print(f"{len(frozen)} frozen vector files unchanged")
        return 0
    if path.exists():
        print(f"{path.relative_to(ROOT)} exists; a freeze is never rewritten")
        return 1
    path.write_text(json.dumps(m, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)} ({len(m['frozen'])} frozen files)")  # type: ignore[arg-type]
    return 0


if __name__ == "__main__":
    sys.exit(main())
