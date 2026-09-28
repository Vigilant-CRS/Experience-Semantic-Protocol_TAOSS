# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Set the status of one work package in the master plan.

Usage: uv run python scripts/set_wp_status.py WP-000 VERIFIED
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

PLAN = Path(__file__).resolve().parent.parent / "docs" / "MASTER_IMPLEMENTATION_PLAN.md"
VALID = {
    "NOT_STARTED",
    "IN_PROGRESS",
    "BLOCKED",
    "IMPLEMENTED",
    "VERIFIED",
    "DEFERRED",
    "REJECTED",
    "FUTURE",
}


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[2] not in VALID or not re.fullmatch(r"WP-\d{3}", argv[1]):
        print(f"usage: set_wp_status.py WP-NNN {{{','.join(sorted(VALID))}}}")
        return 2
    wp, status = argv[1], argv[2]
    text = PLAN.read_text(encoding="utf-8")
    pattern = re.compile(rf"(^## {wp} — .*?\n.*?\*\*Status:\*\* `)([A-Z_]+)(`)", re.S | re.M)
    new, count = pattern.subn(rf"\g<1>{status}\g<3>", text, count=1)
    if count != 1:
        print(f"{wp}: status line not found")
        return 1
    PLAN.write_text(new, encoding="utf-8")
    print(f"{wp}: {status}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
