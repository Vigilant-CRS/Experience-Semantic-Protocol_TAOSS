# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Record a milestone report produced elsewhere (e.g. in a pinned worktree) in this repository.

Usage: uv run python scripts/record_milestone.py M6 /path/to/M6.json [note]

Copies the report to artifacts/test-reports/<M>.json and adds or updates the
milestone row in docs/IMPLEMENTATION_STATUS.md. Only PASS reports are recorded.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATUS = ROOT / "docs" / "IMPLEMENTATION_STATUS.md"


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    milestone, src = argv[1], Path(argv[2])
    note = " ".join(argv[3:])
    report = json.loads(src.read_text(encoding="utf-8"))
    if report.get("verdict") != "PASS" or report.get("milestone") != milestone:
        print(f"refusing: {src} is not a PASS report for {milestone}")
        return 1
    dest = ROOT / "artifacts" / "test-reports" / f"{milestone}.json"
    shutil.copyfile(src, dest)
    commit = report["git_commit"][:7]
    detail = f"commit {commit}" + (f"; {note}" if note else "")
    row = f"| {milestone} | PASS | `artifacts/test-reports/{milestone}.json` ({detail}) |"
    text = STATUS.read_text(encoding="utf-8")
    pattern = re.compile(rf"^\| {re.escape(milestone)} \| (PASS|FAIL|OPEN) \|.*$", re.MULTILINE)
    if pattern.search(text):
        text = pattern.sub(row, text)
    else:
        last = list(re.finditer(r"^\| M\d+a? \| (PASS|FAIL|OPEN) \|.*$", text, re.MULTILINE))[-1]
        text = text[: last.end()] + "\n" + row + text[last.end() :]
    STATUS.write_text(text, encoding="utf-8")
    print(row)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
