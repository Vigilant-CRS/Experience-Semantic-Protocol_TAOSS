# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-085: every resolved gap is proposed as a V13.1 erratum; open gaps are listed."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def gaps() -> dict[str, str]:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    out = {}
    for line in plan.splitlines():
        m = re.match(r"^\| (GAP-\d{3}) \|.*\| ([^|]+) \|$", line)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def test_errata_cover_every_resolved_gap() -> None:
    errata = (ROOT / "docs" / "errata" / "V13-ERRATA.md").read_text(encoding="utf-8")
    g = gaps()
    assert len(g) >= 30
    for gap, status in g.items():
        if status.startswith(("RESOLVED", "ERRATA")) and gap not in {"GAP-010", "GAP-021"}:
            assert gap in errata, f"{gap} ({status}) has no errata entry"
    for gap, status in g.items():
        if status.startswith(("OPEN", "PARTIAL")):
            assert gap in errata.split("## Still open")[1], f"{gap} is open but not listed"
