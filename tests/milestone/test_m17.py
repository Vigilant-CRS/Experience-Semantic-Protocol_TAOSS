# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M17 gate: maximal scope reached (plan §54, M17).

1. Every row of the V13 coverage matrix (§52c) points to WPs that are VERIFIED,
   DEFERRED (with a reason) or FUTURE (with an interface).
2. Every GAP is resolved and submitted as errata. This is checked strictly only
   with ``ESP_M17_GATE=1`` (``scripts/run_milestone.py M17``). Partial gaps are
   reported, and they block M17 honestly.
3. Claims ladder level 3 is reached and no higher level is claimed.
"""

import json
import os
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]
PLAN = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
ERRATA = (ROOT / "docs" / "errata" / "V13-ERRATA.md").read_text(encoding="utf-8")
DONE = ("RESOLVED", "RESOLVED_IN_PLAN", "RESOLVED_IN_IMPLEMENTATION", "ERRATA_PROPOSED")


def _section(title: str) -> str:
    start = PLAN.index(title)
    return PLAN[start : PLAN.index("\n# ", start + 1)]


def _statuses() -> dict[str, str]:
    return dict(re.findall(r"^## (WP-\d{3}) — .*?\n\n\*\*Status:\*\* `([A-Z_]+)`", PLAN, re.M))


def _gaps() -> dict[str, str]:
    rows = re.findall(r"^\| (GAP-\d{3}) \|.*\| ([^|]+) \|\s*$", _section("# 52b."), re.M)
    return {g: status.strip() for g, status in rows}


def test_every_coverage_row_points_to_finished_work_packages() -> None:
    statuses = _statuses()
    matrix = _section("# 52c.")
    rows = [r for r in matrix.splitlines() if r.startswith("| §") or r.startswith("| App.")]
    assert len(rows) >= 45
    for row in rows:
        wps = set(re.findall(r"WP-\d{3}", row))
        ranges = re.findall(r"WP-(\d{3}) … WP-(\d{3})", row)
        for lo, hi in ranges:
            wps |= {f"WP-{i:03d}" for i in range(int(lo), int(hi) + 1)}
        for wp in wps:
            assert statuses[wp] in {"VERIFIED", "DEFERRED", "FUTURE"}, (row[:40], wp)


def test_gap_register_complete_and_errata_cover_resolved_gaps() -> None:
    gaps = _gaps()
    assert len(gaps) == 30
    for gap, status in gaps.items():
        if status.startswith(("RESOLVED_IN_IMPLEMENTATION", "ERRATA_PROPOSED")):
            assert gap in ERRATA, f"{gap} resolved but not submitted as errata"


@pytest.mark.skipif(os.environ.get("ESP_M17_GATE") != "1", reason="strict gap check: M17 only")
def test_all_gaps_resolved() -> None:
    open_gaps = {g: s for g, s in _gaps().items() if not s.startswith(DONE) or "offen" in s}
    assert open_gaps == {}, f"M17 blocked on gaps: {sorted(open_gaps)}"


def test_claims_ladder_level_three_with_evidence_and_nothing_higher() -> None:
    claims = (ROOT / "docs" / "CLAIMS.md").read_text(encoding="utf-8")
    level = int(re.search(r"<!-- claims-level: (\d) -->", claims).group(1))  # type: ignore[union-attr]
    assert level == 3
    for m in ("M3", "M2", "M5", "M6", "M7"):
        report = json.loads((ROOT / "artifacts" / "test-reports" / f"{m}.json").read_text())
        assert report["verdict"] == "PASS", m
    readme = (ROOT / "README.md").read_text(encoding="utf-8").lower()
    for forbidden in ("h1 is supported", "h2 is supported", "h3 is supported", "reads minds"):
        assert forbidden not in readme
