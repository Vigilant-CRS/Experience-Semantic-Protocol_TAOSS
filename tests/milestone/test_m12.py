# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M12 gate: release candidate 1.0 (WP-046, WP-047).

The automated criteria always run. The human sign-offs (legal review, manual
threat review, critical ADR decisions) are checked only when
``ESP_RELEASE_GATE=1`` (set by ``scripts/run_milestone.py M12``). The gate
therefore fails honestly until a human has approved every item.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]
PLAN = ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md"
RELEASE = ROOT / "docs" / "release" / "RELEASE_1.0.md"
HUMAN_ONLY = {"WP-047", "WP-084"}  # the release itself and the external legal review


def _statuses() -> dict[str, str]:
    text = PLAN.read_text(encoding="utf-8")
    return dict(re.findall(r"^## (WP-\d{3}) — .*?\n\n\*\*Status:\*\* `([A-Z_]+)`", text, re.M))


def test_every_work_package_except_the_release_and_legal_review_is_verified() -> None:
    statuses = _statuses()
    assert len(statuses) == 92
    open_wps = {wp: s for wp, s in statuses.items() if s != "VERIFIED" and wp not in HUMAN_ONLY}
    assert open_wps == {}


def test_vectors_are_frozen_and_unchanged() -> None:
    out = subprocess.run(
        [sys.executable, "scripts/freeze_vectors.py", "--check"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stdout
    frozen = json.loads((ROOT / "vectors" / "FROZEN-1.0.0.json").read_text(encoding="utf-8"))
    assert len(frozen["frozen"]) >= 11
    assert "wire/header_valid.json" in frozen["frozen"]


def test_guides_complete() -> None:
    names = {p.name for p in (ROOT / "docs" / "guide").glob("*.md")}
    for required in (
        "ARCHITECTURE.md",
        "PSYCHOLOGY_MODEL.md",
        "PROTOCOL_WALKTHROUGH.md",
        "CONSENT_EXAMPLES.md",
        "SECURITY_EXAMPLES.md",
        "WHAT_ESP_IS_NOT.md",
        "ADAPTER_GUIDE.md",
    ):
        assert required in names
    assert (ROOT / "docs" / "CONFORMANCE.md").exists()


def _signoffs() -> list[tuple[str, str]]:
    text = RELEASE.read_text(encoding="utf-8")
    block = text.split("<!-- signoffs:start -->")[1].split("<!-- signoffs:end -->")[0]
    rows = [r for r in block.strip().splitlines()[2:] if r.startswith("|")]
    return [(c[1].strip(), c[3].strip()) for c in (r.split("|") for r in rows)]


def test_signoff_table_is_well_formed() -> None:
    rows = _signoffs()
    assert len(rows) >= 6
    assert all(status in {"PENDING", "APPROVED"} for _, status in rows)
    items = " ".join(i for i, _ in rows)
    for needle in ("WP-084", "threat-model", "ADR-0014", "ADR-0023", "ADR-0026", "ADR-0027"):
        assert needle in items


@pytest.mark.skipif(os.environ.get("ESP_RELEASE_GATE") != "1", reason="human sign-offs: M12 only")
def test_all_human_signoffs_approved() -> None:
    pending = [item for item, status in _signoffs() if status != "APPROVED"]
    assert pending == [], f"release blocked on human sign-off: {pending}"
