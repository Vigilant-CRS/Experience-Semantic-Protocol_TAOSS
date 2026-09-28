# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The plan-sync checker is a safety net; it needs its own negative tests."""

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "verify_plan_sync.py"


@pytest.fixture(scope="module")
def vps() -> ModuleType:
    spec = importlib.util.spec_from_file_location("verify_plan_sync", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["verify_plan_sync"] = module
    spec.loader.exec_module(module)
    return module


PLAN = """# 53. Arbeitspakete

## WP-000 — Bootstrap

**Status:** `VERIFIED`

text

## WP-001 — Core

**Status:** `NOT_STARTED` · **Klasse:** x

see WP-000

# 54. Meilensteine

## M0 — whatever
"""


def test_splits_sections_and_stops_at_level1_heading(vps: ModuleType) -> None:
    sections = vps.split_work_packages(PLAN)
    assert set(sections) == {"WP-000", "WP-001"}
    assert "Meilensteine" not in sections["WP-001"]
    assert sections["WP-000"].startswith("## WP-000")


def test_reads_exactly_one_status(vps: ModuleType) -> None:
    report = vps.Report()
    statuses = vps.check_statuses(vps.split_work_packages(PLAN), report)
    assert statuses == {"WP-000": "VERIFIED", "WP-001": "NOT_STARTED"}
    assert report.errors == []


def test_missing_and_duplicate_status_fail(vps: ModuleType) -> None:
    bad = PLAN.replace("**Status:** `NOT_STARTED` · **Klasse:** x", "no status here")
    bad = bad.replace("text", "**Status:** `IN_PROGRESS`")
    report = vps.Report()
    vps.check_statuses(vps.split_work_packages(bad), report)
    assert any("WP-000" in e and "found 2" in e for e in report.errors)
    assert any("WP-001" in e and "found 0" in e for e in report.errors)


def test_invalid_status_value_fails(vps: ModuleType) -> None:
    report = vps.Report()
    vps.check_statuses(vps.split_work_packages(PLAN.replace("VERIFIED", "DONE")), report)
    assert any("invalid status 'DONE'" in e for e in report.errors)


def test_verified_without_evidence_fails(vps: ModuleType) -> None:
    report = vps.Report()
    vps.check_evidence({"WP-000": "VERIFIED"}, "| WP | Status | Evidence |\n", report)
    assert any("no evidence row" in e for e in report.errors)


def test_verified_evidence_must_name_existing_test(vps: ModuleType) -> None:
    report = vps.Report()
    doc = "| WP-000 | VERIFIED | `tests/unit/does_not_exist.py` |\n"
    vps.check_evidence({"WP-000": "VERIFIED"}, doc, report)
    assert any("does not exist" in e for e in report.errors)

    report = vps.Report()
    doc = "| WP-000 | VERIFIED | `tests/unit/test_package.py` |\n"
    vps.check_evidence({"WP-000": "VERIFIED"}, doc, report)
    assert report.errors == []


def test_status_disagreement_fails(vps: ModuleType) -> None:
    report = vps.Report()
    doc = "| WP-001 | VERIFIED | `tests/unit/test_package.py` |\n"
    vps.check_evidence({"WP-001": "IN_PROGRESS"}, doc, report)
    assert any("status doc says VERIFIED" in e for e in report.errors)


def test_undefined_reference_fails(vps: ModuleType) -> None:
    report = vps.Report()
    plan = PLAN + "\nrefers to WP-999\n"
    vps.check_references(plan, vps.split_work_packages(plan), report)
    assert report.errors == ["WP-999: referenced but not defined"]


def test_todo_in_verified_section_fails(vps: ModuleType) -> None:
    report = vps.Report()
    plan = PLAN.replace("text", "TODO finish")
    sections = vps.split_work_packages(plan)
    vps.check_todos({"WP-000": "VERIFIED"}, sections, report)
    assert any("TODO" in e for e in report.errors)


def test_real_repository_plan_is_consistent(vps: ModuleType) -> None:
    assert vps.main() == 0
