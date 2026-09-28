# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Verify that the master plan, implementation status and code agree.

Implements master plan section 51. Exit code 0 = consistent, 1 = inconsistent.

Checks:
 1. every work package has exactly one valid status;
 2. every VERIFIED work package has evidence in docs/IMPLEMENTATION_STATUS.md
    and every referenced test path exists;
 3. every milestone marked PASS has a test report under artifacts/test-reports/;
 4. every ADR listed in the decision log with status ACCEPTED exists as a file;
 5. the wire version in code matches the plan's project status block;
 6. every WP referenced anywhere in the plan is defined;
 7. no TODO/FIXME marker remains in the section of a VERIFIED work package.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PLAN = ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md"
STATUS = ROOT / "docs" / "IMPLEMENTATION_STATUS.md"
REPORTS = ROOT / "artifacts" / "test-reports"
DECISIONS = ROOT / "docs" / "decisions"

VALID_STATUS = {
    "NOT_STARTED",
    "IN_PROGRESS",
    "BLOCKED",
    "IMPLEMENTED",
    "VERIFIED",
    "DEFERRED",
    "REJECTED",
    "FUTURE",
}

WP_HEADER = re.compile(r"^## (WP-\d{3}) — .*$", re.MULTILINE)
WP_STATUS = re.compile(r"\*\*Status:\*\* `([A-Z_]+)`")
EVIDENCE_ROW = re.compile(r"^\|\s*(WP-\d{3})\s*\|\s*([A-Z_]+)\s*\|(.*)\|\s*$", re.MULTILINE)
MILESTONE_ROW = re.compile(r"^\|\s*(M\d+a?)\s*\|\s*(PASS|FAIL|OPEN)\s*\|", re.MULTILINE)
ADR_ROW = re.compile(r"^\|\s*(ADR-\d{4})\s*\|[^|]*\|\s*([A-Z_]+)", re.MULTILINE)
WIRE_IN_PLAN = re.compile(r'^wire_version:\s*"(\d+)\.(\d+)"', re.MULTILINE)
WIRE_IN_CODE = re.compile(r"WIRE_VERSION:\s*Final\s*=\s*\((\d+),\s*(\d+)\)")


@dataclass
class Report:
    errors: list[str] = field(default_factory=list)

    def fail(self, message: str) -> None:
        self.errors.append(message)


def split_work_packages(plan: str) -> dict[str, str]:
    """Return a mapping WP-id -> section text (up to the next level-1/2 heading)."""
    headers = list(WP_HEADER.finditer(plan))
    sections: dict[str, str] = {}
    for index, match in enumerate(headers):
        end = headers[index + 1].start() if index + 1 < len(headers) else len(plan)
        body = plan[match.start() : end]
        # Stop at the next level-1 heading (e.g. "# 54. Meilensteine"); the
        # search starts after the WP heading line itself.
        heading_end = body.find("\n") + 1
        next_top = re.search(r"^# ", body[heading_end:], re.MULTILINE)
        if next_top is not None:
            body = body[: heading_end + next_top.start()]
        sections[match.group(1)] = body
    return sections


def check_statuses(sections: dict[str, str], report: Report) -> dict[str, str]:
    statuses: dict[str, str] = {}
    for wp, body in sections.items():
        found = WP_STATUS.findall(body)
        if len(found) != 1:
            report.fail(f"{wp}: expected exactly one status, found {len(found)}")
            continue
        if found[0] not in VALID_STATUS:
            report.fail(f"{wp}: invalid status {found[0]!r}")
        statuses[wp] = found[0]
    return statuses


def check_evidence(statuses: dict[str, str], status_doc: str, report: Report) -> None:
    evidence = {m.group(1): (m.group(2), m.group(3)) for m in EVIDENCE_ROW.finditer(status_doc)}
    for wp, status in statuses.items():
        if status != "VERIFIED":
            continue
        if wp not in evidence:
            report.fail(f"{wp}: VERIFIED but no evidence row in IMPLEMENTATION_STATUS.md")
            continue
        doc_status, rest = evidence[wp]
        if doc_status != "VERIFIED":
            report.fail(f"{wp}: plan says VERIFIED, status doc says {doc_status}")
        paths = re.findall(r"`(tests/[^`]+)`", rest)
        if not paths:
            report.fail(f"{wp}: VERIFIED evidence row names no test path")
        for path in paths:
            if not (ROOT / path.split("::")[0]).exists():
                report.fail(f"{wp}: evidence test path does not exist: {path}")
    for wp, (doc_status, _) in evidence.items():
        if wp in statuses and statuses[wp] != doc_status:
            report.fail(f"{wp}: status doc says {doc_status}, plan says {statuses[wp]}")


def check_milestones(status_doc: str, report: Report) -> None:
    for match in MILESTONE_ROW.finditer(status_doc):
        milestone, verdict = match.group(1), match.group(2)
        if verdict == "PASS" and not (REPORTS / f"{milestone}.json").exists():
            report.fail(f"{milestone}: marked PASS but report {milestone}.json is missing")


def check_adrs(plan: str, report: Report) -> None:
    existing = {"-".join(path.name.split("-")[:2]) for path in DECISIONS.glob("ADR-*.md")}
    for match in ADR_ROW.finditer(plan):
        adr, status = match.group(1), match.group(2)
        if status == "ACCEPTED" and adr not in existing:
            report.fail(f"{adr}: ACCEPTED in decision log but no file in docs/decisions/")


def check_wire_version(plan: str, report: Report) -> None:
    plan_match = WIRE_IN_PLAN.search(plan)
    code = (ROOT / "src" / "esp" / "__init__.py").read_text(encoding="utf-8")
    code_match = WIRE_IN_CODE.search(code)
    if plan_match is None or code_match is None:
        report.fail("wire version not found in plan status block or esp/__init__.py")
        return
    if plan_match.groups() != code_match.groups():
        report.fail(
            f"wire version mismatch: plan {'.'.join(plan_match.groups())}, "
            f"code {'.'.join(code_match.groups())}"
        )


def check_references(plan: str, sections: dict[str, str], report: Report) -> None:
    referenced = set(re.findall(r"WP-\d{3}", plan))
    for wp in sorted(referenced - sections.keys()):
        report.fail(f"{wp}: referenced but not defined")


def check_todos(statuses: dict[str, str], sections: dict[str, str], report: Report) -> None:
    for wp, status in statuses.items():
        if status == "VERIFIED" and re.search(r"\b(TODO|FIXME|XXX)\b", sections[wp]):
            report.fail(f"{wp}: VERIFIED section still contains a TODO/FIXME marker")


def main() -> int:
    report = Report()
    plan = PLAN.read_text(encoding="utf-8")
    status_doc = STATUS.read_text(encoding="utf-8") if STATUS.exists() else ""
    if not status_doc:
        report.fail("docs/IMPLEMENTATION_STATUS.md missing or empty")

    sections = split_work_packages(plan)
    statuses = check_statuses(sections, report)
    check_evidence(statuses, status_doc, report)
    check_milestones(status_doc, report)
    check_adrs(plan, report)
    check_wire_version(plan, report)
    check_references(plan, sections, report)
    check_todos(statuses, sections, report)

    if report.errors:
        print("verify-plan: FAILED")
        for error in report.errors:
            print(f"  - {error}")
        return 1
    counts: dict[str, int] = {}
    for status in statuses.values():
        counts[status] = counts.get(status, 0) + 1
    summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items()))
    print(f"verify-plan: OK ({len(statuses)} work packages; {summary})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
