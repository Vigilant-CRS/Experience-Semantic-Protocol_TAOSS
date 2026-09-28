# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M11 gate: performance and security candidate.

Performance report, full fuzz run (``ESP_FUZZ_ITERATIONS``, 1,000,000 in the
gate run), dependency audit, automated threat review (every V13 threat
mapped to mitigation + tests), failure-mode regressions green, no unresolved
critical findings. The *manual* threat-model review is tracked for M12.
"""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

from esp.perf import report

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]


def test_m11_work_packages_verified() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    for wp in ("WP-043", "WP-044", "WP-080"):
        m = re.search(rf"^## {wp} — .*?\*\*Status:\*\* `([A-Z_]+)`", plan, re.S | re.M)
        assert m is not None
        assert m.group(1) == "VERIFIED", wp


def test_performance_report() -> None:
    r = report(n=int(os.environ.get("ESP_PERF_FRAMES", "100")))
    for p in r["profiles"]:
        assert p["wire_bytes_per_frame"] == p["v13_bytes_per_release"]
        assert p["max_sustainable_hz"] >= 50
    out = os.environ.get("ESP_REPORT_DIR")
    if out:
        Path(out, "M11-metrics.json").write_text(json.dumps(r, indent=2) + "\n")


@pytest.mark.slow
def test_security_review_has_no_findings(tmp_path: Path) -> None:
    iterations = os.environ.get("ESP_FUZZ_ITERATIONS", "20000")
    args = [
        sys.executable,
        "scripts/security_review.py",
        "--fuzz-iterations",
        iterations,
        "--json",
        str(tmp_path / "s.json"),
    ]
    if os.environ.get("ESP_OFFLINE"):
        args.append("--offline")
    proc = subprocess.run(args, cwd=ROOT, capture_output=True, text=True, check=False, timeout=7200)
    result = json.loads((tmp_path / "s.json").read_text())
    assert proc.returncode == 0, json.dumps(
        {k: v for k, v in result.items() if k != "allowlisted"}
    )[:3000]
    assert result["secrets"] == []
    assert result["unsafe_patterns"] == []


def test_every_v13_threat_is_mapped() -> None:
    doc = (ROOT / "docs" / "THREAT_MODEL.md").read_text(encoding="utf-8")
    for n in range(1, 20):
        row = next(line for line in doc.splitlines() if line.startswith(f"| T{n} |"))
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert cells[-1], f"T{n} has no status"
        for path in re.findall(r"`(tests/[^`:]+?)(?:::[^`]*)?`", row):
            assert (ROOT / path.split(" ")[0]).exists(), f"T{n}: {path} does not exist"
    assert "manual threat-model review" in doc
