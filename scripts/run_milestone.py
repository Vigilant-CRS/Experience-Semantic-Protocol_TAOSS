# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Run a milestone gate and write artifacts/test-reports/<M>.json (plan section 55).

Usage: uv run python scripts/run_milestone.py M0
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORTS = ROOT / "artifacts" / "test-reports"

#: Gate test selections per milestone. Every milestone also runs the full suite.
GATES: dict[str, list[str]] = {
    "M0": ["tests/milestone/test_m0.py"],
    "M1": ["tests/milestone/test_m1.py"],
    "M2": ["tests/milestone/test_m2.py"],
    "M3": [
        "tests/milestone/test_m3.py",
        "tests/conformance",
        "tests/unit/test_header_codec.py",
        "tests/unit/test_tlv_codec.py",
        "tests/unit/test_crypto.py",
        "tests/unit/test_identity.py",
        "tests/unit/session",
        "tests/unit/test_consent.py",
        "tests/unit/test_keys_revocation.py",
        "tests/unit/test_provenance.py",
        "tests/unit/test_structure_tlvs.py",
        "tests/unit/frame/test_frame_wire.py",
        "tests/integration",
        "tests/fuzz",
    ],
    "M3a": [
        "tests/milestone/test_m3a.py",
        "tests/unit/test_keys_revocation.py",
        "tests/unit/privacy",
        "tests/unit/test_custody.py",
        "tests/integration/test_endpoint_dp.py",
        "tests/integration/test_endpoint.py",
    ],
    "M4": [
        "tests/milestone/test_m4.py",
        "tests/integration/test_transport.py",
        "tests/integration/test_resilience.py",
        "tests/integration/test_metadata_protection.py",
        "tests/unit/session",
    ],
    "M6": [
        "tests/milestone/test_m6.py",
        "tests/integration/test_physio_streams.py",
        "tests/unit/adapters/test_physio_files.py",
        "tests/unit/features",
        "tests/unit/calibration",
    ],
    "M7": [
        "tests/milestone/test_m7.py",
        "tests/unit/estimators",
        "tests/unit/calibration",
        "tests/unit/regulatory",
    ],
    "M8": ["tests/milestone/test_m8.py", "tests/unit/training"],
    "M9": [
        "tests/milestone/test_m9.py",
        "tests/unit/audit",
        "tests/unit/bench",
        "tests/unit/training/test_leakage.py",
    ],
    "M10": ["tests/milestone/test_m10.py", "tests/interop", "tests/conformance"],
    "M11": ["tests/milestone/test_m11.py", "tests/failure_modes", "tests/integration/test_perf.py"],
    "M5": [
        "tests/milestone/test_m5.py",
        "tests/unit/demo",
        "tests/unit/decoder",
        "tests/unit/regulatory",
        "tests/integration/test_receiver_threats.py",
    ],
}


#: Extra environment per gate (e.g. the M6 30-minute soak).
GATE_ENV: dict[str, dict[str, str]] = {
    "M6": {"ESP_SOAK_SECONDS": "1800"},
    "M11": {"ESP_FUZZ_ITERATIONS": "1000000", "ESP_PERF_FRAMES": "300"},
}


def git(*args: str) -> str:
    out = subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True)
    return out.stdout.strip()


def run_pytest(selection: list[str], junit: Path, env: dict[str, str] | None = None) -> int:
    cmd = [sys.executable, "-m", "pytest", "-q", f"--junitxml={junit}", *selection]
    return subprocess.run(cmd, cwd=ROOT, check=False, env=env).returncode


def summarize(junit: Path) -> dict[str, int]:
    root = ET.parse(junit).getroot()  # noqa: S314 - trusted local file
    suites = [root] if root.tag == "testsuite" else list(root)
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    for suite in suites:
        for key in totals:
            totals[key] += int(suite.get(key, "0"))
    failed = totals["failures"] + totals["errors"]
    return {
        "passed": totals["tests"] - failed - totals["skipped"],
        "failed": failed,
        "skipped": totals["skipped"],
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[1] not in GATES:
        print(f"usage: run_milestone.py {{{','.join(GATES)}}}")
        return 2
    milestone = argv[1]
    dirty = bool(git("status", "--porcelain"))
    with tempfile.TemporaryDirectory() as tmp:
        gate_junit = Path(tmp) / "gate.xml"
        full_junit = Path(tmp) / "full.xml"
        gate_rc = run_pytest(
            GATES[milestone],
            gate_junit,
            os.environ | {"ESP_REPORT_DIR": tmp} | GATE_ENV.get(milestone, {}),
        )
        metrics_file = Path(tmp) / f"{milestone}-metrics.json"
        metrics = json.loads(metrics_file.read_text()) if metrics_file.exists() else None
        full_rc = run_pytest(["tests"], full_junit)
        gate = summarize(gate_junit)
        full = summarize(full_junit)

    verdict = "PASS" if gate_rc == 0 and full_rc == 0 and gate["passed"] > 0 else "FAIL"
    if dirty:
        verdict = "FAIL"
    report = {
        "milestone": milestone,
        "git_commit": git("rev-parse", "HEAD"),
        "working_tree_dirty": dirty,
        "timestamp": datetime.now(UTC).isoformat(timespec="seconds"),
        "environment": {
            "python": platform.python_version(),
            "platform": platform.platform(),
            "machine": platform.machine(),
        },
        "command_line": " ".join(argv),
        "tests": {"gate": gate, "full_suite": full},
        **({"metrics": metrics} if metrics is not None else {}),
        "verdict": verdict,
    }
    REPORTS.mkdir(parents=True, exist_ok=True)
    out = REPORTS / f"{milestone}.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"{milestone}: {verdict} -> {out.relative_to(ROOT)}")
    if dirty:
        print("working tree is dirty: commit first; a dirty tree can never PASS")
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
