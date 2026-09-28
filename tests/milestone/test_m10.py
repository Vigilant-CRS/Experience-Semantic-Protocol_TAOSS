# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M10 gate: conformance and an independent implementation.

Python <-> Rust interoperability is fully green: the conformance runner
(WP-039) passes every vector category and all live interop cells against
the independent Rust implementation (WP-040/041), whose own test suite also
passes the shared vectors; the full matrix is in ``tests/interop``.
"""

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from esp.conformance.runner import main

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "rust" / "esp-rs"
CARGO = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo")


def test_m10_work_packages_verified() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    for wp in ("WP-039", "WP-040", "WP-041", "WP-042"):
        m = re.search(rf"^## {wp} — .*?\*\*Status:\*\* `([A-Z_]+)`", plan, re.S | re.M)
        assert m is not None
        assert m.group(1) == "VERIFIED", wp


@pytest.mark.skipif(not Path(CARGO).exists(), reason="Rust toolchain not available")
def test_conformance_runner_with_rust_peer(tmp_path: Path) -> None:
    subprocess.run([CARGO, "build", "--release", "--quiet"], cwd=CRATE, check=True, timeout=900)
    peer = CRATE / "target" / "release" / "esp-rs"
    assert main(["run", "--peer", str(peer), "--json", str(tmp_path / "r.json")]) == 0
    assert '"interop"' in (tmp_path / "r.json").read_text()
