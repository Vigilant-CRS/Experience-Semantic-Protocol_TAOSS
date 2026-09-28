# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-076: license governance is enforced, not just documented."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_reuse_lint_rejects_a_file_without_spdx_header(tmp_path: Path) -> None:
    (tmp_path / "LICENSES").mkdir()
    shutil.copy(ROOT / "LICENSES" / "AGPL-3.0-or-later.txt", tmp_path / "LICENSES")
    spdx = "SPDX"  # split so that REUSE does not read this test's strings as its own header
    (tmp_path / "ok.py").write_text(
        f"# {spdx}-FileCopyrightText: 2026 Vigilant e.K. and contributors\n"
        f"# {spdx}-License-Identifier: AGPL-3.0-or-later\n"
    )
    ok = subprocess.run(
        [sys.executable, "-m", "reuse", "--root", str(tmp_path), "lint"],
        capture_output=True,
        check=False,
    )
    assert ok.returncode == 0, ok.stdout
    (tmp_path / "new_file.py").write_text("print('no header')\n")
    bad = subprocess.run(
        [sys.executable, "-m", "reuse", "--root", str(tmp_path), "lint"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode != 0
    assert "new_file.py" in bad.stdout


def test_ci_enforces_reuse_and_dco() -> None:
    ci = (ROOT / ".github" / "workflows" / "ci.yml").read_text()
    assert "make verify-full" in ci  # verify-full runs `reuse lint`
    assert "Signed-off-by" in ci  # DCO job on pull requests
    make = (ROOT / "Makefile").read_text()
    assert "reuse lint" in make


@pytest.mark.parametrize(
    "doc",
    [
        "LICENSE",
        "NOTICE",
        "TRADEMARKS.md",
        "CONTRIBUTING.md",
        "docs/LICENSING.md",
        "docs/CONFORMANCE.md",
    ],
)
def test_governance_documents_exist(doc: str) -> None:
    assert (ROOT / doc).stat().st_size > 200
