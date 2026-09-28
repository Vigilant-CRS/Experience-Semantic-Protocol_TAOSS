# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M0 gate: fresh checkout -> install -> tests green, no manual configuration.

Clones the *committed* state of this repository into a temporary directory,
so uncommitted local changes cannot make the gate pass by accident.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

pytestmark = [pytest.mark.milestone, pytest.mark.slow]


def _run(cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("VIRTUAL_ENV", "UV_PROJECT"))}
    return subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, check=False)


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv not installed")
@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_fresh_clone_installs_and_passes(tmp_path: Path) -> None:
    clone = tmp_path / "clone"
    result = _run(["git", "clone", "--quiet", str(ROOT), str(clone)], cwd=tmp_path)
    assert result.returncode == 0, result.stderr

    for cmd in (
        ["uv", "sync", "--frozen"],
        ["uv", "run", "--frozen", "python", "-c", "import esp; print(esp.__version__)"],
        ["uv", "run", "--frozen", "ruff", "check", "src", "tests", "scripts"],
        ["uv", "run", "--frozen", "mypy"],
        ["uv", "run", "--frozen", "python", "scripts/verify_plan_sync.py"],
        ["uv", "run", "--frozen", "pytest", "tests/unit", "-q", "-p", "no:cacheprovider"],
    ):
        result = _run(cmd, cwd=clone)
        assert result.returncode == 0, f"{' '.join(cmd)} failed:\n{result.stdout}\n{result.stderr}"
