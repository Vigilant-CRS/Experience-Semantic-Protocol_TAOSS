# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-090: the Rust neural contract (``esp-rs neural-sim``) agrees with the Python checker."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from esp.conformance import neural
from esp.conformance.runner import DEFAULT_VECTORS, Suite
from esp.neural_sdk import CONTRACT_VERSION

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "rust" / "esp-rs"
CARGO = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo")

if not Path(CARGO).exists():  # pragma: no cover
    pytest.skip("Rust toolchain not available", allow_module_level=True)


@pytest.fixture(scope="module")
def esp_rs() -> Path:
    subprocess.run([CARGO, "build", "--release", "--quiet"], cwd=CRATE, check=True, timeout=900)
    target = Path(os.environ.get("CARGO_TARGET_DIR", CRATE / "target"))
    return target / "release" / "esp-rs"


@pytest.mark.parametrize("mode", sorted(neural.RUST_BREAK_MODES))
def test_rust_and_python_agree_on_every_break_mode(esp_rs: Path, mode: str) -> None:
    neural.check_rust_mode(esp_rs, mode, neural.RUST_BREAK_MODES[mode])


def test_rust_transcript_declares_the_contract_version(esp_rs: Path) -> None:
    adapter = neural.run_rust_sim(esp_rs, "l4-replay")
    assert adapter.contract_version == CONTRACT_VERSION
    assert adapter.info.replay is not None
    assert adapter.verdict is not None
    assert adapter.verdict["ok"] is True


def test_unknown_break_mode_is_an_error(esp_rs: Path) -> None:
    out = subprocess.run(
        [str(esp_rs), "neural-sim", "--break", "nope"], capture_output=True, text=True, check=False
    )
    assert out.returncode == 1
    assert "unknown --break" in out.stderr


def test_conformance_runner_cross_checks_rust(esp_rs: Path) -> None:
    suite = Suite(DEFAULT_VECTORS, neural_rust=esp_rs)
    suite.neural()
    rust = [r for r in suite.report.results if r.name.startswith("rust:")]
    assert len(rust) == len(neural.RUST_BREAK_MODES)
    assert all(r.passed for r in rust), [r for r in rust if not r.passed]
