# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-090: C-ABI vendor adapters (``include/esp_neural.h``) via ``esp-rs neural-capi``.

The example adapter in ``examples/neural_vendor_adapter_c`` is compiled with the system C
compiler; each of its modes must be accepted or refused with the same rules by the Rust host
and the Python checker.
"""

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from esp.conformance import neural
from esp.conformance.runner import DEFAULT_VECTORS, Suite, main

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "rust" / "esp-rs"
EXAMPLE = ROOT / "examples" / "neural_vendor_adapter_c" / "esp_example_adapter.c"
CARGO = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo")
CC = shutil.which("cc")

if CC is None or not Path(CARGO).exists():  # pragma: no cover
    pytest.skip("C compiler or Rust toolchain not available", allow_module_level=True)


@pytest.fixture(scope="module")
def esp_rs() -> Path:
    subprocess.run([CARGO, "build", "--release", "--quiet"], cwd=CRATE, check=True, timeout=900)
    target = Path(os.environ.get("CARGO_TARGET_DIR", CRATE / "target"))
    return target / "release" / "esp-rs"


@pytest.fixture(scope="module")
def library(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("capi") / "libesp_example_adapter.so"
    cmd = [str(CC), "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror"]
    cmd += ["-I", str(CRATE / "include"), str(EXAMPLE), "-o", str(out), "-lm"]
    subprocess.run(cmd, check=True, timeout=120)
    return out


@pytest.mark.parametrize("mode", sorted(neural.C_EXAMPLE_MODES))
def test_rust_host_and_python_agree_on_every_c_mode(esp_rs: Path, library: Path, mode: str) -> None:
    neural.check_c_adapter(esp_rs, library, mode, neural.C_EXAMPLE_MODES[mode])


def test_c_replay_transcript_carries_the_declaration(esp_rs: Path, library: Path) -> None:
    adapter = neural.run_c_adapter(esp_rs, library, "l4-replay")
    assert adapter.info.replay is not None
    assert adapter.info.replay.license == "CC0-1.0"
    assert adapter.verdict is not None
    assert adapter.verdict["ok"] is True
    assert adapter.verdict["samples"] == neural.RUST_BLOCKS * neural.RUST_SAMPLES


def test_wrong_expectation_fails_the_check(esp_rs: Path, library: Path) -> None:
    with pytest.raises(neural.NeuralConformanceError, match="expected"):
        neural.check_c_adapter(esp_rs, library, "inf-sample", frozenset())


def test_a_library_without_the_entry_point_is_refused(esp_rs: Path, tmp_path: Path) -> None:
    src = tmp_path / "empty.c"
    src.write_text("int not_the_entry_point(void) { return 0; }\n")
    lib = tmp_path / "libempty.so"
    subprocess.run([str(CC), "-shared", "-fPIC", str(src), "-o", str(lib)], check=True)
    with pytest.raises(neural.NeuralConformanceError, match="refused"):
        neural.run_c_adapter(esp_rs, lib)


def test_runner_checks_a_c_library(esp_rs: Path, library: Path) -> None:
    suite = Suite(DEFAULT_VECTORS, neural_rust=esp_rs, neural_c=library)
    suite.neural()
    c = [r for r in suite.report.results if r.name.startswith("c:")]
    assert len(c) == 1
    assert c[0].passed, c[0]


def test_runner_fails_a_broken_c_library(esp_rs: Path, library: Path) -> None:
    suite = Suite(
        DEFAULT_VECTORS, neural_rust=esp_rs, neural_c=library, neural_c_config="non-monotonic-clock"
    )
    suite.neural()
    c = [r for r in suite.report.results if r.name.startswith("c:")]
    assert len(c) == 1
    assert not c[0].passed


def test_cli_requires_the_rust_host_for_c(library: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["run", "--neural-c", str(library)])
    assert exc.value.code == 2
