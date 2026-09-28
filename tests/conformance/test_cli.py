# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-039: the conformance runner passes on this implementation and detects breakage."""

import json
import shutil
from pathlib import Path

import pytest

from esp.conformance.runner import DEFAULT_VECTORS, Suite, main

pytestmark = pytest.mark.conformance


def test_runner_passes_every_category(tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    assert main(["run", "--json", str(out)]) == 0
    report = json.loads(out.read_text())
    assert report["passed"] is True
    assert set(report["summary"]) >= {
        "index",
        "wire",
        "malformed",
        "crypto",
        "consent",
        "revocation",
        "identity",
        "session",
        "replay",
        "privacy",
        "ontology",
    }


def copy_vectors(tmp_path: Path) -> Path:
    dst = tmp_path / "vectors"
    shutil.copytree(DEFAULT_VECTORS, dst)
    return dst


def test_tampered_vector_file_fails_the_index(tmp_path: Path) -> None:
    v = copy_vectors(tmp_path)
    p = v / "replay" / "windows.json"
    p.write_text(p.read_text().replace('"w_back"', '"w_back" ', 1))
    report = Suite(v).run_all()
    assert not report.passed
    assert report.summary()["index"]["failed"] == 1


def test_accepting_a_malformed_input_is_a_failure(tmp_path: Path) -> None:
    v = copy_vectors(tmp_path)
    p = v / "malformed" / "header_invalid.json"
    doc = json.loads(p.read_text())
    good = json.loads((v / "wire" / "header_valid.json").read_text())["vectors"][0]["hex"]
    doc["vectors"][0]["hex"] = good  # a valid header listed as malformed must be caught
    p.write_text(json.dumps(doc))
    report = Suite(v).run_all()
    failed = [r for r in report.results if not r.passed]
    assert any(r.category == "malformed" and "accepted" in r.detail for r in failed)
