# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-083: dataset register completeness and manifest verification."""

import json
from pathlib import Path

import pytest

from esp.bench.datasets import DATA, load_registry, verify


def test_register_is_complete() -> None:
    entries = load_registry()
    assert len(entries) >= 5
    for e in entries:
        assert e.license
        assert e.attribution
        assert e.files


def test_register_rejects_missing_consent_status(tmp_path: Path) -> None:
    bad = tmp_path / "r.json"
    bad.write_text(
        json.dumps(
            {
                "datasets": [
                    {
                        "id": "x",
                        "license": "MIT",
                        "attribution": "a",
                        "split_unit": "subject",
                        "files": ["u"],
                    }
                ]
            }
        )
    )
    with pytest.raises(ValueError, match="consent_status"):
        load_registry(bad)


@pytest.mark.dataset
@pytest.mark.skipif(not DATA.exists(), reason="run scripts/fetch_datasets.py")
def test_downloaded_datasets_match_their_manifests(tmp_path: Path) -> None:
    for e in load_registry():
        if (DATA / e.id).exists():
            assert verify(e.id)
    corrupt = tmp_path / "x"
    corrupt.mkdir()
    (corrupt / "a.bin").write_bytes(b"changed")
    (corrupt / "MANIFEST.json").write_text(json.dumps({"files": {"a.bin": {"sha256": "0" * 64}}}))
    with pytest.raises(ValueError, match="digest mismatch"):
        verify("x", root=tmp_path)
