# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Download selected files of an OpenNeuro BIDS dataset into ``data/external/`` (git-ignored).

Usage: uv run python scripts/fetch_openneuro.py [ds003688-seeg]

Files come from the public OpenNeuro S3 bucket. The dataset version is read from
``dataset_description.json`` (``DatasetDOI``), and every file is pinned by SHA-256
in ``data/external/<id>/MANIFEST.json``. Human recordings are never committed.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import urllib.request
from pathlib import Path
from typing import Final

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(os.environ.get("ESP_DATA_DIR", ROOT / "data" / "external"))
S3: Final = "https://s3.amazonaws.com/openneuro.org"
CHUNK = 8 * 1024 * 1024

_SUB1: Final = "sub-01/ses-iemu/ieeg/sub-01_ses-iemu"
#: id -> (OpenNeuro accession, relative paths)
DATASETS: Final[dict[str, tuple[str, tuple[str, ...]]]] = {
    "ds003688-seeg": (
        "ds003688",
        (
            "dataset_description.json",
            "participants.tsv",
            "participants.json",
            "README",
            f"{_SUB1}_acq-clinical_coordsystem.json",
            f"{_SUB1}_acq-clinical_electrodes.tsv",
            f"{_SUB1}_task-rest_acq-clinical_run-1_channels.tsv",
            f"{_SUB1}_task-rest_acq-clinical_run-1_ieeg.json",
            f"{_SUB1}_task-rest_acq-clinical_run-1_ieeg.vhdr",
            f"{_SUB1}_task-rest_acq-clinical_run-1_ieeg.vmrk",
            f"{_SUB1}_task-rest_acq-clinical_run-1_ieeg.eeg",
            f"{_SUB1}_task-rest_run-1_events.tsv",
        ),
    ),
}


def _download(url: str, dest: Path, attempts: int = 6) -> None:
    for attempt in range(attempts):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "esp-taoss-fetch/1"})  # noqa: S310
            part = dest.with_suffix(dest.suffix + ".part")
            with urllib.request.urlopen(req, timeout=120) as r, part.open("wb") as f:  # noqa: S310
                while chunk := r.read(CHUNK):
                    f.write(chunk)
            part.replace(dest)
            return
        except OSError:
            if attempt == attempts - 1:
                raise
            time.sleep(min(120, 5 * 2**attempt))


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def fetch(name: str) -> Path:
    accession, files = DATASETS[name]
    target = OUT / name
    pinned = {}
    for rel in files:
        dest = target / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.is_file():
            print(f"  downloading {rel}", flush=True)
            _download(f"{S3}/{accession}/{rel}", dest)
        pinned[rel] = {"size": dest.stat().st_size, "sha256": _sha256(dest)}
    desc = json.loads((target / "dataset_description.json").read_text(encoding="utf-8"))
    doi = str(desc.get("DatasetDOI", "")).removeprefix("doi:")
    manifest = {
        "id": name,
        "source": f"OpenNeuro {accession}",
        "version": doi.rsplit(".v", 1)[-1] if ".v" in doi else "unknown",
        "doi": doi,
        "license": desc.get("License"),
        "citation": desc.get("HowToAcknowledge"),
        "url": f"https://openneuro.org/datasets/{accession}",
        "personal_data": "de-identified human intracranial recordings; never commit",
        "files": pinned,
    }
    (target / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"{name}: {len(pinned)} files pinned, version {manifest['version']}")
    return target


def main(argv: list[str]) -> int:
    for name in argv or list(DATASETS):
        fetch(name)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
