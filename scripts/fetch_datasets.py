# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Download registered open datasets into ``data/external/`` (git-ignored; WP-083).

Usage: uv run python scripts/fetch_datasets.py [dataset-id ...]

Writes ``data/external/<id>/MANIFEST.json`` with license, attribution, URLs and
SHA-256 of every file, so tests can verify what they read.
"""

from __future__ import annotations

import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "datasets" / "registry.json"
OUT = ROOT / "data" / "external"
MAX_BYTES = 64 * 1024 * 1024


def fetch(url: str, dest: Path) -> str:
    if not url.startswith("https://"):
        msg = f"refusing non-HTTPS URL {url}"
        raise ValueError(msg)
    request = urllib.request.Request(url, headers={"User-Agent": "esp-taoss-fetch/1"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 - https only
        data = response.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        msg = f"{url} exceeds {MAX_BYTES} bytes"
        raise ValueError(msg)
    dest.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def main(argv: list[str]) -> int:
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    wanted = set(argv)
    for ds in registry["datasets"]:
        if wanted and ds["id"] not in wanted:
            continue
        if "fetcher" in ds:  # large or streamed data has its own fetcher
            print(f"{ds['id']}: use {ds['fetcher']}")
            continue
        target = OUT / ds["id"]
        target.mkdir(parents=True, exist_ok=True)
        files = {}
        for url in ds["files"]:
            name = url.rsplit("/", 1)[1]
            files[name] = {"url": url, "sha256": fetch(url, target / name)}
            print(f"{ds['id']}: {name}")
        manifest = {
            k: ds[k] for k in ("id", "title", "license", "attribution", "landing", "personal_data")
        }
        manifest["files"] = files
        (target / "MANIFEST.json").write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
