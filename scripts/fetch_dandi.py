# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Download open neural datasets from DANDI into ``data/external/`` (git-ignored; M18).

Usage:
  uv run python scripts/fetch_dandi.py falcon-h1 falcon-h2      # whole (small) dandisets
  uv run python scripts/fetch_dandi.py dandi-000019 --max-files 2
  uv run python scripts/fetch_dandi.py --list ajile12            # show assets and sizes only

Pins the most recent *published* version when one exists (else the draft,
recorded as such). Streams every asset to disk, verifies the SHA-256 that
DANDI stores for it, resumes by skipping verified files, and writes
``data/external/<id>/MANIFEST.json`` with license, citation, version and the
digest of every file. Human neural data is **never committed**; only the
manifest structure is referenced by tests.
"""

from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "data" / "external"
API = "https://api.dandiarchive.org/api"
CHUNK = 8 * 1024 * 1024

#: id -> (dandiset, path glob, default max files)
DATASETS: dict[str, tuple[str, str, int | None]] = {
    "falcon-h1": ("000954", "*", None),
    "falcon-h2": ("000950", "*", None),
    "dandi-000019": ("000019", "*", None),
    "ajile12": ("000055", "sub-0[12]/*", 5),  # subject 1 (4 days) + subject 2 day 1, ~72 GB
}


def _get(url: str) -> Any:  # noqa: ANN401 - JSON
    req = urllib.request.Request(url, headers={"User-Agent": "esp-taoss-fetch/1"})  # noqa: S310
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 - fixed https API
                return json.load(r)
        except OSError:
            if attempt == 4:
                raise
            time.sleep(2**attempt)
    return None  # pragma: no cover


def version_of(dandiset: str) -> str:
    d = _get(f"{API}/dandisets/{dandiset}/")
    published = d.get("most_recent_published_version") or {}
    return published.get("version") or "draft"


def assets(dandiset: str, version: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    url: str | None = f"{API}/dandisets/{dandiset}/versions/{version}/assets/?page_size=200"
    while url:
        page = _get(url)
        out.extend(page["results"])
        url = page["next"]
    return sorted(out, key=lambda a: a["path"])


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(CHUNK):
            h.update(chunk)
    return h.hexdigest()


def download(asset_id: str, dest: Path, size: int, attempts: int = 8) -> None:
    """Download with resume (HTTP Range) and exponential backoff on connection errors."""
    for attempt in range(attempts):
        try:
            _download_once(asset_id, dest, size)
            return
        except OSError as exc:
            if attempt == attempts - 1:
                raise
            wait = min(300, 5 * 2**attempt)
            print(f"  retry {attempt + 1}/{attempts - 1} in {wait}s after: {exc}", flush=True)
            time.sleep(wait)


def _download_once(asset_id: str, dest: Path, size: int) -> None:
    url = f"{API}/assets/{asset_id}/download/"
    part = dest.with_suffix(dest.suffix + ".part")
    have = part.stat().st_size if part.exists() else 0
    headers = {"User-Agent": "esp-taoss-fetch/1"}
    if 0 < have < size:
        headers["Range"] = f"bytes={have}-"
    req = urllib.request.Request(url, headers=headers)  # noqa: S310
    with urllib.request.urlopen(req, timeout=120) as r, part.open("ab" if have else "wb") as f:  # noqa: S310
        if have and r.status != 206:  # server ignored the range: start over
            f.seek(0)
            f.truncate()
        while chunk := r.read(CHUNK):
            f.write(chunk)
    part.replace(dest)


def fetch(name: str, max_files: int | None, list_only: bool) -> None:
    dandiset, glob, default_max = DATASETS[name]
    version = version_of(dandiset)
    meta = _get(f"{API}/dandisets/{dandiset}/versions/{version}/info/")
    full = _get(f"{API}/dandisets/{dandiset}/versions/{version}/")
    chosen = [a for a in assets(dandiset, version) if fnmatch.fnmatch(a["path"], glob)]
    limit = max_files if max_files is not None else default_max
    if limit is not None:
        chosen = chosen[:limit]
    total = sum(a["size"] for a in chosen)
    print(f"{name}: DANDI {dandiset} version {version}, {len(chosen)} files, {total / 1e9:.2f} GB")
    if list_only:
        for a in chosen:
            print(f"  {a['size'] / 1e6:10.1f} MB  {a['path']}")
        return
    target = OUT / name
    target.mkdir(parents=True, exist_ok=True)
    files = {}
    for a in chosen:
        dest = target / a["path"]
        dest.parent.mkdir(parents=True, exist_ok=True)
        info = _get(f"{API}/assets/{a['asset_id']}/")
        expected = (info.get("digest") or {}).get("dandi:sha2-256")
        if not (dest.exists() and dest.stat().st_size == a["size"]):
            print(f"  downloading {a['path']} ({a['size'] / 1e6:.1f} MB)", flush=True)
            download(a["asset_id"], dest, a["size"])
        digest = sha256_of(dest)
        if expected and digest != expected:
            dest.unlink()
            msg = f"SHA-256 mismatch for {a['path']}"
            raise RuntimeError(msg)
        files[a["path"]] = {
            "asset_id": a["asset_id"],
            "size": a["size"],
            "sha256": digest,
            "verified_against_dandi": bool(expected),
        }
    manifest = {
        "id": name,
        "dandiset": dandiset,
        "version": version,
        "title": meta.get("name") or full.get("name"),
        "license": full.get("license"),
        "citation": full.get("citation"),
        "url": f"https://dandiarchive.org/dandiset/{dandiset}/{version}",
        "personal_data": "de-identified human neural recordings; never commit",
        "files": files,
    }
    (target / "MANIFEST.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"{name}: done, manifest written")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("ids", nargs="*", help=f"dataset ids: {sorted(DATASETS)}")
    ap.add_argument("--max-files", type=int, default=None)
    ap.add_argument("--list", action="store_true")
    args = ap.parse_args(argv)
    for name in args.ids or list(DATASETS):
        fetch(name, args.max_files, args.list)
    return 0


if __name__ == "__main__":
    sys.exit(main())
