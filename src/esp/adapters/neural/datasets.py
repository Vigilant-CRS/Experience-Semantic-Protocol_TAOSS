# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Pinned public invasive neural datasets (M18, WP-088).

``datasets/neural.json`` pins each dataset used by M18 to a DANDI version.
Every file is identified by its asset id, size and SHA-256. The data itself
lives only in ``data/external/<id>/`` (git-ignored, downloaded by
``scripts/fetch_dandi.py``) and is never committed.

A DANDI *draft* version is mutable. For drafts, the pin is the list of asset
ids plus SHA-256 digests: a changed draft fails :func:`verify_local` instead
of being silently accepted.

- :func:`load_registry` reads the pins.
- :func:`verify_local` checks the local copy (missing, size or digest mismatch).
- :func:`replay_declaration` builds the
  :class:`~esp.adapters.neural.model.ReplayDeclaration` that the
  ``L4-REPLAY`` profile requires.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Any, Final

from esp.adapters.neural.model import ReplayDeclaration

ROOT: Final = Path(__file__).resolve().parents[4]
REGISTRY: Final = ROOT / "datasets" / "neural.json"
_CHUNK: Final = 8 * 1024 * 1024


class PinStatus(StrEnum):
    PINNED = "pinned"
    PENDING = "pending"
    """Declared, but no local manifest was available when the registry was built."""


@dataclass(frozen=True, slots=True)
class PinnedFile:
    path: str
    asset_id: str
    size: int
    sha256: str


@dataclass(frozen=True, slots=True)
class NeuralDataset:
    id: str
    dandiset: str
    title: str
    role: str
    selection: str
    consent_basis: str
    consent_pointer: str
    status: PinStatus
    version: str = ""
    version_mutable: bool = True
    license: str = ""
    citation: str = ""
    url: str = ""
    files: tuple[PinnedFile, ...] = ()

    @property
    def total_bytes(self) -> int:
        return sum(f.size for f in self.files)


def data_dir() -> Path:
    """``ESP_DATA_DIR`` or ``<repo>/data/external``."""
    env = os.environ.get("ESP_DATA_DIR")
    return Path(env) if env else ROOT / "data" / "external"


def _dataset(raw: dict[str, Any]) -> NeuralDataset:
    return NeuralDataset(
        id=raw["id"],
        dandiset=raw["dandiset"],
        title=raw["title"],
        role=raw["role"],
        selection=raw["selection"],
        consent_basis=raw["consent_basis"],
        consent_pointer=raw["consent_pointer"],
        status=PinStatus(raw["status"]),
        version=raw.get("version", ""),
        version_mutable=bool(raw.get("version_mutable", True)),
        license=raw.get("license", ""),
        citation=raw.get("citation", ""),
        url=raw.get("url", ""),
        files=tuple(
            PinnedFile(p, f["asset_id"], int(f["size"]), f["sha256"])
            for p, f in sorted(raw.get("files", {}).items())
        ),
    )


def load_registry(path: Path | None = None) -> dict[str, NeuralDataset]:
    raw = json.loads((path or REGISTRY).read_text(encoding="utf-8"))
    out = {d["id"]: _dataset(d) for d in raw["datasets"]}
    if len(out) != len(raw["datasets"]):
        msg = "duplicate dataset id in the neural registry"
        raise ValueError(msg)
    return out


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(_CHUNK):
            h.update(chunk)
    return h.hexdigest()


@dataclass(frozen=True, slots=True)
class VerifyReport:
    id: str
    checked: int = 0
    missing: tuple[str, ...] = field(default_factory=tuple)
    size_mismatch: tuple[str, ...] = field(default_factory=tuple)
    digest_mismatch: tuple[str, ...] = field(default_factory=tuple)
    deep: bool = True

    @property
    def complete(self) -> bool:
        return not self.missing

    @property
    def ok(self) -> bool:
        """Every pinned file is present and matches (size, and SHA-256 if ``deep``)."""
        return self.checked > 0 and not (self.missing or self.size_mismatch or self.digest_mismatch)


def verify_local(
    dataset_id: str,
    *,
    root: Path | None = None,
    deep: bool = True,
    registry: dict[str, NeuralDataset] | None = None,
) -> VerifyReport:
    """Compare the local copy with the pins. ``deep=False`` checks sizes only (fast)."""
    ds = (registry or load_registry())[dataset_id]
    if ds.status is not PinStatus.PINNED:
        msg = f"{dataset_id} is not pinned yet"
        raise ValueError(msg)
    base = (root or data_dir()) / ds.id
    missing, size_bad, digest_bad = [], [], []
    for f in ds.files:
        p = base / f.path
        if not p.is_file():
            missing.append(f.path)
        elif p.stat().st_size != f.size:
            size_bad.append(f.path)
        elif deep and sha256_file(p) != f.sha256:
            digest_bad.append(f.path)
    return VerifyReport(
        ds.id,
        checked=len(ds.files),
        missing=tuple(missing),
        size_mismatch=tuple(size_bad),
        digest_mismatch=tuple(digest_bad),
        deep=deep,
    )


def local_path(dataset_id: str, rel: str, *, root: Path | None = None) -> Path:
    """Absolute path of one pinned file (it need not exist)."""
    ds = load_registry()[dataset_id]
    if rel not in {f.path for f in ds.files}:
        msg = f"{rel!r} is not a pinned file of {dataset_id}"
        raise KeyError(msg)
    return (root or data_dir()) / ds.id / rel


def replay_declaration(
    dataset_id: str,
    *,
    root: Path | None = None,
    registry: dict[str, NeuralDataset] | None = None,
) -> ReplayDeclaration:
    """The ``L4-REPLAY`` declaration for a pinned dataset.

    ``manifest_sha256`` is the digest of the local ``MANIFEST.json`` when it
    exists (it binds a replay to the exact files on disk), else empty.
    """
    ds = (registry or load_registry())[dataset_id]
    if ds.status is not PinStatus.PINNED:
        msg = f"{dataset_id} is not pinned yet; run scripts/pin_neural_datasets.py"
        raise ValueError(msg)
    manifest = (root or data_dir()) / ds.id / "MANIFEST.json"
    return ReplayDeclaration(
        dataset_id=f"DANDI:{ds.dandiset}",
        version=ds.version,
        license=ds.license,
        consent_basis=ds.consent_basis,
        url=ds.url,
        citation=ds.citation,
        manifest_sha256=sha256_file(manifest) if manifest.is_file() else "",
    )
