# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Dataset register (WP-083, GAP-023): license, consent status, split unit, digests.

``datasets/registry.json`` lists every external dataset with its license,
attribution, consent status and the split unit that benchmark splits must
respect. Downloaded copies carry a ``MANIFEST.json`` with SHA-256 per file;
:func:`verify` recomputes them so tests know exactly what they read.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from esp.bench.prereg import SplitUnit

ROOT = Path(__file__).resolve().parents[3]
REGISTRY = ROOT / "datasets" / "registry.json"
DATA = ROOT / "data" / "external"
CONSENT_STATUSES = frozenset(
    {
        "participant_consent_documented_by_source",
        "test_fixture_no_personal_data",
        "synthetic",
        # public posts collected under the platform's terms, no individual research consent:
        # aggregate, non-re-identifying text research only
        "public_text_platform_terms",
    }
)
SPLIT_UNITS = {
    "subject": SplitUnit.SUBJECT,
    "session": SplitUnit.SESSION,
    "recording": SplitUnit.MEDIA_ITEM,
    "text_item": SplitUnit.MEDIA_ITEM,
}


@dataclass(frozen=True, slots=True)
class DatasetEntry:
    id: str
    license: str
    attribution: str
    consent_status: str
    split_unit: SplitUnit
    files: tuple[str, ...]


def load_registry(path: Path = REGISTRY) -> list[DatasetEntry]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for e in raw["datasets"]:
        missing = {"id", "license", "attribution", "consent_status", "split_unit", "files"} - set(e)
        if missing:
            msg = f"dataset {e.get('id')}: missing fields {sorted(missing)}"
            raise ValueError(msg)
        if e["consent_status"] not in CONSENT_STATUSES:
            msg = f"dataset {e['id']}: unknown consent status {e['consent_status']!r}"
            raise ValueError(msg)
        out.append(
            DatasetEntry(
                id=e["id"],
                license=e["license"],
                attribution=e["attribution"],
                consent_status=e["consent_status"],
                split_unit=SPLIT_UNITS[e["split_unit"]],
                files=tuple(e["files"]),
            )
        )
    ids = [e.id for e in out]
    if len(set(ids)) != len(ids):
        msg = "dataset ids must be unique"
        raise ValueError(msg)
    return out


def verify(dataset_id: str, root: Path = DATA) -> dict[str, str]:
    """Recompute SHA-256 of a downloaded dataset against its manifest; returns the digests."""
    folder = root / dataset_id
    manifest = json.loads((folder / "MANIFEST.json").read_text(encoding="utf-8"))
    digests = {}
    for name, entry in sorted(manifest["files"].items()):
        expected = entry["sha256"]
        actual = hashlib.sha256((folder / name).read_bytes()).hexdigest()
        if actual != expected:
            msg = f"{dataset_id}/{name}: digest mismatch"
            raise ValueError(msg)
        digests[name] = actual
    return digests
