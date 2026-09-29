# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Build ``datasets/neural.json`` from the local DANDI manifests (M18, WP-088).

Usage:
  uv run python scripts/pin_neural_datasets.py            # (re)build the registry
  uv run python scripts/pin_neural_datasets.py --verify   # also check local files (SHA-256)
  uv run python scripts/pin_neural_datasets.py --check    # registry consistent with SPEC?

The script reads ``data/external/<id>/MANIFEST.json`` as written by
``scripts/fetch_dandi.py``. Datasets without a local manifest stay ``pending``,
and a dataset pinned earlier is never dropped. Re-run it after further
downloads finish. Only metadata (ids, sizes, digests, license, citation) enters
the repository; human data never does.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from esp.adapters.neural.datasets import PinStatus, data_dir, load_registry, verify_local

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "datasets" / "neural.json"

_CONSENT = (
    "de-identified recordings shared by the data owners under the informed consent and "
    "ethics approval of the originating study; see the dandiset description and the "
    "associated publication"
)

#: static facts per dataset: DANDI id, role in M18, selection
SPEC: dict[str, dict[str, str]] = {
    "falcon-h1": {
        "dandiset": "000954",
        "title": "FALCON Benchmark H1: Human 7DoF Reach and Grasp Motor BCI",
        "role": "motor intent: attempted 7-DoF reach and grasp from intracortical arrays "
        "(held-in / held-out sessions for day drift)",
        "selection": "all assets",
    },
    "falcon-h2": {
        "dandiset": "000950",
        "title": "FALCON Benchmark H2: Human Handwriting iBCI",
        "role": "communication intent: attempted handwriting from intracortical arrays",
        "selection": "all assets",
    },
    "dandi-000019": {
        "dandiset": "000019",
        "title": "Human ECoG speaking consonant-vowel syllables",
        "role": "speech articulation: high-density ECoG during syllable production",
        "selection": "all assets",
    },
    "ajile12": {
        "dandiset": "000055",
        "title": "AJILE12: Long-term naturalistic human intracranial neural recordings and pose",
        "role": "naturalistic robustness: long unstructured ECoG sessions with pose",
        "selection": "sub-01 (all sessions) and sub-02 ses-3",
    },
}


def _license(raw: object) -> str:
    items = raw if isinstance(raw, list) else [raw]
    spdx = [str(x).removeprefix("spdx:") for x in items if x]
    return spdx[0] if spdx else ""


def build(previous: dict[str, Any], root: Path) -> dict[str, Any]:
    old = {d["id"]: d for d in previous.get("datasets", [])}
    out = []
    for ds_id, spec in SPEC.items():
        entry: dict[str, Any] = {
            "id": ds_id,
            **spec,
            "consent_basis": _CONSENT,
            "consent_pointer": f"https://dandiarchive.org/dandiset/{spec['dandiset']}",
            "status": PinStatus.PENDING.value,
        }
        manifest = root / ds_id / "MANIFEST.json"
        if manifest.is_file():
            m = json.loads(manifest.read_text(encoding="utf-8"))
            if m.get("dandiset") != spec["dandiset"]:
                msg = f"{manifest}: dandiset {m.get('dandiset')} != {spec['dandiset']}"
                raise ValueError(msg)
            version = str(m["version"])
            entry |= {
                "status": PinStatus.PINNED.value,
                "version": version,
                "version_mutable": version == "draft",
                "license": _license(m.get("license")),
                "citation": m.get("citation", ""),
                "url": m.get("url", ""),
                "files": {
                    p: {"asset_id": f["asset_id"], "size": f["size"], "sha256": f["sha256"]}
                    for p, f in sorted(m["files"].items())
                },
            }
        elif old.get(ds_id, {}).get("status") == PinStatus.PINNED.value:
            entry = old[ds_id]  # keep an earlier pin; never drop it
        out.append(entry)
    return {
        "_note": (
            "Public invasive neural datasets for M18 (WP-088). Metadata only: data are "
            "downloaded into data/external/<id>/ (git-ignored) by scripts/fetch_dandi.py and "
            "are never committed. Draft DANDI versions are mutable; the asset ids and SHA-256 "
            "digests below are the pin."
        ),
        "datasets": out,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--verify", action="store_true", help="check local files against the pins")
    ap.add_argument("--check", action="store_true", help="only check the registry against SPEC")
    ap.add_argument("--data-dir", type=Path, default=None)
    args = ap.parse_args(argv)
    root = args.data_dir or data_dir()
    if args.check:
        reg = load_registry(REGISTRY)
        if set(reg) != set(SPEC):
            print(f"registry ids {sorted(reg)} != {sorted(SPEC)}")
            return 1
        print("neural registry consistent")
        return 0
    previous = json.loads(REGISTRY.read_text(encoding="utf-8")) if REGISTRY.exists() else {}
    registry = build(previous, root)
    REGISTRY.write_text(json.dumps(registry, indent=1) + "\n", encoding="utf-8")
    for d in registry["datasets"]:
        print(f"{d['id']}: {d['status']} {d.get('version', '')} {len(d.get('files', {}))} files")
    if args.verify:
        bad = 0
        for ds_id, ds in load_registry(REGISTRY).items():
            if ds.status is not PinStatus.PINNED:
                continue
            rep = verify_local(ds_id, root=root)
            print(
                f"verify {ds_id}: {'OK' if rep.ok else 'FAIL'} "
                f"(missing {len(rep.missing)}, size {len(rep.size_mismatch)}, "
                f"digest {len(rep.digest_mismatch)})"
            )
            bad += not rep.ok
        return 1 if bad else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
