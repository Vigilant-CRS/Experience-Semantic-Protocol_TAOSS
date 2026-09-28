# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generate JSON Schemas for the logical ESP objects into ``schemas/``.

Usage: uv run python scripts/generate_schemas.py [--check]
With ``--check`` the committed schemas are compared instead of written.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from esp.calibration.model import CalibrationProfile
from esp.core.model import EspModel
from esp.evidence.claim import EvidenceClaim
from esp.frame.model import ExperienceFrame
from esp.observation.model import Observation
from esp.ontology.registry import Anchor, Registry
from esp.semantics.bindings import SemanticBinding

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "schemas"
BASE_URI = "https://github.com/Vigilant-CRS/Experience-Semantic-Protocol_TAOSS/schemas/"

SCHEMAS: dict[str, type[EspModel]] = {
    "observation": Observation,
    "evidence_claim": EvidenceClaim,
    "experience_frame": ExperienceFrame,
    "semantic_binding": SemanticBinding,
    "anchor": Anchor,
    "registry": Registry,
    "calibration": CalibrationProfile,
}


def render(name: str, model: type[EspModel]) -> str:
    schema = model.model_json_schema(mode="validation")
    schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": f"{BASE_URI}{name}.schema.json",
        **schema,
    }
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = []
    for name, model in SCHEMAS.items():
        path = OUT / f"{name}.schema.json"
        text = render(name, model)
        if check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(path.name)
        else:
            path.write_text(text, encoding="utf-8")
    if stale:
        print(f"stale schemas (run scripts/generate_schemas.py): {', '.join(stale)}")
        return 1
    print("schemas up to date" if check else f"wrote {len(SCHEMAS)} schemas to {OUT}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
