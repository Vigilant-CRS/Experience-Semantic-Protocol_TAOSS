# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Loading of registered vocabulary profiles from the ``ontology/`` data tree."""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path
from typing import Any, Final

from esp.ontology.registry import Anchor, AnchorSet, Registry, Vocabulary

BASIC8_ID: Final = "esp-emo-v13-basic8-v1"
BASIC8_ORDER: Final = (
    "joy",
    "trust",
    "fear",
    "surprise",
    "sadness",
    "anger",
    "disgust",
    "anticipation",
)


def ontology_root() -> Path:
    """Location of the ontology data (wheel: ``esp/_ontology``; source tree: ``ontology/``)."""
    packaged = resources.files("esp") / "_ontology"
    if packaged.is_dir():
        return Path(str(packaged))
    source_tree = Path(__file__).resolve().parents[3] / "ontology"
    if source_tree.is_dir():
        return source_tree
    msg = "ontology data not found"
    raise FileNotFoundError(msg)


def _load_profile(relative: str) -> dict[str, Any]:
    with (ontology_root() / relative).open(encoding="utf-8") as fh:
        data: dict[str, Any] = json.load(fh)
    return data


def profile_registry(relative: str, *, name: str, version: str) -> Registry:
    """Build a registry from one profile file (vocabulary + anchor set + anchors)."""
    data = _load_profile(relative)
    return Registry(
        name=name,
        version=version,
        anchors=tuple(Anchor.from_data(a) for a in data["anchors"]),
        vocabularies=(Vocabulary.from_data(data["vocabulary"]),),
        anchor_sets=(AnchorSet.from_data(data["anchor_set"]),),
    )


def basic8_registry() -> Registry:
    """Registry with the V13 L1 default EMO profile ``esp-emo-v13-basic8-v1``."""
    return profile_registry(f"emo/{BASIC8_ID}.json", name=BASIC8_ID, version="1.0.0")
