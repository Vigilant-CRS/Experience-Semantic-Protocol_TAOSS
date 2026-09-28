# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-010 acceptance tests.

The synthetic fixture exercises every rule. The real legacy ontology is
proprietary and not part of this repository; set
``ESP_LEGACY_MOVIE_ONTOLOGY=/path/to/config/ontology_v3`` to run the
real-data tests as well.
"""

import json
import os
import shutil
from pathlib import Path

import pytest

from esp.adapters.legacy_movie.ontology import (
    VOCABULARY_ID,
    LegacyOntologyError,
    LegacyRetrievalWeights,
    MatchKind,
    basic8_mapping,
    load_legacy_ontology,
    to_registry,
)
from esp.ontology.profiles import BASIC8_ORDER
from esp.semantics.affect import CategoryEstimate

FIXTURE = Path(__file__).resolve().parents[2] / "fixtures" / "legacy_movie_minimal"
REAL = os.environ.get("ESP_LEGACY_MOVIE_ONTOLOGY")


def test_fixture_imports_and_all_tags_resolve() -> None:
    legacy = load_legacy_ontology(FIXTURE)
    registry, report = to_registry(legacy)
    for tag in (*legacy.emotion_tags, *legacy.impact_tags):
        assert registry.resolve_label(VOCABULARY_ID, tag).id == f"esp:emo:movie3-{tag}:v1"
        assert registry.resolve_label(VOCABULARY_ID, f"movie3-{tag}").label == f"movie3-{tag}"
    assert registry.resolve_label(VOCABULARY_ID, "gladness").label == "movie3-joy"
    assert registry.resolve_label(VOCABULARY_ID, "happy-mood").label == "movie3-joy"
    dropped = {(t, s): r for t, s, r in report.dropped_synonyms}
    assert dropped == {
        ("joy", "shared-word"): "ambiguous across tags",
        ("fear", "shared-word"): "ambiguous across tags",
        ("fear", "dread"): "collides with a tag",
        ("fear", "bad!chars"): "invalid label syntax",
    }
    assert report.source_version == "v9.9.9"


def test_mapping_is_reproducible() -> None:
    a, _ = to_registry(load_legacy_ontology(FIXTURE))
    b, _ = to_registry(load_legacy_ontology(FIXTURE))
    assert a.digest_hex() == b.digest_hex()


def test_basic8_mapping_rules() -> None:
    legacy = load_legacy_ontology(FIXTURE)
    assert basic8_mapping(legacy, "contentment").basic8_label == "joy"  # type: ignore[union-attr]
    despair = basic8_mapping(legacy, "despair")
    assert despair is not None
    assert (despair.basic8_label, despair.match) == ("sadness", MatchKind.APPROXIMATE)
    assert basic8_mapping(legacy, "uplifting") is None  # impact tag: no affect mapping
    anchor = to_registry(legacy)[0].resolve_label(VOCABULARY_ID, "fear")
    assert "maps-to:esp-emo-v13-basic8-v1:esp:emo:fear:v1:narrower" in anchor.references
    assert anchor.definition.startswith("[emotion tag; content-side]")


def test_retrieval_normalization_is_isolated() -> None:
    w = LegacyRetrievalWeights({"fear": 0.5, "dread": 0.3, "uplifting": 0.2})
    with pytest.raises(LegacyOntologyError, match="cannot be converted"):
        w.to_category_intensities()
    with pytest.raises(LegacyOntologyError, match="L1-normalized"):
        LegacyRetrievalWeights({"fear": 0.8, "dread": 0.7})
    # the psychological model has no field that could hold a retrieval weight
    assert "retrieval_weight" not in CategoryEstimate.model_fields


def test_malformed_sources_rejected(tmp_path: Path) -> None:
    shutil.copytree(FIXTURE, tmp_path / "o")
    emotions = json.loads((tmp_path / "o" / "emotions.json").read_text())
    emotions["families"]["joy"].append("fear")
    (tmp_path / "o" / "emotions.json").write_text(json.dumps(emotions))
    with pytest.raises(LegacyOntologyError, match="exactly one family"):
        load_legacy_ontology(tmp_path / "o")
    with pytest.raises(LegacyOntologyError, match="missing"):
        load_legacy_ontology(tmp_path / "does-not-exist")


@pytest.mark.skipif(REAL is None, reason="ESP_LEGACY_MOVIE_ONTOLOGY not set (proprietary data)")
def test_real_legacy_ontology_all_tags_resolve() -> None:
    assert REAL is not None
    legacy = load_legacy_ontology(Path(REAL))
    registry, report = to_registry(legacy)
    assert len(legacy.emotion_tags) == 24
    assert len(legacy.impact_tags) == 6
    for tag in (*legacy.emotion_tags, *legacy.impact_tags):
        registry.resolve_label(VOCABULARY_ID, tag)
    for tag in legacy.emotion_tags:
        mapping = basic8_mapping(legacy, tag)
        assert mapping is not None
        assert mapping.basic8_label in BASIC8_ORDER
    again, report_again = to_registry(load_legacy_ontology(Path(REAL)))
    assert again.digest_hex() == registry.digest_hex()
    assert report_again == report
