# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-079: content-side affect pipeline (V13 eq. affect) and typed scene retrieval."""

import numpy as np
import pytest

from esp.bench.tasks import ndcg_at_k
from esp.core.provenance import AffectScope
from esp.semantics.content_affect import ContentAffectPipeline, segment_ref


class Const:
    def __init__(self, name: str, v: float, a: float, n: int = 40) -> None:
        self.extractor_id, self.v, self.a, self.n = name, v, a, n

    def extract(self, segment: object) -> np.ndarray:
        return np.tile([self.v, self.a], (self.n, 1))


def pipe(**w: float) -> ContentAffectPipeline:
    return ContentAffectPipeline(
        {
            "audio": Const("audio@1", 0.8, 0.9),
            "face": Const("face@1", -0.8, 0.1),
            "text": Const("text@1", 0.0, 0.5),
        },
        w=w,
        sigma=0.0,
    )


def test_softmax_weights_and_face_gate() -> None:
    p = pipe(audio=0.0, face=0.0, text=0.0)
    c = p.curve({"audio": 1, "face": 1, "text": 1})
    assert np.allclose(c.weights, 1 / 3)
    assert c.valence[0] == pytest.approx(0.0)
    no_face = np.zeros(40, dtype=bool)
    gated = p.curve({"audio": 1, "face": 1, "text": 1}, face_present=no_face)
    assert np.allclose(gated.weights[:, 1], 0.0)  # alpha_f = 0 without a face
    assert gated.valence[0] == pytest.approx(0.4)  # (0.8 + 0.0) / 2
    strong_audio = pipe(audio=5.0).curve({"audio": 1, "face": 1, "text": 1})
    assert strong_audio.valence[0] > 0.7


def test_missing_modality_renormalizes_and_smoothing_reduces_noise() -> None:
    p = pipe()
    only_text = p.curve({"text": 1})
    assert np.allclose(only_text.weights[:, 2], 1.0)
    rng = np.random.default_rng(0)

    class Noisy:
        extractor_id = "noisy@1"

        def extract(self, segment: object) -> np.ndarray:
            return np.stack([np.clip(rng.normal(0, 0.5, 200), -1, 1), np.full(200, 0.5)], axis=1)

    raw = ContentAffectPipeline({"audio": Noisy()}, sigma=0.0).curve({"audio": 1})
    smooth = ContentAffectPipeline({"audio": Noisy()}, sigma=4.0).curve({"audio": 1})
    assert np.std(smooth.valence) < 0.5 * np.std(raw.valence)


def test_output_is_always_content_scope_with_provenance() -> None:
    p = pipe()
    d = p.descriptor(p.curve({"audio": 1, "text": 1}), segment_ref("m1", 0.0, 4.0))
    assert d.affect_scope is AffectScope.CONTENT
    assert "extractor:audio.1" in d.provenance.source_refs
    assert d.provenance.producer_id == "esp-content-affect"


def test_typed_scene_retrieval_on_a_movie_like_corpus() -> None:
    """ExperienceBench task 1 shape: EMO predicate x CTX predicate over content descriptors."""
    rng = np.random.default_rng(3)
    scenes = [
        (rng.uniform(-1, 1), rng.uniform(0, 1), str(rng.choice(["night", "beach", "office"])))
        for _ in range(200)
    ]
    query = (-0.7, 0.8, "night")  # tense night scene
    rel = np.array(
        [
            (abs(v - query[0]) < 0.3 and abs(a - query[1]) < 0.3) + (c == query[2])
            for v, a, c in scenes
        ],
        dtype=float,
    )
    scores = np.array(
        [-np.hypot(v - query[0], a - query[1]) + (c == query[2]) for v, a, c in scenes]
    )
    assert ndcg_at_k(rel, scores) > 0.8
    assert ndcg_at_k(rel, rng.normal(size=200)) < ndcg_at_k(rel, scores)
