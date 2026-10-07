# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Masked-type erasure (typing plus LEACE): linear guarantee, versioning, frame application."""

import numpy as np
import pytest

from esp.core.taoss_types import TaossType as T
from esp.frame.model import DisclosurePolicy
from esp.privacy.erasure import (
    ErasureError,
    ErasureProfile,
    LeaceEraser,
    declared_erasures,
    missing_erasures,
)
from tests.unit.frame.test_frame_wire import full_anchor_frame

pytestmark = pytest.mark.security


def _r2(x_tr: np.ndarray, y_tr: np.ndarray, x_te: np.ndarray, y_te: np.ndarray) -> float:
    a = np.c_[x_tr, np.ones(len(x_tr))]
    w = np.linalg.solve(a.T @ a + 1e-6 * np.eye(a.shape[1]), a.T @ y_tr)
    pred = np.c_[x_te, np.ones(len(x_te))] @ w
    return float(1 - np.sum((y_te - pred) ** 2) / np.sum((y_te - y_te.mean(0)) ** 2))


def _data(n: int = 4000, seed: int = 0) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    rng = np.random.default_rng(seed)
    z = rng.normal(size=(n, 2))  # the masked concept
    other = rng.normal(size=(n, 3))  # what the released parts should carry
    mix = rng.normal(size=(5, 12))
    x = np.c_[z, other] @ mix + 0.1 * rng.normal(size=(n, 12))
    return x, z, other


def test_erasure_removes_linear_information_on_held_out_rows() -> None:
    x, z, other = _data()
    tr, te = slice(0, 2000), slice(2000, None)
    assert _r2(x[tr], z[tr], x[te], z[te]) > 0.9  # before: the concept is linearly visible
    e = LeaceEraser.fit(
        [x[tr, :8], x[tr, 8:]],
        z[tr],
        concept=T.EMO,
        released_types=(T.KNO, T.CTX),
        training_data_id="synthetic:0",
    )
    erased = e.apply(x)
    assert _r2(erased[tr], z[tr], erased[te], z[te]) < 0.02  # no linear probe beats a constant
    assert _r2(erased[tr], other[tr], erased[te], other[te]) > 0.5  # other content survives
    # LEACE is the least-squares minimal edit: it keeps the training mean
    np.testing.assert_allclose(erased[tr].mean(0), x[tr].mean(0), atol=1e-9)


def test_digest_versions_parameters_and_training_data() -> None:
    x, z, _ = _data()
    kw = {"concept": T.EMO, "released_types": (T.KNO, T.CTX)}
    a = LeaceEraser.fit([x[:, :8], x[:, 8:]], z, training_data_id="train:v1", **kw)
    b = LeaceEraser.fit([x[:, :8], x[:, 8:]], z, training_data_id="train:v2", **kw)
    c = LeaceEraser.fit([x[:500, :8], x[:500, 8:]], z[:500], training_data_id="train:v1", **kw)
    assert len({a.digest, b.digest, c.digest}) == 3
    assert (
        a.digest
        == LeaceEraser.fit([x[:, :8], x[:, 8:]], z, training_data_id="train:v1", **kw).digest
    )
    assert a.ref.startswith("erasure:EMO:leace:")
    assert declared_erasures((a.ref, "dataset:x")) == {T.EMO}


def test_validation() -> None:
    x, z, _ = _data(200)
    with pytest.raises(ErasureError, match="concept"):
        LeaceEraser.fit([x], z, concept=T.KNO, released_types=(T.KNO,), training_data_id="t")
    with pytest.raises(ErasureError, match="training data"):
        LeaceEraser.fit([x], z, concept=T.EMO, released_types=(T.KNO,), training_data_id="")
    e = LeaceEraser.fit([x], z, concept=T.EMO, released_types=(T.KNO,), training_data_id="t")
    with pytest.raises(ErasureError, match="one eraser per concept"):
        ErasureProfile((e, e))


def _profile_for(frame_types: tuple[T, ...], dims: tuple[int, ...]) -> ErasureProfile:
    rng = np.random.default_rng(1)
    blocks = [rng.normal(size=(600, d)) for d in dims]
    concept = blocks[0][:, :3] @ rng.normal(size=(3, 2))
    return ErasureProfile(
        (
            LeaceEraser.fit(
                blocks, concept, concept=T.EMO, released_types=frame_types, training_data_id="t"
            ),
        )
    )


def test_profile_erases_masked_concept_and_declares_it() -> None:
    frame = full_anchor_frame()
    released = tuple(t for t in T if t is not T.EMO)
    disclosed = frame.disclose(DisclosurePolicy(allowed_types=released))
    present = tuple(
        sorted((b.type for b in disclosed.types if b.latent is not None), key=lambda t: t.value)
    )
    dims = tuple(len(disclosed.block(t).latent) for t in present)  # type: ignore[union-attr, arg-type]
    profile = _profile_for(present, dims)
    out = profile.apply(disclosed)
    assert declared_erasures(out.provenance.evidence_refs) == {T.EMO}
    assert missing_erasures(out, frozenset({T.EMO})) == frozenset()
    assert missing_erasures(disclosed, frozenset({T.EMO})) == {T.EMO}
    before = np.concatenate([disclosed.block(t).latent for t in present])  # type: ignore[union-attr]
    after = np.concatenate([out.block(t).latent for t in present])  # type: ignore[union-attr]
    np.testing.assert_allclose(after, profile.erasers[0].apply(before))
    # a disclosed concept needs no erasure: the frame is returned unchanged
    assert profile.apply(frame) == frame


def test_declared_eraser_that_cannot_apply_refuses() -> None:
    frame = full_anchor_frame()
    disclosed = frame.disclose(DisclosurePolicy(allowed_types=(T.KNO, T.CTX)))
    profile = _profile_for((T.KNO, T.INT), (240, 64))
    with pytest.raises(ErasureError, match="expects released"):
        profile.apply(disclosed)
