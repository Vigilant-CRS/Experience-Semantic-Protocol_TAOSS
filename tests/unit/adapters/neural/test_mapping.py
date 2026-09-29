# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-089: neural→TAOSS mapping profile and the reference ridge (Wiener) decoder."""

import numpy as np
import pytest

from esp.adapters.neural.interface import NeuralFeatures, decode_boundary
from esp.adapters.neural.mapping import (
    NEVER_FROM_NEURAL,
    V1_RULES,
    MappedNeuralDecoder,
    MappingError,
    MappingProfile,
    RidgeDecoder,
    TargetKind,
    check_mapping,
    embedding,
    lagged,
    r2_score,
    to_typed,
)
from esp.core.provenance import Provenance, SourceKind
from esp.core.taoss_types import L1_DIMS, TaossType

pytestmark = pytest.mark.security
T = TaossType


def test_v1_rules_never_populate_emo_or_kno() -> None:
    assert not set(V1_RULES.values()) & NEVER_FROM_NEURAL
    check_mapping(MappingProfile())


@pytest.mark.parametrize("bad_type", [T.EMO, T.KNO])
def test_profile_mapping_to_emo_or_kno_is_refused(bad_type: TaossType) -> None:
    with pytest.raises(MappingError, match="never populated"):
        check_mapping(MappingProfile({TargetKind.ATTEMPTED_MOVEMENT: bad_type}))


def test_measured_kinematics_cannot_be_relabelled_as_intention() -> None:
    with pytest.raises(MappingError, match="deviates"):
        check_mapping(MappingProfile({TargetKind.MEASURED_KINEMATICS: T.INT}))


def test_embedding_is_orthonormal_deterministic_and_bounded() -> None:
    e = embedding(T.INT, 7)
    assert e.shape == (L1_DIMS[T.INT], 7)
    assert np.allclose(e.T @ e, np.eye(7), atol=1e-10)
    assert np.array_equal(e, embedding(T.INT, 7))
    assert not np.allclose(embedding(T.SEN, 7), e)
    with pytest.raises(MappingError, match="exceed"):
        embedding(T.TEM, L1_DIMS[T.TEM] + 1)


def test_to_typed_groups_targets_and_preserves_norms() -> None:
    out = to_typed(
        MappingProfile(),
        {
            TargetKind.ATTEMPTED_MOVEMENT: np.array([1.0, -2.0, 0.5]),
            TargetKind.GRASP_STATE: np.array([1.0]),
            TargetKind.MEASURED_KINEMATICS: np.array([0.1, 0.2]),
        },
    )
    assert set(out) == {T.INT, T.SEN}
    assert out[T.INT].shape == (L1_DIMS[T.INT],)
    assert np.linalg.norm(out[T.INT]) == pytest.approx(np.linalg.norm([1.0, -2.0, 0.5, 1.0]))
    with pytest.raises(MappingError, match="not finite"):
        to_typed(MappingProfile(), {TargetKind.TIMING: np.array([np.nan])})


def test_lagged_and_r2() -> None:
    x = np.arange(6.0).reshape(3, 2)
    z = lagged(x, 1)
    assert z.tolist() == [[0, 1, 0, 0], [2, 3, 0, 1], [4, 5, 2, 3]]
    y = np.random.default_rng(0).normal(size=(50, 2))
    assert r2_score(y, y) == 1.0
    assert r2_score(y, np.tile(y.mean(0), (50, 1))) == pytest.approx(0.0)


def _synthetic_motor(n: int = 3000, seed: int = 0) -> tuple[np.ndarray, np.ndarray]:
    """Velocity driven cosine-tuned 'units' with a one-bin lag, plus Poisson noise."""
    rng = np.random.default_rng(seed)
    vel = np.cumsum(rng.normal(size=(n, 2)), axis=0)
    vel = (vel - vel.mean(0)) / vel.std(0)
    tuning = rng.normal(size=(2, 24))
    rate = np.exp(0.5 + 0.6 * np.roll(vel, 1, axis=0) @ tuning)
    return rng.poisson(rate).astype(float), vel


def test_ridge_decoder_learns_and_versions_its_calibration() -> None:
    x, y = _synthetic_motor()
    dec = RidgeDecoder(TargetKind.ATTEMPTED_MOVEMENT, lags=3, alpha=10.0)
    assert dec.decoder_id.endswith("unfitted")
    with pytest.raises(MappingError, match="not calibrated"):
        dec.predict(x)
    dec.fit(x[:2000], y[:2000], session_ids=("day1",))
    held_out = r2_score(y[2000:], dec.predict(x[2000:]))
    assert held_out > 0.5
    shuffled = r2_score(y[2000:], dec.predict(np.random.default_rng(1).permutation(x[2000:])))
    assert shuffled < 0.1  # the decoder uses the neural signal, not the target's own statistics
    first = dec.decoder_id
    dec.fit(x[:2000], y[:2000], session_ids=("day1", "day2"))
    assert dec.decoder_id != first  # every recalibration is versioned


def test_mapped_decoder_passes_the_v13_decode_boundary() -> None:
    x, y = _synthetic_motor()
    dec = RidgeDecoder(TargetKind.ATTEMPTED_MOVEMENT, lags=3).fit(x, y)
    mapped = MappedNeuralDecoder([dec], n_features=x.shape[1])
    assert mapped.output_types == frozenset({T.INT})
    window = x[-(dec.lags + 1) :]
    prov = mapped.provenance(("dandi:000954",))
    assert isinstance(prov, Provenance)
    assert prov.source_kind is SourceKind.MODEL_INFERENCE
    feats = NeuralFeatures(
        names=tuple(f"u{i}.t{k}" for k in range(dec.lags + 1) for i in range(x.shape[1])),
        values=window.ravel(),
        window_start_ns=0,
        window_end_ns=80_000_000,
        provenance=prov,
    )
    out = decode_boundary(mapped, feats, frozenset({T.INT, T.EMO}))
    assert set(out) == {T.INT}  # EMO is never requested from a neural decoder
    assert decode_boundary(mapped, feats, frozenset({T.EMO})) == {}
    expected = embedding(T.INT, 2) @ dec.predict(window)[-1]
    assert np.allclose(out[T.INT], expected)


def test_one_decoder_per_target() -> None:
    d = RidgeDecoder(TargetKind.TIMING)
    with pytest.raises(MappingError, match="one decoder"):
        MappedNeuralDecoder([d, RidgeDecoder(TargetKind.TIMING)], n_features=2)
