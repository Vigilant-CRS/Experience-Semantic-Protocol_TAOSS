# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-089: FALCON H1 evaluation helpers (synthetic always; one real day when downloaded)."""

import json
import os
from pathlib import Path

import numpy as np
import pytest

from esp.bench.neural_falcon import Session, _fit, _halves, _r2, features, load_session

ROOT = Path(__file__).resolve().parents[3]
DATA = Path(os.environ.get("ESP_DATA_DIR", ROOT / "data" / "external")) / "falcon-h1"


def _synthetic(n: int = 3000, seed: int = 0) -> Session:
    rng = np.random.default_rng(seed)
    vel = np.cumsum(rng.normal(size=(n, 2)), axis=0)
    vel = (vel - vel.mean(0)) / vel.std(0)
    rate = np.exp(0.3 + 0.5 * np.roll(vel, 1, axis=0) @ rng.normal(size=(2, 20)))
    return Session(
        "s", "20260101", "held-in-calib", rng.poisson(rate).astype(float), vel, np.ones(n, bool)
    )


def test_features_are_causal() -> None:
    s = _synthetic()
    later = Session(s.name, s.day, s.split, s.counts.copy(), s.velocity, s.mask)
    later.counts[2000:] += 100.0  # change only the future
    a, b = features(s, lags=3, tau_bins=3.0), features(later, lags=3, tau_bins=3.0)
    np.testing.assert_array_equal(a[:2000], b[:2000])
    assert not np.allclose(a[2000:], b[2000:])


def test_halves_split_the_mask_without_overlap() -> None:
    m = np.ones(10, bool)
    m[3] = False
    first, second = _halves(m, 0.5)
    assert not (first & second).any()
    assert ((first | second) == m).all()
    assert first[:5].sum() == 4


def test_fit_on_masked_rows_decodes_and_shuffle_does_not() -> None:
    s = _synthetic()
    z = features(s, lags=3, tau_bins=2.0)
    train, test = _halves(s.mask, 0.6)
    dec = _fit([z], [s.velocity], [train], 10.0, ["synthetic"])
    assert _r2(dec, z, s.velocity, test) > 0.4
    shuffled = z[np.random.default_rng(1).permutation(len(z))]
    assert _r2(dec, shuffled, s.velocity, test) < 0.05


@pytest.mark.skipif(not (DATA / "MANIFEST.json").exists(), reason="run scripts/fetch_dandi.py")
def test_one_real_day_within_session_generalization() -> None:
    """FALCON H1, one day: calib trains, minival (other trials, same day) tests."""
    manifest = json.loads((DATA / "MANIFEST.json").read_text(encoding="utf-8"))
    calib = sorted((DATA / "sub-HumanPitt-held-in-calib").glob("*19250108*.nwb"))
    minival = sorted((DATA / "sub-HumanPitt-held-in-minival").glob("*19250108*.nwb"))
    train = [load_session(p, manifest) for p in calib]
    test = [load_session(p, manifest) for p in minival]
    feats = {s.name: features(s, lags=4, tau_bins=3.0) for s in train + test}
    dec = _fit(
        [feats[s.name] for s in train],
        [s.velocity for s in train],
        [s.mask for s in train],
        100.0,
        [s.name for s in train],
    )
    assert train[0].counts.shape[1] == 176
    scores = [_r2(dec, feats[s.name], s.velocity, s.mask) for s in test]
    assert np.mean(scores) > 0.1  # real signal: attempted velocity is decodable within a day
    rng = np.random.default_rng(0)
    shuffled = [
        _r2(dec, feats[s.name][rng.permutation(len(s.counts))], s.velocity, s.mask) for s in test
    ]
    assert np.mean(shuffled) < 0.02


def test_every_session_of_a_day_counts() -> None:
    """Regression: two sessions on one day were overwritten instead of averaged."""
    from esp.bench.neural_falcon import _per_day  # noqa: PLC0415

    out = _per_day([("20250101", 0.2), ("20250101", 0.6), ("20250102", 0.1)])
    assert out == {"20250101": pytest.approx(0.4), "20250102": pytest.approx(0.1)}
