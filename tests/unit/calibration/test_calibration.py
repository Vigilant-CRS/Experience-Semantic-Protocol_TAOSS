# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-006 acceptance tests: versioning, baseline updates, expiry, determinism."""

import math
import uuid

import numpy as np
import pytest
from pydantic import ValidationError

from esp.calibration.model import (
    CalibrationError,
    CalibrationProfile,
    ChannelBaseline,
    DeviceCalibration,
)
from esp.observation.model import Modality


def hr_baseline(samples: list[float]) -> ChannelBaseline:
    return ChannelBaseline.from_samples(Modality.ECG, "heart_rate", "bpm", samples)


def profile(**overrides: object) -> CalibrationProfile:
    data: dict[str, object] = {
        "id": uuid.uuid4(),
        "subject_id": "subj-0a1b2c3d",
        "version": 1,
        "created_at_ns": 100,
        "valid_from_ns": 100,
        "valid_until_ns": 1_000,
        "baselines": (hr_baseline([60.0, 62.0, 64.0, 66.0, 68.0]),),
        "model_version": "1.0.0",
    }
    data.update(overrides)
    return CalibrationProfile.model_validate(data)


def test_robust_statistics() -> None:
    b = hr_baseline([60.0, 62.0, 64.0, 66.0, 200.0])  # outlier barely moves the median
    assert b.median == 64.0
    assert b.mad == 2.0
    assert math.isclose(b.robust_z(66.9652), (66.9652 - 64.0) / (1.4826 * 2.0))
    assert b.delta(70.0) == 6.0


def test_deterministic_feature_transform(rng: np.random.Generator) -> None:
    samples = rng.normal(70.0, 5.0, size=1_000).tolist()
    a = hr_baseline(samples)
    b = hr_baseline(list(samples))
    assert a == b
    assert a.canonical_json() == b.canonical_json()
    assert a.robust_z(80.0) == b.robust_z(80.0)
    assert a.percentile(80.0) == b.percentile(80.0)


def test_same_raw_value_different_baselines_gives_different_features() -> None:
    calm = hr_baseline([55.0, 56.0, 58.0, 60.0, 61.0])
    athletic_high = hr_baseline([85.0, 88.0, 90.0, 92.0, 95.0])
    raw = 90.0
    assert calm.robust_z(raw) > 5.0
    assert abs(athletic_high.robust_z(raw)) < 0.5
    assert calm.percentile(raw) == 1.0
    assert 0.3 < athletic_high.percentile(raw) < 0.7


def test_percentile_interpolation_and_bounds() -> None:
    b = hr_baseline([0.0, 10.0])
    assert b.percentile(-1.0) == 0.0
    assert b.percentile(11.0) == 1.0
    assert math.isclose(b.percentile(2.5), 0.25, abs_tol=1e-12)


def test_zero_mad_is_an_explicit_error() -> None:
    b = hr_baseline([60.0, 60.0, 60.0])
    with pytest.raises(CalibrationError, match="MAD is zero"):
        b.robust_z(61.0)


def test_non_finite_samples_rejected() -> None:
    with pytest.raises(CalibrationError):
        hr_baseline([60.0, float("nan")])
    with pytest.raises(CalibrationError):
        hr_baseline([])


def test_expired_and_future_calibration_refused() -> None:
    p = profile()
    assert p.baseline(Modality.ECG, "heart_rate", at_ns=500).median == 64.0
    for t in (99, 1_000, 5_000):
        with pytest.raises(CalibrationError, match="not valid"):
            p.baseline(Modality.ECG, "heart_rate", at_ns=t)


def test_baseline_update_creates_new_version_and_keeps_old() -> None:
    v1 = profile()
    new_hr = hr_baseline([70.0, 72.0, 74.0])
    eda = ChannelBaseline.from_samples(Modality.EDA, "scl", "uS", [2.0, 2.5, 3.0])
    v2 = v1.updated([new_hr, eda], created_at_ns=900, valid_until_ns=2_000)
    assert (v2.version, v2.supersedes, v2.subject_id) == (2, v1.id, v1.subject_id)
    assert v2.id != v1.id
    assert v2.baseline(Modality.ECG, "heart_rate", at_ns=950).median == 72.0
    assert v2.baseline(Modality.EDA, "scl", at_ns=950).median == 2.5
    assert v1.baseline(Modality.ECG, "heart_rate", at_ns=500).median == 64.0


def test_versioning_rules() -> None:
    with pytest.raises(ValidationError, match="predecessor"):
        profile(version=2)
    with pytest.raises(ValidationError, match="predecessor"):
        profile(supersedes=uuid.uuid4())
    with pytest.raises(ValidationError, match="non-empty"):
        profile(valid_until_ns=100)


def test_subject_id_must_be_pseudonymous() -> None:
    for bad in ("max.mustermann@example.org", "Max Mustermann", "subj-short"):
        with pytest.raises(ValidationError):
            profile(subject_id=bad)


def test_profile_stores_no_raw_samples() -> None:
    dumped = hr_baseline([61.0, 62.0, 63.0]).model_dump()
    assert "samples" not in dumped
    assert set(dumped) == {"modality", "channel", "unit", "median", "mad", "n_samples", "quantiles"}


def test_device_calibration() -> None:
    d = DeviceCalibration(device_id="dev-1", channel="scl", gain=1.02, offset=-0.1)
    assert math.isclose(d.apply(2.0), 1.94)
    with pytest.raises(ValidationError):
        DeviceCalibration(device_id="dev-1", channel="scl", gain=0.0)


def test_roundtrip() -> None:
    p = profile(device_calibrations=(DeviceCalibration(device_id="dev-1", channel="scl"),))
    assert CalibrationProfile.from_json(p.canonical_json()) == p
