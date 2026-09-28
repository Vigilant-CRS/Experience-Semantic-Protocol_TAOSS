# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-029: baseline collection, device correction, robust normalization, person transform."""

import numpy as np
import pytest

from esp.calibration.model import CalibrationError, DeviceCalibration
from esp.calibration.pipeline import (
    BaselineCollector,
    CalibrationPipeline,
    Standardization,
    build_profile,
)
from esp.features.physio import FeatureValue
from esp.observation.model import Modality

HOUR = 3600 * 10**9


def hr(value: float, quality: float = 1.0) -> FeatureValue:
    return FeatureValue("hr", value, "bpm", Modality.ECG, 0, 10**9, 250, quality)


def profile_for(values: list[float], subject: str = "subj-aaaaaaaa", **kw: object):  # type: ignore[no-untyped-def]
    c = BaselineCollector("hr", "bpm", min_samples=5)
    c.extend(hr(v) for v in values)
    return build_profile(subject, [c.finish()], created_at_ns=0, valid_for_ns=HOUR, **kw)  # type: ignore[arg-type]


def test_same_raw_value_differs_across_personal_baselines() -> None:
    calm = CalibrationPipeline(profile_for([58, 60, 61, 59, 62, 60, 57]))
    fast = CalibrationPipeline(profile_for([78, 80, 82, 79, 81, 80, 83], "subj-bbbbbbbb"))
    a = calm.standardize(hr(80.0), device_id="d", at_ns=1)
    b = fast.standardize(hr(80.0), device_id="d", at_ns=1)
    assert a.raw == b.raw == 80.0
    assert a.value > 5.0  # far above this person's baseline
    assert abs(b.value) < 0.5  # ordinary for this person


def test_device_correction_happens_before_normalization() -> None:
    corr = DeviceCalibration(device_id="d", channel="hr", gain=1.0, offset=-5.0)
    p = CalibrationPipeline(profile_for([60, 61, 59, 62, 58, 60], device_calibrations=[corr]))
    with_dev = p.standardize(hr(65.0), device_id="d", at_ns=1)
    other = p.standardize(hr(65.0), device_id="other", at_ns=1)
    assert with_dev.corrected == 60.0
    assert with_dev.value == pytest.approx(0.0)
    assert other.corrected == 65.0


def test_person_probit_transform_is_monotone_and_finite() -> None:
    rng = np.random.default_rng(0)
    p = CalibrationPipeline(
        profile_for(list(rng.gamma(2.0, 5.0, 500) + 50)), Standardization.PERSON_PROBIT
    )
    vals = [p.standardize(hr(v), device_id="d", at_ns=1).value for v in (40, 55, 60, 70, 200)]
    assert vals == sorted(vals)
    assert all(np.isfinite(vals))
    assert vals[0] == pytest.approx(-3.09, abs=0.01)  # clamped at the 0.1 % percentile


def test_low_quality_values_are_not_part_of_the_baseline() -> None:
    c = BaselineCollector("hr", "bpm", min_samples=3)
    c.extend([hr(60), hr(61), hr(250, quality=0.1), hr(float("nan")), hr(59)])
    b = c.finish()
    assert b.n_samples == 3
    assert c.rejected == 2
    with pytest.raises(CalibrationError, match="usable values"):
        BaselineCollector("hr", "bpm", min_samples=10).finish()
    with pytest.raises(CalibrationError, match="collector for hr"):
        c.add(FeatureValue("eda_scl", 2.0, "uS", Modality.EDA, 0, 1, 1, 1.0))


def test_expired_profile_unknown_unit_and_unusable_values_are_refused() -> None:
    p = CalibrationPipeline(profile_for([60, 61, 59, 62, 58]))
    with pytest.raises(CalibrationError, match="not valid"):
        p.standardize(hr(60.0), device_id="d", at_ns=2 * HOUR)
    with pytest.raises(CalibrationError, match="no usable value"):
        p.standardize(hr(float("nan")), device_id="d", at_ns=1)
    with pytest.raises(CalibrationError, match="no baseline"):
        p.standardize(
            FeatureValue("eda_scl", 2.0, "uS", Modality.EDA, 0, 1, 1, 1.0), device_id="d", at_ns=1
        )
