# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Personalized calibration pipeline (WP-029).

Order of operations for one feature value (plan section 16):

1. **device correction**: ``raw * gain + offset`` for the (device, channel);
2. **robust normalization** against the personal baseline:
   ``(x - median) / (1.4826 * MAD)``;
3. **person-specific transform** (optional): the personal percentile of the
   corrected value is mapped to a standard-normal score
   (``Φ⁻¹(percentile)``). This makes different people's distributions
   comparable without assuming they are normal.

Baselines are *collected* from feature values during a declared baseline
period (:class:`BaselineCollector`). Only aggregate statistics are kept
(:class:`~esp.calibration.model.ChannelBaseline`), never raw samples.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from statistics import NormalDist
from typing import Final

from esp.calibration.model import (
    CalibrationError,
    CalibrationProfile,
    ChannelBaseline,
    DeviceCalibration,
)
from esp.features.physio import FeatureValue
from esp.observation.model import Modality

#: Percentiles are clamped away from 0/1 so the probit stays finite.
PERCENTILE_EPS: Final = 1e-3
MIN_QUALITY: Final = 0.5


class Standardization(StrEnum):
    ROBUST_Z = "robust_z"
    PERSON_PROBIT = "person_probit"


@dataclass(slots=True)
class BaselineCollector:
    """Collects feature values of one channel during a baseline period."""

    feature: str
    unit: str
    min_samples: int = 10
    min_quality: float = MIN_QUALITY
    _values: list[float] = field(default_factory=list)
    _modality: Modality | None = None
    rejected: int = 0

    def add(self, f: FeatureValue) -> None:
        if f.name != self.feature or f.unit != self.unit:
            msg = f"collector for {self.feature} [{self.unit}] got {f.name} [{f.unit}]"
            raise CalibrationError(msg)
        if f.quality < self.min_quality or f.value != f.value:  # low quality or NaN
            self.rejected += 1
            return
        if self._modality is not None and f.modality is not self._modality:
            msg = f"{self.feature}: mixed modalities in one baseline"
            raise CalibrationError(msg)
        self._modality = f.modality
        self._values.append(float(f.value))

    def extend(self, features: Iterable[FeatureValue]) -> None:
        for f in features:
            if f.name == self.feature:
                self.add(f)

    def finish(self) -> ChannelBaseline:
        if self._modality is None or len(self._values) < self.min_samples:
            msg = (
                f"baseline for {self.feature} has {len(self._values)} usable values, "
                f"{self.min_samples} required"
            )
            raise CalibrationError(msg)
        return ChannelBaseline.from_samples(self._modality, self.feature, self.unit, self._values)


def build_profile(
    subject_id: str,
    baselines: Sequence[ChannelBaseline],
    *,
    created_at_ns: int,
    valid_for_ns: int,
    device_calibrations: Sequence[DeviceCalibration] = (),
    model_version: str = "0.1.0",
) -> CalibrationProfile:
    return CalibrationProfile(
        id=uuid.uuid4(),
        subject_id=subject_id,
        version=1,
        created_at_ns=created_at_ns,
        valid_from_ns=created_at_ns,
        valid_until_ns=created_at_ns + valid_for_ns,
        baselines=tuple(baselines),
        device_calibrations=tuple(device_calibrations),
        model_version=model_version,
    )


@dataclass(frozen=True, slots=True)
class StandardizedFeature:
    name: str
    raw: float
    corrected: float
    value: float
    method: Standardization
    profile_id: uuid.UUID
    profile_version: int


class CalibrationPipeline:
    def __init__(
        self, profile: CalibrationProfile, method: Standardization = Standardization.ROBUST_Z
    ) -> None:
        self._profile = profile
        self._method = method
        self._devices = {(d.device_id, d.channel): d for d in profile.device_calibrations}

    def standardize(self, f: FeatureValue, *, device_id: str, at_ns: int) -> StandardizedFeature:
        if f.value != f.value or f.quality <= 0.0:
            msg = f"{f.name}: no usable value to standardize"
            raise CalibrationError(msg)
        baseline = self._profile.baseline(f.modality, f.name, at_ns=at_ns)
        if baseline.unit != f.unit:
            msg = f"{f.name}: baseline unit {baseline.unit} differs from {f.unit}"
            raise CalibrationError(msg)
        device = self._devices.get((device_id, f.name))
        corrected = device.apply(f.value) if device is not None else f.value
        if self._method is Standardization.ROBUST_Z:
            value = baseline.robust_z(corrected)
        else:
            p = min(1.0 - PERCENTILE_EPS, max(PERCENTILE_EPS, baseline.percentile(corrected)))
            value = NormalDist().inv_cdf(p)
        return StandardizedFeature(
            name=f.name,
            raw=f.value,
            corrected=corrected,
            value=value,
            method=self._method,
            profile_id=self._profile.id,
            profile_version=self._profile.version,
        )
