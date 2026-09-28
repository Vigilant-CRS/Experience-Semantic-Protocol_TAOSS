# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Calibration profiles: personal baselines and device calibration.

Physiological signals vary strongly between people, so features are
computed relative to a personal baseline. Profiles store only aggregate
robust statistics — never raw samples — and are keyed by a pseudonymous
subject id. A calibration profile must not be repurposed as a biometric
identifier (plan section 16).

Robust z-score: ``(x - median) / (1.4826 * MAD)``; the constant makes the
scaled MAD a consistent estimator of the standard deviation for normal data.
"""

from __future__ import annotations

import bisect
import uuid
from collections.abc import Sequence
from itertools import pairwise
from typing import Annotated, Final

import numpy as np
from pydantic import Field, StringConstraints, field_validator, model_validator

from esp.core.errors import ErrorCode, EspError
from esp.core.ids import UUID4
from esp.core.model import EspModel
from esp.core.scalars import FiniteFloat, UInt64
from esp.core.versions import SemVer
from esp.observation.model import Channel, DeviceId, Modality, UnitSymbol

MAD_TO_SIGMA: Final = 1.4826

#: Pseudonymous subject id; deliberately excludes e-mail addresses and names.
SubjectPseudonym = Annotated[str, StringConstraints(pattern=r"^subj-[a-z0-9]{8,64}$")]


class CalibrationError(EspError):
    code = ErrorCode.VALIDATION


class ChannelBaseline(EspModel):
    """Robust baseline statistics for one channel."""

    modality: Modality
    channel: Channel
    unit: UnitSymbol
    median: FiniteFloat
    mad: Annotated[float, Field(ge=0.0, allow_inf_nan=False)]
    n_samples: Annotated[int, Field(ge=1)]
    quantiles: tuple[FiniteFloat, ...] = ()
    """Empirical quantiles at equally spaced probabilities 0..1 (for percentiles)."""

    @field_validator("quantiles")
    @classmethod
    def _monotone(cls, value: tuple[float, ...]) -> tuple[float, ...]:
        if value and len(value) < 2:
            msg = "quantiles need at least two knots"
            raise ValueError(msg)
        if any(b < a for a, b in pairwise(value)):
            msg = "quantiles must be non-decreasing"
            raise ValueError(msg)
        return value

    @property
    def key(self) -> tuple[str, str]:
        return (self.modality.value, self.channel)

    @classmethod
    def from_samples(
        cls,
        modality: Modality,
        channel: str,
        unit: str,
        samples: Sequence[float],
        *,
        n_quantiles: int = 101,
    ) -> ChannelBaseline:
        """Compute robust statistics deterministically; samples are not stored."""
        data = np.asarray(samples, dtype=np.float64)
        if data.size == 0 or not np.all(np.isfinite(data)):
            msg = "baseline needs at least one finite sample"
            raise CalibrationError(msg)
        median = float(np.median(data))
        mad = float(np.median(np.abs(data - median)))
        knots = np.quantile(data, np.linspace(0.0, 1.0, n_quantiles), method="linear")
        return cls(
            modality=modality,
            channel=channel,
            unit=unit,
            median=median,
            mad=mad,
            n_samples=int(data.size),
            quantiles=tuple(float(q) for q in knots),
        )

    def delta(self, value: float) -> float:
        """Baseline delta ``x - median``."""
        return value - self.median

    def robust_z(self, value: float) -> float:
        """Robust z-score; undefined (error) for a zero MAD."""
        if self.mad == 0.0:
            msg = f"robust z undefined for {self.key}: MAD is zero"
            raise CalibrationError(msg)
        return (value - self.median) / (MAD_TO_SIGMA * self.mad)

    def percentile(self, value: float) -> float:
        """Personal percentile in ``[0, 1]`` by linear interpolation of the quantiles."""
        q = self.quantiles
        if not q:
            msg = f"no quantiles stored for {self.key}"
            raise CalibrationError(msg)
        if value <= q[0]:
            return 0.0
        if value >= q[-1]:
            return 1.0
        i = bisect.bisect_right(q, value) - 1
        lo, hi = q[i], q[i + 1]
        step = 1.0 / (len(q) - 1)
        frac = 0.0 if hi == lo else (value - lo) / (hi - lo)
        return (i + frac) * step


class DeviceCalibration(EspModel):
    """Linear device correction ``corrected = raw * gain + offset``."""

    device_id: DeviceId
    channel: Channel
    gain: Annotated[float, Field(gt=0.0, allow_inf_nan=False)] = 1.0
    offset: FiniteFloat = 0.0

    def apply(self, raw: float) -> float:
        return raw * self.gain + self.offset


class CalibrationProfile(EspModel):
    id: UUID4
    subject_id: SubjectPseudonym
    version: Annotated[int, Field(ge=1)]
    supersedes: UUID4 | None = None
    created_at_ns: UInt64
    valid_from_ns: UInt64
    valid_until_ns: UInt64
    baselines: tuple[ChannelBaseline, ...]
    device_calibrations: tuple[DeviceCalibration, ...] = ()
    model_version: SemVer

    @model_validator(mode="after")
    def _consistency(self) -> CalibrationProfile:
        if self.valid_until_ns <= self.valid_from_ns:
            msg = "validity interval must be non-empty"
            raise ValueError(msg)
        keys = [b.key for b in self.baselines]
        if len(set(keys)) != len(keys):
            msg = "one baseline per (modality, channel)"
            raise ValueError(msg)
        dev = [(d.device_id, d.channel) for d in self.device_calibrations]
        if len(set(dev)) != len(dev):
            msg = "one device calibration per (device, channel)"
            raise ValueError(msg)
        if (self.version == 1) != (self.supersedes is None):
            msg = "version 1 has no predecessor; later versions must name the superseded profile"
            raise ValueError(msg)
        return self

    def is_valid_at(self, t_ns: int) -> bool:
        return self.valid_from_ns <= t_ns < self.valid_until_ns

    def baseline(self, modality: Modality, channel: str, *, at_ns: int) -> ChannelBaseline:
        """Return the baseline, refusing expired or not-yet-valid profiles."""
        if not self.is_valid_at(at_ns):
            msg = f"calibration profile {self.id} v{self.version} not valid at {at_ns}"
            raise CalibrationError(msg)
        for b in self.baselines:
            if b.key == (modality.value, channel):
                return b
        msg = f"no baseline for {(modality.value, channel)}"
        raise CalibrationError(msg)

    def updated(
        self,
        baselines: Sequence[ChannelBaseline],
        *,
        created_at_ns: int,
        valid_until_ns: int,
    ) -> CalibrationProfile:
        """New version replacing the given channel baselines; old versions stay intact."""
        replacement = {b.key: b for b in baselines}
        merged = [replacement.pop(b.key, b) for b in self.baselines]
        merged.extend(replacement.values())
        return CalibrationProfile(
            id=uuid.uuid4(),
            subject_id=self.subject_id,
            version=self.version + 1,
            supersedes=self.id,
            created_at_ns=created_at_ns,
            valid_from_ns=created_at_ns,
            valid_until_ns=valid_until_ns,
            baselines=tuple(merged),
            device_calibrations=self.device_calibrations,
            model_version=self.model_version,
        )
