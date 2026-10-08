# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Observation, SignalQuality, DeviceMetadata (plan section 15, WP-002).

An observation is a raw measurement with time, quality and device
provenance. It carries **no interpretation**: there is deliberately no
field for affect, intent or any semantic label (plan section 4.2).
"""

from __future__ import annotations

import uuid
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from enum import StrEnum, unique
from typing import Annotated

from pydantic import AfterValidator, Field, StringConstraints, model_validator

from esp.core.clock import ClockStamp
from esp.core.ids import UUID4, LocalRef
from esp.core.model import EspModel
from esp.core.scalars import FiniteFloat, UInt64, UnitInterval
from esp.observation.units import UNITS, convert, convert_difference


@unique
class Modality(StrEnum):
    """Measurement modality. Neutral: names *what was measured*."""

    ECG = "ecg"
    PPG = "ppg"
    EDA = "eda"
    RESPIRATION = "respiration"
    EEG = "eeg"
    EMG = "emg"
    EYE = "eye"
    TEMPERATURE = "temperature"
    MOTION = "motion"
    AUDIO = "audio"
    VIDEO = "video"
    TEXT = "text"
    BEHAVIOR = "behavior"
    EVENT = "event"
    # invasive / intracranial neural recordings (M18, WP-086); neutral signal names only
    ECOG = "ecog"
    SEEG = "seeg"
    LFP = "lfp"
    MUA = "mua"
    BROADBAND = "broadband"
    """Unfiltered wideband intracortical voltage (e.g. Neuropixels at 30 kHz)."""
    SPIKES = "spikes"
    SPIKE_COUNTS = "spike_counts"
    NEURAL_FEATURES = "neural_features"


def _known_unit(symbol: str) -> str:
    if symbol not in UNITS:
        msg = f"unknown unit {symbol!r}"
        raise ValueError(msg)
    return symbol


UnitSymbol = Annotated[str, AfterValidator(_known_unit)]
Channel = Annotated[
    str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_.\-]*$", min_length=1, max_length=64)
]
DeviceId = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:\-]*$", max_length=128)
]


class DeviceMetadata(EspModel):
    """Pseudonymous description of the measuring device.

    ``device_id`` must be a pseudonymous, deployment-local identifier; raw
    hardware serial numbers are identifying and do not belong here.
    """

    device_id: DeviceId
    kind: Annotated[str, StringConstraints(min_length=1, max_length=64)]
    manufacturer: Annotated[str, StringConstraints(max_length=128)] | None = None
    model: Annotated[str, StringConstraints(max_length=128)] | None = None
    firmware_version: Annotated[str, StringConstraints(max_length=64)] | None = None
    sampling_rate_hz: Annotated[float, Field(gt=0.0)] | None = None
    synthetic: bool = False
    """True for simulated devices (BrainFlow synthetic board, simulator)."""


class SignalQuality(EspModel):
    """Quality of a single measurement."""

    signal_quality: UnitInterval | None = None
    """0 = unusable, 1 = perfect; ``None`` if the device reports no quality."""
    dropout: bool = False
    """True if no valid sample exists for this timestamp."""
    saturated: bool = False
    artifact: bool = False


class Observation(EspModel):
    """A raw measurement. Semantically neutral."""

    id: UUID4
    modality: Modality
    channel: Channel
    value: FiniteFloat | None
    """Measured value in ``unit``; ``None`` exactly when ``quality.dropout``."""
    unit: UnitSymbol
    value_uncertainty: Annotated[float, Field(ge=0.0, allow_inf_nan=False)] | None = None
    """Standard uncertainty of ``value`` in the same unit."""
    device: DeviceMetadata
    timestamp: ClockStamp
    quality: SignalQuality = SignalQuality()
    calibration_ref: LocalRef | None = None

    @model_validator(mode="after")
    def _dropout_consistency(self) -> Observation:
        if self.quality.dropout and self.value is not None:
            msg = "a dropout observation must not carry a value"
            raise ValueError(msg)
        if not self.quality.dropout and self.value is None:
            msg = "value is missing but dropout is not flagged"
            raise ValueError(msg)
        if self.value is None and self.value_uncertainty is not None:
            msg = "value_uncertainty without value"
            raise ValueError(msg)
        return self

    def converted(self, unit: str) -> Observation:
        """Return a fully revalidated copy expressed in ``unit`` (same dimension)."""
        value = None if self.value is None else convert(self.value, self.unit, unit)
        uncertainty = (
            None
            if self.value_uncertainty is None
            else abs(convert_difference(self.value_uncertainty, self.unit, unit))
        )
        return Observation.model_validate(
            self.model_dump() | {"value": value, "unit": unit, "value_uncertainty": uncertainty}
        )


@dataclass(frozen=True, slots=True)
class OrderingViolation:
    """A timestamp-ordering problem within one (device, modality, channel) stream."""

    stream: tuple[str, str, str]
    index: int
    reason: str


def check_stream_ordering(observations: Sequence[Observation]) -> list[OrderingViolation]:
    """Check per-stream ordering of observations given in arrival order.

    Within one ``(device_id, modality, channel)`` stream:

    - ``timestamp.sequence`` must strictly increase;
    - ``timestamp.monotonic_ns`` must not decrease;
    - ``timestamp.clock_domain`` must not change.
    """
    violations: list[OrderingViolation] = []
    last: dict[tuple[str, str, str], ClockStamp] = {}
    for index, obs in enumerate(observations):
        key = (obs.device.device_id, obs.modality.value, obs.channel)
        stamp = obs.timestamp
        previous = last.get(key)
        if previous is not None:
            if stamp.sequence <= previous.sequence:
                violations.append(OrderingViolation(key, index, "sequence not increasing"))
            if stamp.monotonic_ns < previous.monotonic_ns:
                violations.append(OrderingViolation(key, index, "monotonic clock went backwards"))
            if stamp.clock_domain != previous.clock_domain:
                violations.append(OrderingViolation(key, index, "clock domain changed"))
        last[key] = stamp
    return violations


def apply_clock_offset(
    stamp: ClockStamp, offset_ns: int, offset_uncertainty_ns: UInt64
) -> ClockStamp:
    """Apply an additional offset estimate; uncertainties add (worst-case bound)."""
    return ClockStamp.model_validate(
        stamp.model_dump()
        | {
            "clock_offset_ns": stamp.clock_offset_ns + offset_ns,
            "uncertainty_ns": stamp.uncertainty_ns + offset_uncertainty_ns,
        }
    )


def valid_values(observations: Iterable[Observation]) -> list[float]:
    """Values of non-dropout observations (convenience for feature code)."""
    return [o.value for o in observations if o.value is not None]


def new_observation_id() -> uuid.UUID:
    return uuid.uuid4()
