# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
import math
import uuid

import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from esp.core.clock import ClockStamp
from esp.observation.model import (
    DeviceMetadata,
    Modality,
    Observation,
    SignalQuality,
    apply_clock_offset,
    check_stream_ordering,
)
from esp.observation.units import UnitError, convert, convert_difference

DEVICE = DeviceMetadata(device_id="dev-ecg-01", kind="ecg-chest-strap", sampling_rate_hz=250.0)


def obs(
    value: float | None = 112.0,
    *,
    unit: str = "bpm",
    seq: int = 0,
    mono: int = 1_000,
    domain: str = "host:monotonic",
    dropout: bool = False,
    channel: str = "heart_rate",
    **extra: object,
) -> Observation:
    data: dict[str, object] = {
        "id": uuid.uuid4(),
        "modality": Modality.ECG,
        "channel": channel,
        "value": value,
        "unit": unit,
        "device": DEVICE,
        "timestamp": ClockStamp(
            source_ns=mono, monotonic_ns=mono, clock_domain=domain, sequence=seq
        ),
        "quality": SignalQuality(signal_quality=0.92, dropout=dropout),
    }
    data.update(extra)
    return Observation.model_validate(data)


# --- unit conversions -------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "src", "dst", "expected"),
    [
        (60.0, "bpm", "Hz", 1.0),
        (1.5, "Hz", "bpm", 90.0),
        (250.0, "ms", "s", 0.25),
        (2.0, "uS", "S", 2e-6),
        (0.0, "degC", "K", 273.15),
        (310.15, "K", "degC", 37.0),
        (1.0, "g0", "m_per_s2", 9.80665),
        (50.0, "percent", "1", 0.5),
    ],
)
def test_unit_conversions(value: float, src: str, dst: str, expected: float) -> None:
    assert math.isclose(convert(value, src, dst), expected, rel_tol=1e-12, abs_tol=1e-12)


def test_differences_ignore_offsets() -> None:
    assert math.isclose(convert_difference(0.5, "degC", "K"), 0.5)
    assert math.isclose(convert(0.5, "degC", "K"), 273.65)


@pytest.mark.parametrize(("src", "dst"), [("bpm", "s"), ("uS", "uV"), ("degC", "1")])
def test_incompatible_dimensions_rejected(src: str, dst: str) -> None:
    with pytest.raises(UnitError, match="cannot convert"):
        convert(1.0, src, dst)


def test_unknown_unit_rejected() -> None:
    with pytest.raises(UnitError, match="unknown unit"):
        convert(1.0, "furlong", "m")
    with pytest.raises(ValidationError, match="unknown unit"):
        obs(unit="beats")


@given(st.floats(-1e9, 1e9), st.sampled_from([("bpm", "Hz"), ("ms", "s"), ("degC", "K")]))
def test_conversion_roundtrip(value: float, pair: tuple[str, str]) -> None:
    there = convert(value, *pair)
    back = convert(there, pair[1], pair[0])
    assert math.isclose(back, value, rel_tol=1e-9, abs_tol=1e-6)


def test_observation_conversion_scales_uncertainty() -> None:
    o = obs(112.0, value_uncertainty=3.0).converted("Hz")
    assert o.unit == "Hz"
    assert o.value is not None
    assert math.isclose(o.value, 112.0 / 60.0)
    assert o.value_uncertainty is not None
    assert math.isclose(o.value_uncertainty, 3.0 / 60.0)
    with pytest.raises(UnitError):
        obs(112.0).converted("s")


# --- invalid values / dropout ----------------------------------------------


@pytest.mark.parametrize("bad", [math.nan, math.inf, "112", True])
def test_invalid_values_rejected(bad: object) -> None:
    with pytest.raises(ValidationError):
        obs(bad)  # type: ignore[arg-type]


def test_negative_uncertainty_rejected() -> None:
    with pytest.raises(ValidationError):
        obs(112.0, value_uncertainty=-1.0)


def test_dropout_flags() -> None:
    assert obs(None, dropout=True).value is None
    with pytest.raises(ValidationError, match="must not carry a value"):
        obs(112.0, dropout=True)
    with pytest.raises(ValidationError, match="dropout is not flagged"):
        obs(None, dropout=False)
    with pytest.raises(ValidationError, match="uncertainty without value"):
        obs(None, dropout=True, value_uncertainty=1.0)


def test_missing_clock_rejected() -> None:
    data = obs().model_dump()
    del data["timestamp"]
    with pytest.raises(ValidationError, match="timestamp"):
        Observation.model_validate(data)


def test_observation_is_semantically_neutral() -> None:
    """No interpretation fields can be smuggled into an observation."""
    for field in ("affect", "emotion", "fear", "intensity", "label"):
        with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
            obs(**{field: 0.75})


def test_roundtrip_json() -> None:
    o = obs(112.0, value_uncertainty=2.5, calibration_ref="cal-17")
    again = Observation.from_json(o.canonical_json())
    assert again == o
    assert again.canonical_json() == o.canonical_json()


# --- ordering ----------------------------------------------------------------


def test_ordering_ok() -> None:
    stream = [obs(seq=i, mono=1_000 + i) for i in range(5)]
    assert check_stream_ordering(stream) == []


def test_ordering_violations_detected() -> None:
    stream = [
        obs(seq=0, mono=1_000),
        obs(seq=0, mono=1_001),
        obs(seq=2, mono=900),
        obs(seq=3, mono=1_100, domain="lsl:other"),
    ]
    reasons = [(v.index, v.reason) for v in check_stream_ordering(stream)]
    assert reasons == [
        (1, "sequence not increasing"),
        (2, "monotonic clock went backwards"),
        (3, "clock domain changed"),
    ]


def test_ordering_is_per_stream() -> None:
    stream = [obs(seq=5, channel="heart_rate"), obs(seq=0, channel="rr_interval", unit="ms")]
    assert check_stream_ordering(stream) == []


# --- uncertainty propagation ------------------------------------------------


def test_clock_offset_uncertainties_add() -> None:
    stamp = ClockStamp(
        source_ns=10_000,
        monotonic_ns=1,
        clock_domain="lsl:eeg",
        sequence=0,
        clock_offset_ns=100,
        uncertainty_ns=20,
    )
    shifted = apply_clock_offset(stamp, -300, 15)
    assert shifted.reference_ns == 9_800
    assert shifted.uncertainty_ns == 35
    assert shifted.reference_interval_ns == (9_765, 9_835)
