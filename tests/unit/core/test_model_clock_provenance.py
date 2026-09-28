# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
import pytest
from pydantic import ValidationError

from esp.core.clock import ClockStamp
from esp.core.errors import ErrorCode, EspError, EspValidationError
from esp.core.model import canonical_json_bytes
from esp.core.provenance import AffectScope, Provenance, SourceKind


def stamp(**overrides: object) -> ClockStamp:
    values: dict[str, object] = {
        "source_ns": 1_000,
        "monotonic_ns": 5_000,
        "clock_domain": "host:monotonic",
        "sequence": 0,
    }
    values.update(overrides)
    return ClockStamp.model_validate(values)


def test_frozen_objects_reject_assignment() -> None:
    s = stamp()
    with pytest.raises(ValidationError):
        s.source_ns = 3  # type: ignore[misc]


def test_unknown_fields_rejected() -> None:
    with pytest.raises(ValidationError):
        stamp(unexpected=1)


@pytest.mark.parametrize("field", ["source_ns", "monotonic_ns", "clock_domain", "sequence"])
def test_required_fields(field: str) -> None:
    values: dict[str, object] = {
        "source_ns": 1,
        "monotonic_ns": 1,
        "clock_domain": "d",
        "sequence": 0,
    }
    del values[field]
    with pytest.raises(ValidationError):
        ClockStamp.model_validate(values)


def test_canonical_json_is_order_independent_and_roundtrips() -> None:
    a = ClockStamp.model_validate(
        {"sequence": 7, "clock_domain": "lsl:eeg-01", "monotonic_ns": 9, "source_ns": 3}
    )
    b = stamp(source_ns=3, monotonic_ns=9, clock_domain="lsl:eeg-01", sequence=7)
    assert a == b
    assert a.canonical_json() == b.canonical_json()
    assert ClockStamp.from_json(a.canonical_json()) == a
    assert b"\n" not in a.canonical_json()
    assert a.canonical_digest() == b.canonical_digest()
    assert len(a.canonical_digest()) == 32


def test_canonical_json_rejects_nan() -> None:
    with pytest.raises(ValueError, match="not JSON compliant"):
        canonical_json_bytes({"x": float("nan")})


def test_reference_time_and_uncertainty() -> None:
    s = stamp(source_ns=1_000, clock_offset_ns=-200, uncertainty_ns=50)
    assert s.reference_ns == 800
    assert s.reference_interval_ns == (750, 850)
    later = stamp(source_ns=1_000, clock_offset_ns=0, uncertainty_ns=50)
    assert s.definitely_before(later)
    overlapping = stamp(source_ns=1_000, clock_offset_ns=-140, uncertainty_ns=50)
    assert not s.definitely_before(overlapping)


def test_reference_time_must_not_underflow() -> None:
    with pytest.raises(ValidationError):
        stamp(source_ns=10, clock_offset_ns=-11)


@pytest.mark.parametrize("domain", ["", "Host", "a b", "x" * 65])
def test_clock_domain_format(domain: str) -> None:
    with pytest.raises(ValidationError):
        stamp(clock_domain=domain)


def test_inference_requires_provenance() -> None:
    with pytest.raises(ValidationError, match="requires producer_id"):
        Provenance(source_kind=SourceKind.MODEL_INFERENCE, source_refs=("obs_1",))
    with pytest.raises(ValidationError, match="at least one source_ref"):
        Provenance(
            source_kind=SourceKind.DERIVED, producer_id="esp-fusion", producer_version="1.0.0"
        )
    ok = Provenance(
        source_kind=SourceKind.MODEL_INFERENCE,
        producer_id="esp-emo-fusion",
        producer_version="1.0.0",
        source_refs=("obs_voice_193", "self_report_22"),
    )
    assert Provenance.from_json(ok.canonical_json()) == ok


def test_self_report_needs_no_producer() -> None:
    assert Provenance(source_kind=SourceKind.SELF_REPORT).producer_id is None


def test_duplicate_source_refs_rejected() -> None:
    with pytest.raises(ValidationError, match="unique"):
        Provenance(source_kind=SourceKind.SELF_REPORT, source_refs=("a", "a"))


def test_enum_values_are_stable_strings() -> None:
    assert [s.value for s in SourceKind] == [
        "self_report",
        "human_annotation",
        "sensor_observation",
        "model_inference",
        "derived",
        "synthetic_ground_truth",
    ]
    assert [s.value for s in AffectScope] == [
        "content",
        "self_declared",
        "inferred_subject",
        "machine_relay",
    ]


def test_error_codes_are_unique_and_formatted() -> None:
    assert len({c.value for c in ErrorCode}) == len(ErrorCode)
    assert ErrorCode.DECODER_POLICY_FAILED == 0x0601
    err = EspValidationError("bad", code=ErrorCode.RANGE)
    assert isinstance(err, EspError)
    assert str(err) == "[RANGE 0x0101] bad"


def test_from_data_uses_json_strictness() -> None:
    p = Provenance.from_data({"source_kind": "self_report", "source_refs": ["a", "b"]})
    assert p.source_kind is SourceKind.SELF_REPORT
    assert p.source_refs == ("a", "b")
    with pytest.raises(ValidationError):
        ClockStamp.from_data(
            {"source_ns": "1", "monotonic_ns": 1, "clock_domain": "d", "sequence": 0}
        )
    with pytest.raises(ValueError, match="not JSON compliant"):
        ClockStamp.from_data({"source_ns": float("nan")})
