# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-001 property tests: >= 10,000 generated valid and invalid objects."""

import math

import numpy as np
import pytest
from hypothesis import given
from hypothesis import strategies as st
from pydantic import ValidationError

from esp.core.clock import ClockStamp
from esp.core.model import EspModel
from esp.core.provenance import Provenance, SourceKind
from esp.core.scalars import Intensity, Valence

pytestmark = pytest.mark.property


class Pair(EspModel):
    intensity: Intensity
    valence: Valence


def oracle_pair(intensity: float, valence: float) -> bool:
    finite = math.isfinite(intensity) and math.isfinite(valence)
    return finite and 0.0 <= intensity <= 1.0 and -1.0 <= valence <= 1.0


def test_ten_thousand_generated_scalar_objects_match_oracle(rng: np.random.Generator) -> None:
    specials = np.array([0.0, -0.0, 1.0, -1.0, 1.0 + 1e-15, -1e-300, np.nan, np.inf, -np.inf])
    n = 12_000
    values = rng.uniform(-1.5, 1.5, size=(n, 2))
    mask = rng.random((n, 2)) < 0.1
    values[mask] = rng.choice(specials, size=int(mask.sum()))
    accepted = rejected = 0
    for intensity, valence in values.tolist():
        expected = oracle_pair(intensity, valence)
        try:
            obj = Pair(intensity=intensity, valence=valence)
        except ValidationError:
            assert not expected, (intensity, valence)
            rejected += 1
            continue
        assert expected, (intensity, valence)
        assert Pair.from_json(obj.canonical_json()) == obj
        accepted += 1
    assert accepted + rejected == n
    assert accepted > 1_000
    assert rejected > 1_000


@given(st.floats(allow_nan=True, allow_infinity=True), st.floats(allow_nan=True))
def test_scalar_validation_matches_oracle(intensity: float, valence: float) -> None:
    try:
        Pair(intensity=intensity, valence=valence)
    except ValidationError:
        assert not oracle_pair(intensity, valence)
    else:
        assert oracle_pair(intensity, valence)


clock_stamps = st.builds(
    ClockStamp,
    source_ns=st.integers(0, 2**63),
    monotonic_ns=st.integers(0, 2**64 - 1),
    clock_domain=st.from_regex(r"[a-z0-9][a-z0-9_.:\-]{0,20}", fullmatch=True),
    clock_offset_ns=st.integers(0, 2**62),
    uncertainty_ns=st.integers(0, 2**40),
    sequence=st.integers(0, 2**64 - 1),
    wall_clock_ns=st.none() | st.integers(0, 2**64 - 1),
)


@given(clock_stamps)
def test_clock_stamp_roundtrip(s: ClockStamp) -> None:
    again = ClockStamp.from_json(s.canonical_json())
    assert again == s
    assert again.canonical_json() == s.canonical_json()


refs = st.lists(
    st.from_regex(r"[A-Za-z0-9][A-Za-z0-9_.:\-]{0,30}", fullmatch=True), unique=True, max_size=5
).map(tuple)


@given(
    kind=st.sampled_from(SourceKind),
    producer=st.none() | st.just("esp-emo-fusion"),
    version=st.none() | st.just("1.2.3"),
    source_refs=refs,
)
def test_provenance_rule_matches_oracle(
    kind: SourceKind, producer: str | None, version: str | None, source_refs: tuple[str, ...]
) -> None:
    inferential = kind in {SourceKind.MODEL_INFERENCE, SourceKind.DERIVED}
    expected = not inferential or (producer is not None and version is not None and source_refs)
    try:
        p = Provenance(
            source_kind=kind,
            producer_id=producer,
            producer_version=version,
            source_refs=source_refs,
        )
    except ValidationError:
        assert not expected
    else:
        assert expected
        assert Provenance.from_json(p.canonical_json()) == p
