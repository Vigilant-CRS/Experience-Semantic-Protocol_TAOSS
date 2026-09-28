# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-007 acceptance tests: V13 layout, projection properties, split/compose."""

import itertools

import numpy as np
import pytest
from hypothesis import given
from hypothesis import strategies as st
from hypothesis.extra.numpy import arrays

from esp.core.taoss_types import TaossType
from esp.taoss.blocks import TAOSS6_L1, BlockLayout

L = TAOSS6_L1


def test_v13_l1_offsets() -> None:
    assert L.total == 512
    expected = {
        TaossType.KNO: range(0, 240),
        TaossType.INT: range(240, 304),
        TaossType.EMO: range(304, 368),
        TaossType.CTX: range(368, 432),
        TaossType.SEN: range(432, 496),
        TaossType.TEM: range(496, 512),
    }
    for t, r in expected.items():
        assert L.index_range(t) == r


def test_projection_properties_exact() -> None:
    projections = {t: L.projection(t) for t in L.types}
    for s, t in itertools.permutations(L.types, 2):
        assert not np.any(projections[s] @ projections[t])
    assert np.array_equal(sum(projections.values()), np.eye(512))
    for p in projections.values():
        assert np.array_equal(p @ p, p)  # idempotent


finite = st.floats(-1e6, 1e6, allow_nan=False, allow_infinity=False)


@given(arrays(np.float64, 512, elements=finite))
def test_compose_split_roundtrip(x: np.ndarray) -> None:
    assert np.array_equal(L.compose(L.split(x)), x)


@given(arrays(np.float64, 512, elements=finite))
def test_projection_equals_split(x: np.ndarray) -> None:
    parts = L.split(x)
    for t in L.types:
        projected = L.projection(t) @ x
        r = L.index_range(t)
        assert np.array_equal(projected[r.start : r.stop], parts[t])
        mask = np.ones(512, dtype=bool)
        mask[r.start : r.stop] = False
        assert not np.any(projected[mask])


def test_split_blocks_are_read_only_copies() -> None:
    x = np.arange(512, dtype=np.float64)
    parts = L.split(x)
    with pytest.raises(ValueError, match="read-only"):
        parts[TaossType.EMO][0] = 1.0
    x[304] = -1.0
    assert parts[TaossType.EMO][0] == 304.0


def test_compose_refuses_missing_types_no_silent_zero() -> None:
    parts = L.split(np.zeros(512))
    del parts[TaossType.EMO]
    with pytest.raises(ValueError, match="missing=\\['EMO'\\]"):
        L.compose(parts)


@pytest.mark.parametrize("bad", [np.zeros(511), np.zeros((2, 256)), np.full(512, np.nan)])
def test_shape_and_finiteness_checked(bad: np.ndarray) -> None:
    with pytest.raises(ValueError, match=r"expected shape|finite"):
        L.split(bad)


def test_alternative_layouts_and_order() -> None:
    small = BlockLayout({TaossType.KNO: 4, TaossType.CTX: 2})
    assert small.total == 6
    assert small.offset(TaossType.CTX) == 4
    with pytest.raises(ValueError, match="TAOSS order"):
        BlockLayout({TaossType.CTX: 2, TaossType.KNO: 4})
    with pytest.raises(ValueError, match="positive"):
        BlockLayout({TaossType.KNO: 0})
    with pytest.raises(KeyError):
        small.offset(TaossType.EMO)
