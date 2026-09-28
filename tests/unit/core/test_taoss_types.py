# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
import itertools

import pytest

from esp.core.taoss_types import (
    L1_DIMS,
    L1_TOTAL_DIM,
    TAOSS6_ORDER,
    TaossType,
    bitmap_to_types,
    type_from_tlv_code,
    types_to_bitmap,
)


def test_v13_normative_bits_codes_and_dims() -> None:
    expected = {
        TaossType.KNO: (0x0001, 0x60, 240),
        TaossType.INT: (0x0002, 0x61, 64),
        TaossType.EMO: (0x0004, 0x62, 64),
        TaossType.CTX: (0x0008, 0x63, 64),
        TaossType.SEN: (0x0010, 0x64, 64),
        TaossType.TEM: (0x0020, 0x65, 16),
    }
    for t, (bit, code, dim) in expected.items():
        assert (t.bit, t.tlv_code, t.l1_dim) == (bit, code, dim)
    assert sum(L1_DIMS.values()) == L1_TOTAL_DIM == 512
    assert [t.name for t in TAOSS6_ORDER] == ["KNO", "INT", "EMO", "CTX", "SEN", "TEM"]


def test_bitmap_roundtrip_for_all_64_subsets() -> None:
    for r in range(7):
        for subset in itertools.combinations(TAOSS6_ORDER, r):
            assert bitmap_to_types(types_to_bitmap(subset)) == subset


@pytest.mark.parametrize("bitmap", [0x0040, 0x8000, 0xFFFF, 0x0041])
def test_reserved_bitmap_bits_rejected(bitmap: int) -> None:
    with pytest.raises(ValueError, match="reserved"):
        bitmap_to_types(bitmap)


@pytest.mark.parametrize("bitmap", [-1, 0x10000])
def test_bitmap_range(bitmap: int) -> None:
    with pytest.raises(ValueError, match="16-bit"):
        bitmap_to_types(bitmap)


def test_tlv_codes_are_not_reinterpreted() -> None:
    assert type_from_tlv_code(0x62) is TaossType.EMO
    for code in (0x50, 0x5F, 0x66, 0x70, 0x00):
        with pytest.raises(ValueError, match="not a TAOSS-6"):
            type_from_tlv_code(code)
