# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The six TAOSS types (V13 section 5.1, Appendix A). Class: ``V13_NORMATIVE``.

The enum value is the bit position in ``types_bitmap`` and the TAOSS order.
TLV code = ``0x60 + value`` (V13 section 8.4).
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import IntEnum, unique
from types import MappingProxyType
from typing import Final


@unique
class TaossType(IntEnum):
    """TAOSS-6 type; the integer value is the bitmap bit and the TAOSS order."""

    KNO = 0
    INT = 1
    EMO = 2
    CTX = 3
    SEN = 4
    TEM = 5

    @property
    def bit(self) -> int:
        """Mask of this type in ``types_bitmap``."""
        return 1 << self.value

    @property
    def tlv_code(self) -> int:
        """V13 v1 typed-latent TLV code (``0x60`` … ``0x65``)."""
        return 0x60 + self.value

    @property
    def l1_dim(self) -> int:
        """L1 dimensionality of this type."""
        return L1_DIMS[self]


#: L1 dimensionalities (V13 section 5.1).
L1_DIMS: Final = MappingProxyType(
    {
        TaossType.KNO: 240,
        TaossType.INT: 64,
        TaossType.EMO: 64,
        TaossType.CTX: 64,
        TaossType.SEN: 64,
        TaossType.TEM: 16,
    }
)

#: Total L1 latent dimension.
L1_TOTAL_DIM: Final = 512

#: TAOSS order, used for canonical TLV ordering.
TAOSS6_ORDER: Final = tuple(TaossType)

#: Bits 0-5 are assigned in v1; bits 6-15 are reserved (V13 Appendix A).
TYPES_BITMAP_ASSIGNED_MASK: Final = 0x003F

_BY_TLV: Final = MappingProxyType({t.tlv_code: t for t in TaossType})


def types_to_bitmap(types: Iterable[TaossType]) -> int:
    """Encode a set of types as the 16-bit ``types_bitmap``."""
    bitmap = 0
    for t in types:
        bitmap |= TaossType(t).bit
    return bitmap


def bitmap_to_types(bitmap: int) -> tuple[TaossType, ...]:
    """Decode ``types_bitmap`` in TAOSS order. Reserved bits are rejected."""
    if not 0 <= bitmap <= 0xFFFF:
        msg = f"types_bitmap out of 16-bit range: {bitmap}"
        raise ValueError(msg)
    if bitmap & ~TYPES_BITMAP_ASSIGNED_MASK:
        msg = f"reserved types_bitmap bits set: 0x{bitmap:04x}"
        raise ValueError(msg)
    return tuple(t for t in TAOSS6_ORDER if bitmap & t.bit)


def type_from_tlv_code(code: int) -> TaossType:
    """Return the TAOSS type for a typed-latent TLV code; never reinterprets others."""
    try:
        return _BY_TLV[code]
    except KeyError:
        msg = f"not a TAOSS-6 typed-latent TLV code: 0x{code:02x}"
        raise ValueError(msg) from None


if sum(L1_DIMS.values()) != L1_TOTAL_DIM:  # pragma: no cover - import-time invariant
    msg = "L1 dimensions must sum to 512"
    raise RuntimeError(msg)
