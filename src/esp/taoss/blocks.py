# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Block layout, projections, split and compose (V13 section 5.1). ``V13_NORMATIVE``.

The experience space is ``R^d`` with ``d = sum_t d_t``; type ``t`` owns the
index range ``I_t = [offset_t, offset_t + d_t)`` in TAOSS order. Projections
``P_t`` are diagonal 0/1 matrices with ``P_s P_t = 0`` for ``s != t`` and
``sum_t P_t = I``. Disjoint support is exact; *semantic* independence is not
implied and is measured empirically (audit suite, WP-058).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

import numpy as np
from numpy.typing import NDArray

from esp.core.taoss_types import L1_DIMS, TAOSS6_ORDER, TaossType

FloatArray = NDArray[np.float64]


@dataclass(frozen=True, slots=True)
class BlockLayout:
    """Contiguous per-type blocks in TAOSS order."""

    dims: Mapping[TaossType, int]

    def __post_init__(self) -> None:
        if tuple(self.dims) != tuple(t for t in TAOSS6_ORDER if t in self.dims):
            msg = "layout types must be given in TAOSS order"
            raise ValueError(msg)
        if not self.dims:
            msg = "layout needs at least one type"
            raise ValueError(msg)
        for t, d in self.dims.items():
            if d <= 0:
                msg = f"dimension of {t.name} must be positive"
                raise ValueError(msg)
        object.__setattr__(self, "dims", MappingProxyType(dict(self.dims)))

    @property
    def types(self) -> tuple[TaossType, ...]:
        return tuple(self.dims)

    @property
    def total(self) -> int:
        return sum(self.dims.values())

    def offset(self, t: TaossType) -> int:
        offset = 0
        for u, d in self.dims.items():
            if u is t:
                return offset
            offset += d
        msg = f"{t.name} not in layout"
        raise KeyError(msg)

    def index_range(self, t: TaossType) -> range:
        start = self.offset(t)
        return range(start, start + self.dims[t])

    def projection(self, t: TaossType) -> FloatArray:
        """Diagonal projection matrix ``P_t``."""
        diag = np.zeros(self.total)
        r = self.index_range(t)
        diag[r.start : r.stop] = 1.0
        return np.diag(diag)

    def split(self, x: FloatArray) -> dict[TaossType, FloatArray]:
        """Split a full vector into read-only per-type blocks (copies)."""
        vec = _as_vector(x, self.total)
        parts: dict[TaossType, FloatArray] = {}
        for t in self.types:
            r = self.index_range(t)
            block = vec[r.start : r.stop].copy()
            block.flags.writeable = False
            parts[t] = block
        return parts

    def compose(self, parts: Mapping[TaossType, FloatArray]) -> FloatArray:
        """Inverse of :meth:`split`. All types of the layout are required.

        Absent types are *not* silently zero-filled: absence (⊥) and a zero
        vector are different (V13 section 7.2). Use explicit masks instead.
        """
        missing = [t.name for t in self.types if t not in parts]
        extra = [t.name for t in parts if t not in self.dims]
        if missing or extra:
            msg = f"compose needs exactly the layout types (missing={missing}, extra={extra})"
            raise ValueError(msg)
        out = np.empty(self.total)
        for t in self.types:
            r = self.index_range(t)
            out[r.start : r.stop] = _as_vector(parts[t], self.dims[t])
        out.flags.writeable = False
        return out


def _as_vector(x: FloatArray, n: int) -> FloatArray:
    arr = np.asarray(x, dtype=np.float64)
    if arr.shape != (n,):
        msg = f"expected shape ({n},), got {arr.shape}"
        raise ValueError(msg)
    if not np.all(np.isfinite(arr)):
        msg = "latent values must be finite"
        raise ValueError(msg)
    return arr


#: The V13 L1 layout: KNO 240, INT 64, EMO 64, CTX 64, SEN 64, TEM 16 = 512.
TAOSS6_L1: Final = BlockLayout(L1_DIMS)
