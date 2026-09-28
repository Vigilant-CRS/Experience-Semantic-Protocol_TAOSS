# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Validated scalar types (plan sections 8 and 9).

Intensity, confidence, model probability and anchor similarity are
*different quantities* (plan section 9). They share a numeric range but are
never interchangeable; models keep them in separately named fields.

All floats must be finite. Negative zero is normalized to ``0.0`` so that
equal values always have identical canonical serializations.
"""

from __future__ import annotations

import math
from typing import Annotated

from pydantic import AfterValidator, Field


def _canonical_float(value: float) -> float:
    if not math.isfinite(value):
        msg = "value must be finite"
        raise ValueError(msg)
    return 0.0 if value == 0.0 else value


_Canonical = AfterValidator(_canonical_float)

#: Closed unit interval ``[0, 1]``.
UnitInterval = Annotated[float, Field(ge=0.0, le=1.0), _Canonical]

#: Subjective / estimated intensity. ``0`` = absent, ``1`` = maximal for this
#: scale. Intensities of different categories are independent (no sum rule).
Intensity = UnitInterval

#: How sure the source/model is that the description is correct.
Confidence = UnitInterval

#: A classifier probability. Never automatically an intensity.
Probability = UnitInterval

#: V13 default affect dimension: valence in ``[-1, +1]``.
Valence = Annotated[float, Field(ge=-1.0, le=1.0), _Canonical]

#: V13 default affect dimension: arousal in ``[0, 1]``.
Arousal = UnitInterval

#: Signed similarity in ``[-1, 1]`` (for example cosine anchor similarity).
Similarity = Annotated[float, Field(ge=-1.0, le=1.0), _Canonical]

#: Any finite float (normalized negative zero).
FiniteFloat = Annotated[float, _Canonical]

#: Unsigned 64-bit integer (wire timestamps, counters).
UInt64 = Annotated[int, Field(ge=0, le=2**64 - 1)]

#: Signed 64-bit integer (clock offsets).
Int64 = Annotated[int, Field(ge=-(2**63), le=2**63 - 1)]

#: Unsigned 32-bit integer (``segment_seq``, lengths).
UInt32 = Annotated[int, Field(ge=0, le=2**32 - 1)]
