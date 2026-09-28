# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Minimal unit registry with explicit dimensions and exact conversions.

Conversion is only allowed within one physical dimension. Every unit maps to
its dimension's SI base unit via ``si = value * scale + offset``. Offsets are
only non-zero for absolute temperature scales; uncertainties (differences)
are converted with ``scale`` only.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum, unique
from types import MappingProxyType
from typing import Final


@unique
class Dimension(StrEnum):
    FREQUENCY = "frequency"
    TIME = "time"
    CONDUCTANCE = "conductance"
    VOLTAGE = "voltage"
    TEMPERATURE = "temperature"
    LENGTH = "length"
    ACCELERATION = "acceleration"
    ANGULAR_VELOCITY = "angular_velocity"
    PRESSURE = "pressure"
    DIMENSIONLESS = "dimensionless"
    COUNT = "count"


@dataclass(frozen=True, slots=True)
class Unit:
    symbol: str
    dimension: Dimension
    scale: float
    offset: float = 0.0


UNITS: Final = MappingProxyType(
    {
        u.symbol: u
        for u in (
            Unit("Hz", Dimension.FREQUENCY, 1.0),
            Unit("bpm", Dimension.FREQUENCY, 1.0 / 60.0),
            Unit("breaths_per_min", Dimension.FREQUENCY, 1.0 / 60.0),
            Unit("s", Dimension.TIME, 1.0),
            Unit("ms", Dimension.TIME, 1e-3),
            Unit("us", Dimension.TIME, 1e-6),
            Unit("ns", Dimension.TIME, 1e-9),
            Unit("S", Dimension.CONDUCTANCE, 1.0),
            Unit("uS", Dimension.CONDUCTANCE, 1e-6),
            Unit("V", Dimension.VOLTAGE, 1.0),
            Unit("mV", Dimension.VOLTAGE, 1e-3),
            Unit("uV", Dimension.VOLTAGE, 1e-6),
            Unit("K", Dimension.TEMPERATURE, 1.0),
            Unit("degC", Dimension.TEMPERATURE, 1.0, 273.15),
            Unit("m", Dimension.LENGTH, 1.0),
            Unit("mm", Dimension.LENGTH, 1e-3),
            Unit("m_per_s2", Dimension.ACCELERATION, 1.0),
            Unit("g0", Dimension.ACCELERATION, 9.80665),
            Unit("rad_per_s", Dimension.ANGULAR_VELOCITY, 1.0),
            Unit("Pa", Dimension.PRESSURE, 1.0),
            Unit("1", Dimension.DIMENSIONLESS, 1.0),
            Unit("percent", Dimension.DIMENSIONLESS, 0.01),
            Unit("px", Dimension.COUNT, 1.0),
            Unit("count", Dimension.COUNT, 1.0),
        )
    }
)


class UnitError(ValueError):
    """Unknown unit or incompatible dimensions."""


def get_unit(symbol: str) -> Unit:
    try:
        return UNITS[symbol]
    except KeyError:
        msg = f"unknown unit {symbol!r}"
        raise UnitError(msg) from None


def convert(value: float, from_unit: str, to_unit: str) -> float:
    """Convert an absolute value between units of the same dimension."""
    src, dst = get_unit(from_unit), get_unit(to_unit)
    if src.dimension is not dst.dimension:
        msg = (
            f"cannot convert {src.dimension.value} ({from_unit}) "
            f"to {dst.dimension.value} ({to_unit})"
        )
        raise UnitError(msg)
    if src is dst:
        return value
    si = value * src.scale + src.offset
    return (si - dst.offset) / dst.scale


def convert_difference(delta: float, from_unit: str, to_unit: str) -> float:
    """Convert a difference / uncertainty (offsets cancel)."""
    src, dst = get_unit(from_unit), get_unit(to_unit)
    if src.dimension is not dst.dimension:
        msg = f"cannot convert {src.dimension.value} to {dst.dimension.value}"
        raise UnitError(msg)
    if src is dst:
        return delta
    return delta * src.scale / dst.scale
