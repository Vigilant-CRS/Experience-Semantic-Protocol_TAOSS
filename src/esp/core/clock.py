# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Time model (plan section 17).

Every relevant record carries: source timestamp, monotonic timestamp,
clock domain, clock offset estimate, timestamp uncertainty and a sequence
number. The *reference time* of a stamp is ``source_ns + clock_offset_ns``
with uncertainty ``uncertainty_ns``.
"""

from __future__ import annotations

from typing import Annotated

from pydantic import StringConstraints, model_validator

from esp.core.model import EspModel
from esp.core.scalars import Int64, UInt64

ClockDomain = Annotated[
    str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9_.:\-]*$", min_length=1, max_length=64)
]


class ClockStamp(EspModel):
    """A timestamp with explicit clock provenance."""

    source_ns: UInt64
    """Timestamp in the source device's own clock domain."""
    monotonic_ns: UInt64
    """Receiving host's monotonic clock at capture (never goes backwards)."""
    clock_domain: ClockDomain
    """Identifier of the source clock, e.g. ``lsl:eeg-01`` or ``host:monotonic``."""
    clock_offset_ns: Int64 = 0
    """Estimated offset to add to ``source_ns`` to obtain reference time."""
    uncertainty_ns: UInt64 = 0
    """Half-width of the uncertainty interval of the reference time."""
    sequence: UInt64
    """Per-stream sequence number."""
    wall_clock_ns: UInt64 | None = None
    """Optional wall-clock time (Unix epoch, ns). Informational only."""

    @model_validator(mode="after")
    def _reference_time_in_range(self) -> ClockStamp:
        reference = self.source_ns + self.clock_offset_ns
        if not 0 <= reference <= 2**64 - 1:
            msg = "source_ns + clock_offset_ns must lie in the unsigned 64-bit range"
            raise ValueError(msg)
        return self

    @property
    def reference_ns(self) -> int:
        """Best estimate of the time in the shared reference clock."""
        return self.source_ns + self.clock_offset_ns

    @property
    def reference_interval_ns(self) -> tuple[int, int]:
        """Closed interval ``[reference - uncertainty, reference + uncertainty]``."""
        reference = self.reference_ns
        return (max(0, reference - self.uncertainty_ns), reference + self.uncertainty_ns)

    def definitely_before(self, other: ClockStamp) -> bool:
        """True only if the uncertainty intervals do not overlap and self is earlier."""
        return self.reference_interval_ns[1] < other.reference_interval_ns[0]
