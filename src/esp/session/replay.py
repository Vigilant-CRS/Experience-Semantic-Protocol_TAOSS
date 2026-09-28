# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Receiver replay protection (V13 section 9.5; ADR-0016).

Adaptive window sizes (packet counts, memory-capped)::

    W_back = min(8192, max(1024, ceil(2 * RTT_p99[s] * r_pkt[Hz])))
    W_fwd  = min(8192, max(128,  ceil(jitter_p99[s] * r_pkt[Hz])))

A packet with sequence ``s`` is accepted iff it is not a duplicate and
``max_seen - W_back < s <= max_seen + W_fwd`` (the very first packet is
accepted if ``s <= W_fwd``). Sequences never wrap.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Final

from esp.core.errors import ErrorCode, EspError

W_CAP: Final = 8192
W_BACK_FLOOR: Final = 1024
W_FWD_FLOOR: Final = 128


class ReplayError(EspError):
    code = ErrorCode.SESSION_STATE


def replay_windows(rtt_p99_s: float, jitter_p99_s: float, packet_rate_hz: float) -> tuple[int, int]:
    """V13 section 9.5 formulas."""
    for name, value in (("rtt", rtt_p99_s), ("jitter", jitter_p99_s), ("rate", packet_rate_hz)):
        if not math.isfinite(value) or value < 0.0:
            msg = f"{name} must be finite and non-negative"
            raise ValueError(msg)
    w_back = min(W_CAP, max(W_BACK_FLOOR, math.ceil(2.0 * rtt_p99_s * packet_rate_hz)))
    w_fwd = min(W_CAP, max(W_FWD_FLOOR, math.ceil(jitter_p99_s * packet_rate_hz)))
    return w_back, w_fwd


@dataclass(slots=True)
class ReplayWindow:
    w_back: int = W_BACK_FLOOR
    w_fwd: int = W_FWD_FLOOR
    _max_seen: int = field(default=-1, init=False)
    _seen: set[int] = field(default_factory=set, init=False)

    def __post_init__(self) -> None:
        if not (1 <= self.w_back <= W_CAP and 1 <= self.w_fwd <= W_CAP):
            msg = "window sizes must lie in [1, 8192]"
            raise ValueError(msg)

    @property
    def max_seen(self) -> int:
        return self._max_seen

    def check(self, seq: int) -> None:
        """Raise :class:`ReplayError` unless ``seq`` is acceptable (no state change)."""
        if not 0 <= seq <= 2**32 - 1:
            msg = "sequence out of range"
            raise ReplayError(msg)
        if seq > self._max_seen + self.w_fwd:
            msg = f"segment_seq {seq} too far ahead"
            raise ReplayError(msg)
        if seq <= self._max_seen - self.w_back:
            msg = f"segment_seq {seq} too old"
            raise ReplayError(msg)
        if seq in self._seen:
            msg = f"replayed segment_seq {seq}"
            raise ReplayError(msg)

    def accept(self, seq: int) -> None:
        """Check and record ``seq``. Call only after the packet authenticated."""
        self.check(seq)
        self._seen.add(seq)
        if seq > self._max_seen:
            self._max_seen = seq
            floor = seq - self.w_back
            if len(self._seen) > self.w_back + self.w_fwd:
                self._seen = {s for s in self._seen if s > floor}


@dataclass(slots=True)
class NonceReplayCache:
    """Random-nonce profile: receivers keep seen nonces for the key lifetime."""

    max_entries: int = 2**24
    _seen: set[bytes] = field(default_factory=set)

    def accept(self, nonce: bytes) -> None:
        if nonce in self._seen:
            msg = "replayed nonce"
            raise ReplayError(msg)
        if len(self._seen) >= self.max_entries:
            msg = "nonce cache full: rekey required"
            raise ReplayError(msg)
        self._seen.add(nonce)
