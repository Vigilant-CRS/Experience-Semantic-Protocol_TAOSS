# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Decoder resource budgets (WP-060, T16: decoder capacity exhaustion).

A token bucket bounds the decode *rate*; a per-session cost ceiling bounds
the *total* work. When either is exhausted the receiver throttles — the
packet is not decoded and not committed (a retransmission may succeed
later) — instead of crashing or queueing unbounded work.
"""

from __future__ import annotations

from dataclasses import dataclass, field

NS_PER_S = 1_000_000_000


@dataclass(slots=True)
class DecodeBudget:
    rate_per_s: float
    burst: int
    session_cost_limit: float = float("inf")
    _tokens: float = field(init=False)
    _last_ns: int | None = field(default=None, init=False)
    spent: float = field(default=0.0, init=False)
    throttled: int = field(default=0, init=False)

    def __post_init__(self) -> None:
        if self.rate_per_s <= 0 or self.burst < 1 or self.session_cost_limit <= 0:
            msg = "rate, burst and cost limit must be positive"
            raise ValueError(msg)
        self._tokens = float(self.burst)

    def try_spend(self, now_ns: int, cost: float = 1.0) -> bool:
        """Reserve one decode of ``cost``. False means: throttle, do not decode."""
        if self._last_ns is not None and now_ns > self._last_ns:
            refill = (now_ns - self._last_ns) / NS_PER_S * self.rate_per_s
            self._tokens = min(float(self.burst), self._tokens + refill)
        self._last_ns = now_ns if self._last_ns is None else max(self._last_ns, now_ns)
        if self._tokens < 1.0 or self.spent + cost > self.session_cost_limit:
            self.throttled += 1
            return False
        self._tokens -= 1.0
        self.spent += cost
        return True


def decode_cost(payload_len: int) -> float:
    """Cheap cost estimate available before decoding: payload kilobytes (min 1)."""
    return max(1.0, payload_len / 1024)
