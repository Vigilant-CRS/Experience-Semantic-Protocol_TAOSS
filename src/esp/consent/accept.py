# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""The bidirectional packet acceptance predicate (V13 section 9.7). ``V13_NORMATIVE``.

``Accept(p, c_S, c_R)`` holds iff **all** of:

 1. the packet authenticated (signature and AEAD);
 2. a verified sender capability exists (no consent => no data) and the
    receiver policy is valid (signed capability or built-in default deny);
 3. ``types(p) ⊆ c_S.types_allowed ∩ c_R.accept_types``;
 4. the recipient is in the capability audience;
 5. segments accepted for (capability, recipient) < ``max_segments``;
 6. ``now <= c_S.valid_until + Δ_clock``;
 7. ``c_R.valid_from - Δ <= now <= c_R.valid_until + Δ``;
 8. ``ε_after <= c_S.dp_epsilon_ceiling``;
 9. requested policy flags do not exceed rights (no ALLOW_REPLAY ⇒ NO_REPLAY set,
    no ALLOW_STORE ⇒ NO_STORE set);
10. ``‖Z_t‖₂ <= max_norm[t]`` for every present type;
11. EMO present ⇒ valence within ``valence_bounds`` (fail closed if a bound is
    set and no valence is declared);
12. session packet rate <= ``rate_limit_hz``.

:func:`evaluate` is pure and reports *every* violated condition.
:class:`AcceptState` holds the counters that :func:`commit` advances only
after acceptance. Nothing here decodes semantics: callers pass minimally
parsed facts from the quarantine buffer.
"""

from __future__ import annotations

import collections
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

from esp.codec.header import ConsentFlags
from esp.consent.capability import AudienceMode, ReceiverPolicy, Rights, SenderCapability
from esp.core.taoss_types import TaossType, bitmap_to_types
from esp.crypto.primitives import blake2b

NS_PER_S: Final = 1_000_000_000


@dataclass(frozen=True, slots=True)
class PacketFacts:
    """What the Accept predicate needs to know about one packet."""

    authenticated: bool
    types: frozenset[TaossType]
    consent_flags: int
    norms: Mapping[TaossType, float]
    valence: float | None
    creates_dp_release: bool = False
    epsilon_increment: float = 0.0


@dataclass(frozen=True, slots=True)
class Decision:
    accepted: bool
    violations: tuple[str, ...]


@dataclass(slots=True)
class AcceptState:
    """Per-receiver counters. ``segments`` survive session re-establishment."""

    segments: dict[tuple[bytes, bytes], int] = field(default_factory=dict)
    epsilon_spent: dict[bytes, float] = field(default_factory=dict)
    recent: collections.deque[int] = field(default_factory=collections.deque)

    def packets_in_last_second(self, now_ns: int) -> int:
        while self.recent and self.recent[0] <= now_ns - NS_PER_S:
            self.recent.popleft()
        return len(self.recent)


def audience_leaf(recipient_pk: bytes) -> bytes:
    return blake2b(b"esp/v1/audience-leaf" + recipient_pk)


def audience_root(members: Sequence[bytes]) -> bytes:
    """Reference Merkle root for ``AUDIENCE_SET_ROOT`` (BLAKE2b, sorted leaves)."""
    level = sorted(audience_leaf(m) for m in members)
    if not level:
        msg = "empty audience"
        raise ValueError(msg)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            blake2b(b"esp/v1/audience-node" + level[i] + level[i + 1])
            for i in range(0, len(level), 2)
        ]
    return level[0]


def audience_proof_ok(
    root: bytes, recipient_pk: bytes, proof: Sequence[tuple[bytes, bool]]
) -> bool:
    """``proof`` = [(sibling, sibling_is_left), ...] from leaf to root."""
    node = audience_leaf(recipient_pk)
    for sibling, sibling_is_left in proof:
        pair = sibling + node if sibling_is_left else node + sibling
        node = blake2b(b"esp/v1/audience-node" + pair)
    return node == root


def _recipient_ok(
    c_s: SenderCapability, recipient_pk: bytes, proof: Sequence[tuple[bytes, bool]] | None
) -> bool:
    if c_s.audience_mode is AudienceMode.RECIPIENT_PUBKEY:
        return c_s.audience_value == recipient_pk
    return proof is not None and audience_proof_ok(c_s.audience_value, recipient_pk, proof)


def evaluate(  # noqa: PLR0912 - one branch per V13 condition, kept flat on purpose
    p: PacketFacts,
    c_s: SenderCapability | None,
    policy: ReceiverPolicy | None,
    state: AcceptState,
    *,
    recipient_pk: bytes,
    now_ns: int,
    clock_tolerance_ns: int,
    audience_proof: Sequence[tuple[bytes, bool]] | None = None,
) -> Decision:
    v: list[str] = []
    if not p.authenticated:
        v.append("1:not authenticated")
    if c_s is None:
        v.append("2:no sender capability (no consent)")
    if policy is None:
        v.append("2:no valid receiver policy")
    if c_s is None or policy is None:
        return Decision(False, tuple(v))

    allowed = set(bitmap_to_types(c_s.types_allowed)) & policy.accept_types
    if not p.types <= allowed:
        extra = sorted(t.name for t in p.types - allowed)
        v.append(f"3:types not permitted: {','.join(extra)}")
    if not _recipient_ok(c_s, recipient_pk, audience_proof):
        v.append("4:recipient not in audience")
    key = (c_s.capability_id.bytes, recipient_pk)
    if state.segments.get(key, 0) >= c_s.max_segments:
        v.append("5:max_segments exhausted")
    if now_ns > c_s.valid_until_ns + clock_tolerance_ns:
        v.append("6:sender capability expired")
    if (
        not policy.valid_from_ns - clock_tolerance_ns
        <= now_ns
        <= (policy.valid_until_ns + clock_tolerance_ns)
    ):
        v.append("7:receiver policy not valid now")
    spent = state.epsilon_spent.get(c_s.capability_id.bytes, 0.0)
    after = spent + (p.epsilon_increment if p.creates_dp_release else 0.0)
    if after > c_s.dp_epsilon_ceiling:
        v.append("8:DP epsilon ceiling exceeded")
    if not c_s.rights & Rights.ALLOW_REPLAY and not p.consent_flags & ConsentFlags.NO_REPLAY:
        v.append("9:replay not allowed but NO_REPLAY not set")
    if not c_s.rights & Rights.ALLOW_STORE and not p.consent_flags & ConsentFlags.NO_STORE:
        v.append("9:store not allowed but NO_STORE not set")
    for t in sorted(p.types):
        cap = policy.norm_caps.get(t)
        norm = p.norms.get(t)
        if cap is not None and (norm is None or norm > cap):
            v.append(f"10:{t.name} norm exceeds cap")
    if TaossType.EMO in p.types and policy.valence_bounds is not None:
        lo, hi = policy.valence_bounds
        unconstrained = lo <= -1.0 and hi >= 1.0
        if not unconstrained and (p.valence is None or not lo <= p.valence <= hi):
            v.append("11:valence outside receiver bounds")
    if state.packets_in_last_second(now_ns) + 1 > policy.rate_limit_hz:
        v.append("12:rate limit exceeded")
    return Decision(not v, tuple(v))


def commit(
    p: PacketFacts, c_s: SenderCapability, state: AcceptState, *, recipient_pk: bytes, now_ns: int
) -> None:
    """Advance counters after an accepted packet (never before)."""
    key = (c_s.capability_id.bytes, recipient_pk)
    state.segments[key] = state.segments.get(key, 0) + 1
    if p.creates_dp_release:
        cid = c_s.capability_id.bytes
        state.epsilon_spent[cid] = state.epsilon_spent.get(cid, 0.0) + p.epsilon_increment
    state.recent.append(now_ns)
