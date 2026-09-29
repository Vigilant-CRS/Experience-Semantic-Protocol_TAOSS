# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Persistent receiver consent state (2026-09-29 review, ADR-0033).

Segment limits, cumulative ε, pre-rotation grants and revocations hold across
sessions, endpoint instances, processes and restarts.
"""

import threading
import uuid
from pathlib import Path

import pytest

from esp.consent.accept import AcceptState
from esp.consent.revocation import RevocationRegistry
from esp.consent.store import ConsentStateStore
from tests.integration.test_endpoint import ALL, NOW, establish, pair, sender_capability
from tests.unit.frame.test_frame_wire import full_anchor_frame

pytestmark = [pytest.mark.integration, pytest.mark.security]


def _session(tmp: Path, name: str, store: ConsentStateStore, max_segments: int, cap_id: uuid.UUID):  # type: ignore[no-untyped-def]
    sub = tmp / name
    sub.mkdir()
    s, r = pair(sub, cap=sender_capability(max_segments=max_segments, capability_id=cap_id))
    r._consent_store = store
    establish(s, r)
    return s, r


def test_segment_limit_holds_across_sessions_and_restarts(tmp_path: Path) -> None:
    store = ConsentStateStore(tmp_path / "consent.sqlite")
    cid = uuid.uuid4()
    s1, r1 = _session(tmp_path, "a", store, 1, cid)
    assert r1.receive(s1.send_frame(full_anchor_frame(), ALL, now_ns=NOW), now_ns=NOW).accepted
    # a new session, a new endpoint object and a reopened store: the limit is still spent
    s2, r2 = _session(tmp_path, "b", ConsentStateStore(tmp_path / "consent.sqlite"), 1, cid)
    res = r2.receive(s2.send_frame(full_anchor_frame(), ALL, now_ns=NOW), now_ns=NOW)
    assert not res.accepted
    assert any(v.startswith("5:") for v in res.violations)


def test_without_a_store_limits_are_per_endpoint(tmp_path: Path) -> None:
    """Documents the in-memory default the review flagged: use a store for real services."""
    cid = uuid.uuid4()
    accepted = []
    for name in ("a", "b"):
        sub = tmp_path / name
        sub.mkdir()
        s, r = pair(sub, cap=sender_capability(max_segments=1, capability_id=cid))
        establish(s, r)
        accepted.append(
            r.receive(s.send_frame(full_anchor_frame(), ALL, now_ns=NOW), now_ns=NOW).accepted
        )
    assert accepted == [True, True]


def test_revocation_survives_a_restart(tmp_path: Path) -> None:
    path = tmp_path / "consent.sqlite"
    cid = uuid.uuid4()
    state, rev = AcceptState(), RevocationRegistry()
    with ConsentStateStore(path).transaction(state, rev):
        rev.revoked_capabilities.add(cid.bytes)
    fresh_state, fresh_rev = AcceptState(), RevocationRegistry()
    with ConsentStateStore(path).transaction(fresh_state, fresh_rev):
        assert cid.bytes in fresh_rev.revoked_capabilities


def test_counters_never_decrease(tmp_path: Path) -> None:
    path = tmp_path / "consent.sqlite"
    state, rev = AcceptState(), RevocationRegistry()
    with ConsentStateStore(path).transaction(state, rev):
        state.segments[(b"c", b"m")] = 5
        state.epsilon_spent[b"c"] = 0.7
    stale = AcceptState()
    with ConsentStateStore(path).transaction(stale, RevocationRegistry()):
        stale.segments[(b"c", b"m")] = 1  # an out-of-date writer
        stale.epsilon_spent[b"c"] = 0.1
    check = AcceptState()
    with ConsentStateStore(path).transaction(check, RevocationRegistry()):
        assert check.segments[(b"c", b"m")] == 5
        assert check.epsilon_spent[b"c"] == pytest.approx(0.7)


def test_failed_decision_rolls_back(tmp_path: Path) -> None:
    path = tmp_path / "consent.sqlite"
    state = AcceptState()

    def failing_decision() -> None:
        with ConsentStateStore(path).transaction(state, RevocationRegistry()):
            state.segments[(b"c", b"m")] = 3
            raise RuntimeError

    with pytest.raises(RuntimeError):
        failing_decision()
    check = AcceptState()
    with ConsentStateStore(path).transaction(check, RevocationRegistry()):
        assert (b"c", b"m") not in check.segments


def test_concurrent_receivers_cannot_both_take_the_last_segment(tmp_path: Path) -> None:
    path = tmp_path / "consent.sqlite"
    ConsentStateStore(path)
    barrier = threading.Barrier(8)
    taken: list[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        state, rev = AcceptState(), RevocationRegistry()
        barrier.wait()
        with ConsentStateStore(path).transaction(state, rev):
            n = state.segments.get((b"c", b"m"), 0)
            ok = n < 1  # max_segments = 1
            if ok:
                state.segments[(b"c", b"m")] = n + 1
        with lock:
            taken.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert taken.count(True) == 1
