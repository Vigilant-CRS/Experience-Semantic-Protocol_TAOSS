# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Persistent, process-safe receiver consent state (2026-09-29 review, ADR-0033).

:class:`~esp.consent.accept.AcceptState` and
:class:`~esp.consent.revocation.RevocationRegistry` are in-memory objects. A
receiver that serves several sessions, processes or restarts must not let
limits reset: ``max_segments`` per capability and audience member, cumulative ε,
grants accepted before a key rotation, and revocations.

:class:`ConsentStateStore` keeps that state in SQLite. The endpoint wraps each
consent decision in :meth:`ConsentStateStore.transaction`:

1. take an exclusive write lock (``BEGIN IMMEDIATE``, OS-level and cross-process);
2. reload the durable state into the in-memory objects;
3. decide;
4. write back and commit.

Two receivers therefore can never both accept the last allowed segment. The
per-second rate window (``AcceptState.recent``) stays local to one process by
design: it throttles load, it is not a consent limit.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from esp.consent.accept import AcceptState
from esp.consent.revocation import RevocationRegistry

_SCHEMA = """
CREATE TABLE IF NOT EXISTS segments (cap BLOB, member BLOB, n INTEGER, PRIMARY KEY (cap, member));
CREATE TABLE IF NOT EXISTS epsilon (cap BLOB PRIMARY KEY, spent REAL);
CREATE TABLE IF NOT EXISTS grants (digest BLOB PRIMARY KEY);
CREATE TABLE IF NOT EXISTS revoked_caps (cap BLOB PRIMARY KEY);
CREATE TABLE IF NOT EXISTS revoked_timelines (timeline BLOB PRIMARY KEY, from_seq INTEGER);
"""


class ConsentStateStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.executescript(_SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30, isolation_level=None)
        conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=FULL")
        return conn

    @contextmanager
    def transaction(self, state: AcceptState, revocations: RevocationRegistry) -> Iterator[None]:
        """Exclusive section: reload durable state, let the caller decide, persist on success."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._load(conn, state, revocations)
            yield
            self._save(conn, state, revocations)
            conn.execute("COMMIT")
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        finally:
            conn.close()

    @staticmethod
    def _load(conn: sqlite3.Connection, state: AcceptState, rev: RevocationRegistry) -> None:
        state.segments.clear()
        state.segments.update(
            {(bytes(c), bytes(m)): int(n) for c, m, n in conn.execute("SELECT * FROM segments")}
        )
        state.epsilon_spent.clear()
        state.epsilon_spent.update(
            {bytes(c): float(e) for c, e in conn.execute("SELECT * FROM epsilon")}
        )
        state.accepted_grants.clear()
        state.accepted_grants.update(bytes(d) for (d,) in conn.execute("SELECT * FROM grants"))
        rev.revoked_capabilities.update(
            bytes(c) for (c,) in conn.execute("SELECT * FROM revoked_caps")
        )
        for t, seq in conn.execute("SELECT * FROM revoked_timelines"):
            key = bytes(t)
            rev.revoked_timelines[key] = min(int(seq), rev.revoked_timelines.get(key, int(seq)))

    @staticmethod
    def _save(conn: sqlite3.Connection, state: AcceptState, rev: RevocationRegistry) -> None:
        conn.executemany(
            "INSERT INTO segments VALUES (?, ?, ?) ON CONFLICT(cap, member) "
            "DO UPDATE SET n = max(n, excluded.n)",
            [(c, m, n) for (c, m), n in state.segments.items()],
        )
        conn.executemany(
            "INSERT INTO epsilon VALUES (?, ?) ON CONFLICT(cap) "
            "DO UPDATE SET spent = max(spent, excluded.spent)",
            list(state.epsilon_spent.items()),
        )
        conn.executemany(
            "INSERT OR IGNORE INTO grants VALUES (?)", [(d,) for d in state.accepted_grants]
        )
        conn.executemany(
            "INSERT OR IGNORE INTO revoked_caps VALUES (?)",
            [(c,) for c in rev.revoked_capabilities],
        )
        conn.executemany(
            "INSERT INTO revoked_timelines VALUES (?, ?) ON CONFLICT(timeline) "
            "DO UPDATE SET from_seq = min(from_seq, excluded.from_seq)",
            list(rev.revoked_timelines.items()),
        )
