# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Hash-chained agent event log and causal audit (WP-067; V13 section 18.2).

Every agent keeps an append-only log. Each entry hashes its predecessor, so
removing, reordering or editing an entry breaks the chain. :func:`causal_audit`
checks across the logs of all parties:

- every chain is intact;
- every received latent was sent under the same event id with the same digest
  (no injected or altered latents);
- every visible action names the event that caused it, and the acting agent
  actually received that event (latent ↔ visible action linkage).
"""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass
from typing import Final

import numpy as np

from esp.agent.descriptor import EventKind
from esp.frame.model import ExperienceFrame

_GENESIS: Final = bytes(32)


@dataclass(frozen=True, slots=True)
class LogEntry:
    index: int
    owner: str
    kind: EventKind
    event_id: uuid.UUID
    caused_by: uuid.UUID | None
    subject_digest: bytes
    detail: str
    prev: bytes
    entry_hash: bytes

    @staticmethod
    def compute_hash(
        *,
        index: int,
        owner: str,
        kind: EventKind,
        event_id: uuid.UUID,
        caused_by: uuid.UUID | None,
        subject_digest: bytes,
        detail: str,
        prev: bytes,
    ) -> bytes:
        h = hashlib.blake2b(digest_size=32)
        for part in (
            b"esp/agent/v1/log",
            index.to_bytes(8, "big"),
            owner.encode(),
            bytes([kind]),
            event_id.bytes,
            (caused_by or uuid.UUID(int=0)).bytes,
            subject_digest,
            detail.encode(),
            prev,
        ):
            h.update(len(part).to_bytes(4, "big") + part)
        return h.digest()


class EventLog:
    def __init__(self, owner: str) -> None:
        self.owner = owner
        self.entries: list[LogEntry] = []

    def append(
        self,
        kind: EventKind,
        event_id: uuid.UUID,
        *,
        subject_digest: bytes,
        detail: str,
        caused_by: uuid.UUID | None = None,
    ) -> LogEntry:
        index = len(self.entries)
        prev = self.entries[-1].entry_hash if self.entries else _GENESIS
        h = LogEntry.compute_hash(
            index=index,
            owner=self.owner,
            kind=kind,
            event_id=event_id,
            caused_by=caused_by,
            subject_digest=subject_digest,
            detail=detail,
            prev=prev,
        )
        entry = LogEntry(
            index, self.owner, kind, event_id, caused_by, subject_digest, detail, prev, h
        )
        self.entries.append(entry)
        return entry

    def chain_problems(self) -> list[str]:
        problems: list[str] = []
        prev = _GENESIS
        for i, e in enumerate(self.entries):
            expected = LogEntry.compute_hash(
                index=i,
                owner=self.owner,
                kind=e.kind,
                event_id=e.event_id,
                caused_by=e.caused_by,
                subject_digest=e.subject_digest,
                detail=e.detail,
                prev=prev,
            )
            if e.index != i or e.owner != self.owner or e.prev != prev or e.entry_hash != expected:
                problems.append(f"{self.owner}: chain broken at entry {i}")
                break
            prev = e.entry_hash
        return problems

    def render(self) -> str:
        return "\n".join(
            f"{e.index:03d} {e.owner} {e.kind.name} {e.event_id}"
            + (f" <- {e.caused_by}" if e.caused_by else "")
            + f" {e.detail}"
            for e in self.entries
        )


@dataclass(frozen=True, slots=True)
class CausalAudit:
    problems: tuple[str, ...]
    links: tuple[tuple[uuid.UUID, uuid.UUID], ...]
    """(latent event id, visible action event id)."""

    @property
    def passed(self) -> bool:
        return not self.problems


def causal_audit(*logs: EventLog) -> CausalAudit:
    problems: list[str] = []
    for log in logs:
        problems += log.chain_problems()
    sent = {
        e.event_id: e.subject_digest
        for log in logs
        for e in log.entries
        if e.kind is EventKind.LATENT_SENT
    }
    links: list[tuple[uuid.UUID, uuid.UUID]] = []
    for log in logs:
        received = {e.event_id for e in log.entries if e.kind is EventKind.LATENT_RECEIVED}
        for e in log.entries:
            if e.kind is EventKind.LATENT_RECEIVED:
                if e.event_id not in sent:
                    problems.append(f"{log.owner}: received {e.event_id} that nobody sent")
                elif sent[e.event_id] != e.subject_digest:
                    problems.append(f"{log.owner}: {e.event_id} differs from what was sent")
            elif e.kind is EventKind.VISIBLE_ACTION:
                if e.caused_by is None:
                    problems.append(f"{log.owner}: action {e.event_id} names no causing event")
                elif e.caused_by not in received:
                    problems.append(
                        f"{log.owner}: action {e.event_id} cites {e.caused_by}, not received"
                    )
                else:
                    links.append((e.caused_by, e.event_id))
    return CausalAudit(tuple(problems), tuple(links))


def frame_digest(frame: ExperienceFrame) -> bytes:
    """Digest of a typed frame's latents as they travel on the wire (binary32)."""
    h = hashlib.blake2b(b"esp/agent/v1/frame", digest_size=32)
    for block in frame.types:
        h.update(bytes([block.type]))
        if block.latent is not None:
            h.update(np.asarray(block.latent, dtype=">f4").tobytes())
    return h.digest()
