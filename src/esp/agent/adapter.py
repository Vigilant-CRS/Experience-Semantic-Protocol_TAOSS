# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""``g_agent``: agent state → ``T_mach`` latents (WP-067; V13 section 18.1).

Mapping: goal → INT, task context → CTX, facts → KNO. Tokens are hashed into
fixed buckets and projected with fixed, documented random matrices
(``esp-agent-hash``). This is a deterministic reference adapter, **not** a model
of any LLM's internal geometry.

An agent may claim TAOSS semantics only through an *audited* adapter
(V13 section 18.1). :meth:`AgentAdapter.typed_frame` refuses until
:meth:`AgentAdapter.audited` has run the cross-type leakage audit
(:mod:`esp.audit.suite`) on a sample of states and it passed. Frames always mask
EMO: agents are machines and never author EMO.
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import combinations
from typing import Final

import numpy as np
from numpy.typing import NDArray

from esp.audit.suite import AuditReport, audit_pair
from esp.core.clock import ClockStamp
from esp.core.errors import ErrorCode, EspError
from esp.core.taoss_types import L1_DIMS, TaossType
from esp.frame.model import ExperienceFrame, FrameProvenance, TypeBlock
from esp.meb.profiles import check_machine_types

F64 = NDArray[np.float64]
ADAPTER_ID: Final = "esp-agent-hash@0.1.0"
BUCKETS: Final = 48
MAPPING: Final = {"goal": TaossType.INT, "task_context": TaossType.CTX, "facts": TaossType.KNO}


class UnauditedAdapterError(EspError):
    code = ErrorCode.CONSENT_DENIED


@dataclass(frozen=True, slots=True)
class AgentState:
    goal: tuple[str, ...]
    task_context: tuple[str, ...]
    facts: tuple[str, ...]


def _hash_features(tokens: tuple[str, ...]) -> F64:
    v = np.zeros(BUCKETS)
    for tok in tokens:
        h = hashlib.blake2b(tok.encode(), digest_size=4).digest()
        v[int.from_bytes(h) % BUCKETS] += 1.0
    return v if tokens else np.full(BUCKETS, 1e-3)


def _projection(t: TaossType) -> F64:
    seed = int.from_bytes(
        hashlib.blake2b(f"{ADAPTER_ID}/{t.name}".encode(), digest_size=8).digest()
    )
    return np.random.default_rng(seed).normal(0.0, 1.0, size=(L1_DIMS[t], BUCKETS))


@dataclass(frozen=True, slots=True)
class AgentAdapter:
    adapter_id: str = ADAPTER_ID
    audit: AuditReport | None = None

    @property
    def types(self) -> frozenset[TaossType]:
        return check_machine_types(MAPPING.values())

    def encode(self, state: AgentState) -> dict[TaossType, F64]:
        out: dict[TaossType, F64] = {}
        for attr, t in MAPPING.items():
            z = _projection(t) @ _hash_features(getattr(state, attr))
            out[t] = z / max(float(np.linalg.norm(z)), 1e-12)
        return out

    def audited(self, sample: Sequence[AgentState], *, seed: int = 0) -> AgentAdapter:
        """Run the pairwise cross-type leakage audit; return an adapter carrying the report.

        Raises :class:`UnauditedAdapterError` if the audit fails. A failed adapter
        may not call its output TAOSS.
        """
        if len(sample) < 50:
            msg = "the audit needs at least 50 sampled agent states"
            raise UnauditedAdapterError(msg)
        z = {t: np.stack([self.encode(s)[t] for s in sample]) for t in self.types}
        pairs = tuple(
            audit_pair(a.name, b.name, z[a], z[b], seed=seed) for a, b in combinations(sorted(z), 2)
        )
        report = AuditReport(pairs, notes=(f"g_agent {self.adapter_id}",))
        if not report.passed:
            failed = [f"{p.source}/{p.target}" for p in pairs if not p.passed]
            msg = f"g_agent leakage audit failed for {failed}"
            raise UnauditedAdapterError(msg)
        return AgentAdapter(self.adapter_id, report)

    def typed_frame(
        self,
        state: AgentState,
        *,
        timeline_id: uuid.UUID,
        sequence: int,
        now_ns: int,
        event_id: uuid.UUID,
    ) -> ExperienceFrame:
        """A TAOSS frame for ``state``. The event id is the frame id (causal audit)."""
        if self.audit is None or not self.audit.passed:
            msg = "g_agent output may be called TAOSS only after a passed audit (V13 18.1)"
            raise UnauditedAdapterError(msg)
        stamp = ClockStamp(
            source_ns=now_ns, monotonic_ns=now_ns, clock_domain="agent:wall", sequence=sequence
        )
        return ExperienceFrame(
            frame_id=event_id,
            timeline_id=timeline_id,
            sequence=sequence,
            timestamp=stamp,
            types=tuple(
                TypeBlock(type=t, latent=tuple(float(x) for x in v))
                for t, v in self.encode(state).items()
            ),
            masked_types=(TaossType.EMO,),
            provenance=FrameProvenance(encoder_id=self.adapter_id),
        )
