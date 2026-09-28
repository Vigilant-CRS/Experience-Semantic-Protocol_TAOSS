# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-067 over real endpoints: agents exchange INT/CTX/KNO under capability with event audit."""

import uuid
from pathlib import Path

import numpy as np
import pytest

from esp.agent.adapter import AgentAdapter, AgentState
from esp.agent.companion import CompanionError, OpaqueLatent, accept_opaque
from esp.agent.demo import (
    AgentConsentError,
    ScriptedAgent,
    audit_sample,
    deliver,
    granted_types,
    open_link,
    run_agent_demo,
    send_opaque,
    send_state,
)
from esp.agent.descriptor import EventKind, OpaqueLatentDescriptor, StateKind
from esp.codec.frame_wire import consent_flags_for, frame_to_payload
from esp.core.taoss_types import TaossType
from esp.frame.model import DisclosurePolicy, ExperienceFrame

pytestmark = [pytest.mark.integration, pytest.mark.security]
T = TaossType
NOW = 10**18
KIC = frozenset({T.KNO, T.INT, T.CTX})


@pytest.fixture(scope="module")
def adapter() -> AgentAdapter:
    return AgentAdapter().audited(audit_sample())


def _agents() -> tuple[ScriptedAgent, ScriptedAgent]:
    def silent(agent: ScriptedAgent, item: ExperienceFrame | OpaqueLatent) -> None:
        return None

    return ScriptedAgent("a", silent), ScriptedAgent("b", silent)


STATE = AgentState(("close", "valve_7"), ("plant_north",), ("pressure_high",))


def test_reference_demo_two_agents_with_event_audit() -> None:
    r = run_agent_demo(now_ns=NOW)
    assert r.audit.passed, r.audit.problems
    assert len(r.audit.links) == 3  # typed, opaque, and the executor's typed report
    kinds = [e.kind for e in r.executor.entries]
    assert kinds.count(EventKind.LATENT_RECEIVED) == 2
    assert EventKind.REFUSED in kinds
    assert any("execute:close_valve_7" in e.detail for e in r.executor.entries)  # decoded goal
    assert r.refused
    assert "INT" in r.refused[0]
    assert [rep["kind"] for rep in r.reports] == ["typed", "opaque", "typed"]
    assert r.reports[0]["taoss_types"] == ["KNO", "INT", "CTX"]
    assert r.reports[1]["taoss_types"] == []
    assert r.reports[1]["consent_guarantees"] is None
    assert r.reports[2]["taoss_types"] == ["KNO", "CTX"]  # no INT from the executor
    assert r.executor_notices == 1
    assert r.planner_notices == 2  # signed 0x99 action events


def test_agent_without_int_capability_cannot_send_int(
    tmp_path: Path, adapter: AgentAdapter
) -> None:
    a, b = _agents()
    link = open_link(
        a, b, sender_types={T.KNO, T.CTX}, receiver_types=KIC, now_ns=NOW, state_dir=tmp_path
    )
    assert granted_types(link) == {T.KNO, T.CTX}
    # 1. the agent API refuses before anything reaches the wire, and logs it
    with pytest.raises(AgentConsentError, match="INT"):
        send_state(link, adapter, STATE, KIC, now_ns=NOW)
    assert a.log.entries[-1].kind is EventKind.REFUSED
    # 2. bypassing the agent API: the endpoint withholds INT (capability intersection)
    frame = adapter.typed_frame(
        STATE, timeline_id=link.sender.timeline_id, sequence=1, now_ns=NOW, event_id=uuid.uuid4()
    )
    packet = link.sender.send_frame(frame, DisclosurePolicy(allowed_types=tuple(KIC)), now_ns=NOW)
    got = link.receiver.receive(packet, now_ns=NOW)
    assert got.accepted
    assert got.frame is not None
    assert T.INT not in got.frame.present_types
    # 3. a crafted packet carrying INT is rejected by the receiver's Accept predicate
    encoded = frame_to_payload(frame, link.sender._wire)
    flags = consent_flags_for(encoded, link.sender._rights_flags())
    crafted = link.sender._seal(encoded.types_bitmap, flags, encoded.payload, NOW)
    before = link.receiver.decoder_invocations
    result = link.receiver.receive(crafted, now_ns=NOW)
    assert not result.accepted
    assert "3:types not permitted: INT" in result.violations, result.violations
    assert link.receiver.decoder_invocations == before


def test_typed_event_id_links_latent_and_action(tmp_path: Path, adapter: AgentAdapter) -> None:
    a, _ = _agents()
    b = ScriptedAgent("b", lambda agent, item: "act")
    link = open_link(a, b, sender_types=KIC, receiver_types=KIC, now_ns=NOW, state_dir=tmp_path)
    event_id, packet = send_state(link, adapter, STATE, KIC, now_ns=NOW)
    (action,) = deliver(link, packet, now_ns=NOW)
    received = b.log.entries[0]
    assert received.event_id == event_id
    assert received.subject_digest == a.log.entries[0].subject_digest  # same latents as sent
    assert action.caused_by == event_id
    assert b.log.entries[1].kind is EventKind.VISIBLE_ACTION


def test_opaque_descriptor_cannot_be_replayed_into_another_session(
    tmp_path: Path, adapter: AgentAdapter
) -> None:
    a, b = _agents()
    one = open_link(a, b, sender_types=KIC, receiver_types=KIC, now_ns=NOW, state_dir=tmp_path)
    two = open_link(a, b, sender_types=KIC, receiver_types=KIC, now_ns=NOW, state_dir=tmp_path)
    tensor = np.ones((2, 8), dtype=np.float32)
    _, packet = send_opaque(one, tensor, state_kind=StateKind.KV_CACHE, layers=(0, 1), now_ns=NOW)
    result = one.receiver.receive(packet, now_ns=NOW)
    (tlv,) = result.control
    desc = OpaqueLatentDescriptor.decode(tlv)
    payload = one.companion.take(desc)
    accept_opaque(
        desc,
        payload,
        transcript=one.receiver.transcript,
        receiver_capability_tlv=one.receiver.capability_tlv,
        expected_agent=a.pk,
    )
    with pytest.raises(CompanionError, match="transcript"):
        accept_opaque(
            desc,
            payload,
            transcript=two.receiver.transcript,
            receiver_capability_tlv=two.receiver.capability_tlv,
            expected_agent=a.pk,
        )


def test_opaque_path_logs_payload_digest(tmp_path: Path) -> None:
    a, _ = _agents()
    b = ScriptedAgent("b", lambda agent, item: "cache")
    link = open_link(a, b, sender_types=KIC, receiver_types=KIC, now_ns=NOW, state_dir=tmp_path)
    event_id, packet = send_opaque(
        link,
        np.zeros((3, 3), dtype=np.float32),
        state_kind=StateKind.LOGITS,
        layers=(7, 7),
        now_ns=NOW,
    )
    deliver(link, packet, now_ns=NOW)
    assert b.log.entries[0].event_id == event_id
    assert b.log.entries[0].subject_digest == a.log.entries[0].subject_digest
    assert b.log.entries[0].detail == "opaque received"
