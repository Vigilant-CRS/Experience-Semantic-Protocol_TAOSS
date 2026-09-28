# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-067: companion binding, the audited g_agent, reports and the causal audit."""

import dataclasses
import uuid

import numpy as np
import pytest

from esp.agent.adapter import AgentAdapter, AgentState, UnauditedAdapterError
from esp.agent.audit import EventLog, causal_audit, frame_digest
from esp.agent.companion import (
    CompanionError,
    CompanionStream,
    OpaqueLatent,
    accept_opaque,
    describe,
)
from esp.agent.demo import audit_sample
from esp.agent.descriptor import (
    DType,
    EventKind,
    OpaqueLatentDescriptor,
    StateKind,
    TensorSchema,
    capability_digest,
    payload_digest,
)
from esp.core.taoss_types import TaossType
from esp.crypto.primitives import SigningKey

pytestmark = pytest.mark.security
T = TaossType
AGENT = SigningKey.from_seed(b"\x51" * 32)
TRANSCRIPT = b"\x61" * 32
CAP_TLV = b"\x22" + b"receiver-capability-bytes"
PAYLOAD = np.arange(16, dtype=">f4").tobytes()


def opaque_descriptor(**kw: object) -> OpaqueLatentDescriptor:
    fields: dict[str, object] = {
        "state_kind": StateKind.HIDDEN_STATE,
        "schema": TensorSchema(DType.F32, (4, 4), 0, 0),
        "model_digest": b"\x01" * 32,
        "model_version_digest": b"\x02" * 32,
        "payload_digest": payload_digest(PAYLOAD),
        "payload_len": len(PAYLOAD),
        "agent_pk": AGENT.public_bytes,
        "recipient_capability_digest": capability_digest(CAP_TLV),
        "transcript_hash": TRANSCRIPT,
        "event_id": uuid.uuid4(),
    }
    return OpaqueLatentDescriptor(**(fields | kw)).signed(AGENT)  # type: ignore[arg-type]


def accept(desc: OpaqueLatentDescriptor, payload: bytes = PAYLOAD, **kw: object) -> OpaqueLatent:
    args: dict[str, object] = {
        "transcript": TRANSCRIPT,
        "receiver_capability_tlv": CAP_TLV,
        "expected_agent": AGENT.public_bytes,
    }
    return accept_opaque(desc, payload, **(args | kw))  # type: ignore[arg-type]


def test_companion_payload_is_bound_to_session_capability_and_digest() -> None:
    desc = opaque_descriptor()
    stream = CompanionStream()
    stream.put(desc, PAYLOAD)
    assert accept(desc, stream.take(desc)).payload == PAYLOAD
    with pytest.raises(CompanionError, match="no companion payload"):
        stream.take(desc)  # consumed exactly once
    with pytest.raises(CompanionError, match="transcript"):
        accept(desc, transcript=b"\x62" * 32)  # replayed into another session
    with pytest.raises(CompanionError, match="transcript"):
        accept(desc, transcript=None)
    with pytest.raises(CompanionError, match="recipient capability"):
        accept(desc, receiver_capability_tlv=b"\x22other")
    with pytest.raises(CompanionError, match="recipient capability"):
        accept(desc, receiver_capability_tlv=None)  # default deny is a different consent
    with pytest.raises(CompanionError, match="unexpected agent"):
        accept(desc, expected_agent=b"\x09" * 32)
    tampered = bytearray(PAYLOAD)
    tampered[5] ^= 1
    with pytest.raises(CompanionError, match="digest"):
        accept(desc, bytes(tampered))
    with pytest.raises(CompanionError, match="digest"):
        accept(desc, PAYLOAD + b"\x00")


def test_opaque_payload_never_claims_taoss_consent_guarantees() -> None:
    report = describe(accept(opaque_descriptor()), adapter_audited=True)
    assert report["kind"] == "opaque"
    assert report["taoss_types"] == []
    assert report["consent_guarantees"] is None
    assert "not a TAOSS representation" in report["notice"]
    text = " ".join(str(v) for v in report.values())
    for t in TaossType:
        assert t.name not in text  # no type label is ever attached to opaque bytes


@pytest.fixture(scope="module")
def audited() -> AgentAdapter:
    return AgentAdapter().audited(audit_sample())


STATE = AgentState(("close", "valve_7"), ("plant_north",), ("pressure_high",))


def test_g_agent_is_called_taoss_only_after_a_passed_audit(audited: AgentAdapter) -> None:
    raw = AgentAdapter()
    with pytest.raises(UnauditedAdapterError, match="only after a passed audit"):
        raw.typed_frame(
            STATE, timeline_id=uuid.uuid4(), sequence=1, now_ns=1, event_id=uuid.uuid4()
        )
    assert audited.audit is not None
    assert audited.audit.passed
    assert len(audited.audit.pairs) == 3  # KNO/INT, KNO/CTX, INT/CTX
    event = uuid.uuid4()
    frame = audited.typed_frame(
        STATE, timeline_id=uuid.uuid4(), sequence=1, now_ns=1, event_id=event
    )
    assert frame.frame_id == event
    assert set(frame.present_types) == {T.KNO, T.INT, T.CTX}
    assert frame.masked_types == (T.EMO,)
    assert describe(frame, adapter_audited=True)["taoss_types"] == ["KNO", "INT", "CTX"]
    unaudited = describe(frame, adapter_audited=False)
    assert unaudited["taoss_types"] == []
    assert unaudited["consent_guarantees"] is None


def test_g_agent_mapping_is_block_wise(audited: AgentAdapter) -> None:
    base = audited.encode(STATE)
    other_goal = audited.encode(dataclasses.replace(STATE, goal=("open", "valve_3")))
    other_facts = audited.encode(dataclasses.replace(STATE, facts=("pressure_low",)))
    assert not np.allclose(base[T.INT], other_goal[T.INT])  # goal -> INT
    np.testing.assert_array_equal(base[T.KNO], other_goal[T.KNO])
    np.testing.assert_array_equal(base[T.CTX], other_goal[T.CTX])
    assert not np.allclose(base[T.KNO], other_facts[T.KNO])  # facts -> KNO
    np.testing.assert_array_equal(base[T.INT], other_facts[T.INT])


def test_a_leaky_agent_adapter_fails_the_audit() -> None:
    # goal and facts carry the same tokens: INT and KNO leak into each other
    leaky = [AgentState(s.goal, s.task_context, s.goal) for s in audit_sample(3)]
    with pytest.raises(UnauditedAdapterError, match="KNO/INT"):
        AgentAdapter().audited(leaky)
    with pytest.raises(UnauditedAdapterError, match="at least 50"):
        AgentAdapter().audited(audit_sample(n=10))


def test_event_log_chain_and_causal_audit() -> None:
    a, b = EventLog("a"), EventLog("b")
    e1, act = uuid.uuid4(), uuid.uuid4()
    a.append(EventKind.LATENT_SENT, e1, subject_digest=b"\x01" * 32, detail="typed")
    b.append(EventKind.LATENT_RECEIVED, e1, subject_digest=b"\x01" * 32, detail="typed")
    b.append(EventKind.VISIBLE_ACTION, act, caused_by=e1, subject_digest=b"\x02" * 32, detail="go")
    ok = causal_audit(a, b)
    assert ok.passed
    assert ok.links == ((e1, act),)
    assert "<- " + str(e1) in b.render()

    # an edited entry breaks the chain
    tampered = EventLog("b")
    tampered.entries = [dataclasses.replace(b.entries[0], detail="edited"), b.entries[1]]
    assert any("chain broken" in p for p in causal_audit(a, tampered).problems)
    reordered = EventLog("b")
    reordered.entries = [b.entries[1], b.entries[0]]
    assert not causal_audit(a, reordered).passed

    # received but never sent / altered in transit
    c = EventLog("c")
    c.append(EventKind.LATENT_RECEIVED, uuid.uuid4(), subject_digest=b"\x01" * 32, detail="x")
    c.append(EventKind.LATENT_RECEIVED, e1, subject_digest=b"\x09" * 32, detail="x")
    problems = causal_audit(a, c).problems
    assert any("nobody sent" in p for p in problems)
    assert any("differs" in p for p in problems)

    # actions must name a cause the actor actually received
    d = EventLog("d")
    d.append(EventKind.VISIBLE_ACTION, uuid.uuid4(), subject_digest=b"\x02" * 32, detail="x")
    d.append(
        EventKind.VISIBLE_ACTION,
        uuid.uuid4(),
        caused_by=e1,
        subject_digest=b"\x02" * 32,
        detail="x",
    )
    problems = causal_audit(a, d).problems
    assert any("names no causing event" in p for p in problems)
    assert any("not received" in p for p in problems)


def test_frame_digest_matches_the_wire_precision(audited: AgentAdapter) -> None:
    frame = audited.typed_frame(
        STATE, timeline_id=uuid.uuid4(), sequence=1, now_ns=1, event_id=uuid.uuid4()
    )
    rounded = frame.model_copy(
        update={
            "types": tuple(
                b.model_copy(update={"latent": tuple(float(np.float32(x)) for x in b.latent or ())})
                for b in frame.types
            )
        }
    )
    assert frame_digest(frame) == frame_digest(rounded)
    changed = frame.model_copy(update={"types": frame.types[:1]})
    assert frame_digest(changed) != frame_digest(frame)
