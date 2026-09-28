# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""ESP-Agent reference demo: two scripted agents over real ESP endpoints (WP-067).

A *planner* and an *executor* stand in for two LLM agents. They are deterministic
scripts: no network, no model. They communicate only through ESP:

- link planner→executor: capability {KNO, INT, CTX}, profile ``esp-typeset-agent-v1``;
- link executor→planner: capability {KNO, CTX}. The executor has no INT consent;
- typed state goes through the audited ``g_agent`` (goal→INT, context→CTX, facts→KNO);
  the event id is the frame id;
- an opaque hidden-state tensor goes on the companion stream. Its descriptor
  (TLV 0x98) travels on CONTROL and is bound to transcript and capability;
- visible actions are logged with the event that caused them and announced to the
  peer as signed agent events (TLV 0x99). The causal audit checks both logs.
"""

from __future__ import annotations

import hashlib
import secrets
import tempfile
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

import numpy as np

from esp.agent.adapter import AgentAdapter, AgentState
from esp.agent.audit import CausalAudit, EventLog, causal_audit, frame_digest
from esp.agent.companion import CompanionStream, OpaqueLatent, accept_opaque, describe
from esp.agent.descriptor import (
    AGENT_EVENT_CODE,
    OPAQUE_DESCRIPTOR_CODE,
    AgentEvent,
    DType,
    EventKind,
    OpaqueLatentDescriptor,
    StateKind,
    TensorSchema,
    action_digest,
    capability_digest,
    payload_digest,
)
from esp.codec.frame_wire import WireOptions
from esp.consent.capability import AudienceMode, ReceiverCapability, Rights, SenderCapability
from esp.core.errors import ErrorCode, EspError
from esp.core.taoss_types import TaossType, types_to_bitmap
from esp.crypto.noise_ik import StaticKeyPair
from esp.crypto.primitives import SigningKey
from esp.frame.model import DisclosurePolicy, ExperienceFrame
from esp.regulatory.guard import DeploymentContext, Regime, RegulatoryDeclaration
from esp.session.descriptor import SessionDescriptor
from esp.session.endpoint import ReceiverEndpoint, SenderEndpoint
from esp.session.profiles import CUSTOM_PROFILES, custom_profile_digest

T = TaossType
PROFILE: Final = "esp-typeset-agent-v1"
ADDENDUM_DIGEST: Final = hashlib.blake2b(b"esp-addendum-v1/ADR-0011", digest_size=32).digest()
HOUR_NS: Final = 3600 * 10**9
DECLARATION: Final = RegulatoryDeclaration(
    regimes=(Regime.EU_AI_ACT, Regime.EU_GDPR),
    intended_use="ESP-Agent reference demo: two scripted software agents, no natural persons",
    deployment_context=DeploymentContext.OTHER,
    biometric_inputs=False,
    affect_scopes=(),
)
GOALS: Final = (
    ("inspect", "valve_7"),
    ("close", "valve_7"),
    ("open", "valve_3"),
    ("report", "status"),
)
_MODEL: Final = hashlib.blake2b(b"scripted-planner-model", digest_size=32).digest()
_MODEL_VERSION: Final = hashlib.blake2b(b"scripted-planner-model@1", digest_size=32).digest()


class AgentConsentError(EspError):
    code = ErrorCode.CONSENT_DENIED


def descriptor() -> SessionDescriptor:
    return SessionDescriptor(
        profile=1,
        sf_level=0,
        registries={"esp-addendum-v1": ADDENDUM_DIGEST, PROFILE: custom_profile_digest(PROFILE)},
    )


WIRE: Final = WireOptions(addendum=True)


@dataclass
class ScriptedAgent:
    """A deterministic stand-in for an LLM agent: identity, event log, visible policy."""

    name: str
    policy: Callable[[ScriptedAgent, ExperienceFrame | OpaqueLatent], str | None]
    key: SigningKey = field(default_factory=SigningKey.generate)
    static: StaticKeyPair = field(default_factory=StaticKeyPair.generate)
    log: EventLog = field(init=False)
    notices: list[AgentEvent] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.log = EventLog(self.name)

    @property
    def pk(self) -> bytes:
        return self.key.public_bytes


@dataclass
class Link:
    """One direction of agent communication: an established ESP session."""

    src: ScriptedAgent
    dst: ScriptedAgent
    sender: SenderEndpoint
    receiver: ReceiverEndpoint
    companion: CompanionStream = field(default_factory=CompanionStream)
    sequence: int = 0


def open_link(
    src: ScriptedAgent,
    dst: ScriptedAgent,
    *,
    sender_types: Iterable[TaossType],
    receiver_types: Iterable[TaossType],
    now_ns: int,
    state_dir: Path,
) -> Link:
    """Establish a real Noise IK session with capabilities, in process."""
    accept = frozenset(receiver_types)

    def receiver_cap(noise_h: bytes) -> ReceiverCapability:
        return ReceiverCapability(
            accept_types=types_to_bitmap(accept),
            max_norm=(2.0,) * len(accept),
            valence_bounds=None,
            rate_limit_hz=100,
            valid_from_ns=now_ns - HOUR_NS,
            valid_until_ns=now_ns + HOUR_NS,
            nonce=secrets.token_bytes(16),
            pk_receiver=dst.pk,
            noise_h=noise_h,
        )

    sender = SenderEndpoint(
        master=src.key,
        static=src.static,
        responder_static=dst.static.public_bytes,
        receiver_identity=dst.pk,
        descriptor=descriptor(),
        capability=SenderCapability(
            capability_id=uuid.uuid4(),
            types_allowed=types_to_bitmap(sender_types),
            rights=Rights(0),
            max_segments=1000,
            dp_epsilon_ceiling=0.0,
            valid_until_ns=now_ns + HOUR_NS,
            audience_mode=AudienceMode.RECIPIENT_PUBKEY,
            audience_value=dst.pk,
            issuer_pk=src.pk,
            nonce=secrets.token_bytes(16),
        ),
        state_dir=state_dir,
        wire=WIRE,
        declaration=DECLARATION,
    )
    receiver = ReceiverEndpoint(
        identity=dst.key,
        static=dst.static,
        descriptor=descriptor(),
        capability=receiver_cap,
        trusted_issuers=frozenset({src.pk}),
        wire=WIRE,
        declaration=DECLARATION,
    )
    hs2, t1 = receiver.on_handshake1(sender.start())
    sender.on_handshake2(hs2)
    receiver.on_transport2(sender.on_transport1(t1))
    return Link(src, dst, sender, receiver)


def granted_types(link: Link) -> frozenset[TaossType]:
    """Types this link may carry: c_S ∩ receiver policy ∩ session profile."""
    policy = link.sender.effective_policy(DisclosurePolicy(allowed_types=tuple(TaossType)))
    return frozenset(policy.allowed_types)


def send_state(
    link: Link,
    adapter: AgentAdapter,
    state: AgentState,
    types: Iterable[TaossType],
    *,
    now_ns: int,
) -> tuple[uuid.UUID, bytes]:
    """Send typed agent state. Refused (and logged) if ``types`` exceed the grant."""
    requested = frozenset(types)
    event_id = uuid.uuid4()
    over = requested - granted_types(link)
    if over:
        link.src.log.append(
            EventKind.REFUSED,
            event_id,
            subject_digest=bytes(32),
            detail=f"no capability for {sorted(t.name for t in over)}",
        )
        msg = f"{link.src.name} has no capability to send {sorted(t.name for t in over)}"
        raise AgentConsentError(msg)
    link.sequence += 1
    frame = adapter.typed_frame(
        state,
        timeline_id=link.sender.timeline_id,
        sequence=link.sequence,
        now_ns=now_ns,
        event_id=event_id,
    )
    policy = DisclosurePolicy(allowed_types=tuple(sorted(requested)))
    packet = link.sender.send_frame(frame, policy, now_ns=now_ns)
    disclosed = frame.disclose(link.sender.effective_policy(policy))
    link.src.log.append(
        EventKind.LATENT_SENT,
        event_id,
        subject_digest=frame_digest(disclosed),
        detail="typed " + ",".join(t.name for t in disclosed.present_types),
    )
    return event_id, packet


def send_opaque(
    link: Link, tensor: np.ndarray, *, state_kind: StateKind, layers: tuple[int, int], now_ns: int
) -> tuple[uuid.UUID, bytes]:
    """Opaque tensor on the companion stream; its signed descriptor on ESP CONTROL."""
    payload = np.ascontiguousarray(tensor, dtype=">f4").tobytes()
    event_id = uuid.uuid4()
    transcript = link.sender.transcript
    if transcript is None:  # pragma: no cover - the link is established
        msg = "no session transcript"
        raise AgentConsentError(msg)
    desc = OpaqueLatentDescriptor(
        state_kind=state_kind,
        schema=TensorSchema(DType.F32, tuple(int(d) for d in tensor.shape), *layers),
        model_digest=_MODEL,
        model_version_digest=_MODEL_VERSION,
        payload_digest=payload_digest(payload),
        payload_len=len(payload),
        agent_pk=link.src.pk,
        recipient_capability_digest=capability_digest(link.sender.receiver_capability_tlv),
        transcript_hash=transcript,
        event_id=event_id,
    ).signed(link.src.key)
    link.companion.put(desc, payload)
    packet = link.sender.send_control(desc.encode().encode(), now_ns=now_ns)
    link.src.log.append(
        EventKind.LATENT_SENT,
        event_id,
        subject_digest=desc.payload_digest,
        detail=f"opaque {state_kind.name}",
    )
    return event_id, packet


def _act(agent: ScriptedAgent, cause: uuid.UUID, action: str) -> AgentEvent:
    event_id = uuid.uuid4()
    agent.log.append(
        EventKind.VISIBLE_ACTION,
        event_id,
        caused_by=cause,
        subject_digest=action_digest(action),
        detail=f"action {action}",
    )
    return AgentEvent(
        EventKind.VISIBLE_ACTION, event_id, cause, action_digest(action), agent.pk
    ).signed(agent.key)


def deliver(link: Link, packet: bytes, *, now_ns: int) -> list[AgentEvent]:
    """Receive at ``link.dst``: log, verify companions, run the visible policy."""
    dst = link.dst
    result = link.receiver.receive(packet, now_ns=now_ns)
    if not result.accepted:
        dst.log.append(
            EventKind.REFUSED,
            uuid.uuid4(),
            subject_digest=bytes(32),
            detail="refused: " + "; ".join(result.violations),
        )
        return []
    actions: list[AgentEvent] = []
    items: list[tuple[uuid.UUID, bytes, ExperienceFrame | OpaqueLatent]] = []
    if result.frame is not None:
        items.append((result.frame.frame_id, frame_digest(result.frame), result.frame))
    for tlv in result.control:
        if tlv.code == OPAQUE_DESCRIPTOR_CODE:
            desc = OpaqueLatentDescriptor.decode(tlv)
            opaque = accept_opaque(
                desc,
                link.companion.take(desc),
                transcript=link.receiver.transcript,
                receiver_capability_tlv=link.receiver.capability_tlv,
                expected_agent=link.src.pk,
            )
            items.append((desc.event_id, desc.payload_digest, opaque))
        elif tlv.code == AGENT_EVENT_CODE:
            event = AgentEvent.decode(tlv)
            if event.agent_pk != link.src.pk:
                msg = "agent event from an unexpected agent"
                raise AgentConsentError(msg)
            dst.notices.append(event)
    for event_id, subject, item in items:
        kind = "opaque" if isinstance(item, OpaqueLatent) else "typed"
        dst.log.append(
            EventKind.LATENT_RECEIVED, event_id, subject_digest=subject, detail=f"{kind} received"
        )
        action = dst.policy(dst, item)
        if action is not None:
            actions.append(_act(dst, event_id, action))
    return actions


def decode_goal(adapter: AgentAdapter, frame: ExperienceFrame) -> tuple[str, ...] | None:
    """Nearest candidate goal by INT cosine (the executor shares the public adapter)."""
    block = frame.block(T.INT)
    if block is None or block.latent is None:
        return None
    z = np.asarray(block.latent)
    scores = [float(z @ adapter.encode(AgentState(g, (), ()))[T.INT]) for g in GOALS]
    return GOALS[int(np.argmax(scores))]


@dataclass(frozen=True, slots=True)
class AgentDemoResult:
    planner: EventLog
    executor: EventLog
    audit: CausalAudit
    reports: tuple[dict[str, Any], ...]
    refused: tuple[str, ...]
    executor_notices: int
    planner_notices: int


def audit_sample(seed: int = 0, n: int = 300) -> list[AgentState]:
    """Synthetic agent states with independent goal/context/fact tokens (audit sample)."""
    rng = np.random.default_rng(seed)
    vocab = [f"tok{i}" for i in range(400)]

    def pick(k: int) -> tuple[str, ...]:
        return tuple(str(x) for x in rng.choice(vocab, size=k, replace=False))

    return [AgentState(pick(2), pick(3), pick(3)) for _ in range(n)]


def run_agent_demo(*, now_ns: int = 10**18) -> AgentDemoResult:
    adapter = AgentAdapter().audited(audit_sample())
    reports: list[dict[str, Any]] = []
    refused: list[str] = []

    def executor_policy(agent: ScriptedAgent, item: ExperienceFrame | OpaqueLatent) -> str:
        if isinstance(item, OpaqueLatent):
            reports.append(describe(item, adapter_audited=False))
            return "cache_opaque_state"
        reports.append(describe(item, adapter_audited=adapter.audit is not None))
        goal = decode_goal(adapter, item)
        return "execute:" + "_".join(goal) if goal else "ask_for_goal"

    def planner_policy(agent: ScriptedAgent, item: ExperienceFrame | OpaqueLatent) -> str:
        reports.append(describe(item, adapter_audited=adapter.audit is not None))
        return "mark_step_done"

    planner = ScriptedAgent("planner", planner_policy)
    executor = ScriptedAgent("executor", executor_policy)
    profile_types = CUSTOM_PROFILES[PROFILE].allowed
    with tempfile.TemporaryDirectory() as tmp:
        ab = open_link(
            planner,
            executor,
            sender_types=profile_types,
            receiver_types=profile_types,
            now_ns=now_ns,
            state_dir=Path(tmp),
        )
        ba = open_link(
            executor,
            planner,
            sender_types={T.KNO, T.CTX},  # the executor has no INT consent
            receiver_types=profile_types,
            now_ns=now_ns,
            state_dir=Path(tmp),
        )
        # 1. planner shares its goal, context and facts; the executor acts on it
        state = AgentState(GOALS[1], ("plant_north", "shift_2"), ("valve_7_pressure_high",))
        _, packet = send_state(ab, adapter, state, {T.KNO, T.INT, T.CTX}, now_ns=now_ns)
        for ev in deliver(ab, packet, now_ns=now_ns):
            deliver(ba, ba.sender.send_control(ev.encode().encode(), now_ns=now_ns), now_ns=now_ns)
        # 2. planner shares an opaque hidden state on the companion stream
        tensor = np.linspace(-1.0, 1.0, 64, dtype=np.float32).reshape(4, 16)
        _, packet = send_opaque(
            ab, tensor, state_kind=StateKind.HIDDEN_STATE, layers=(10, 12), now_ns=now_ns
        )
        for ev in deliver(ab, packet, now_ns=now_ns):
            deliver(ba, ba.sender.send_control(ev.encode().encode(), now_ns=now_ns), now_ns=now_ns)
        # 3. the executor tries to send INT without capability: refused before the wire
        status = AgentState(("report", "status"), ("plant_north",), ("valve_7_closed",))
        try:
            send_state(ba, adapter, status, {T.KNO, T.INT, T.CTX}, now_ns=now_ns)
        except AgentConsentError as exc:
            refused.append(str(exc))
        # 4. ... and reports KNO + CTX, which it may send
        _, packet = send_state(ba, adapter, status, {T.KNO, T.CTX}, now_ns=now_ns)
        for ev in deliver(ba, packet, now_ns=now_ns):
            deliver(ab, ab.sender.send_control(ev.encode().encode(), now_ns=now_ns), now_ns=now_ns)
    return AgentDemoResult(
        planner=planner.log,
        executor=executor.log,
        audit=causal_audit(planner.log, executor.log),
        reports=tuple(reports),
        refused=tuple(refused),
        executor_notices=len(executor.notices),
        planner_notices=len(planner.notices),
    )
