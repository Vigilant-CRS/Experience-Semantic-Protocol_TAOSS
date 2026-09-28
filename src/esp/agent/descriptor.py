# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Opaque-latent descriptor (TLV 0x98) and agent event (TLV 0x99) (WP-067; ADR-0028).

V13 section 18.1: the authenticated descriptor MUST identify

1. state kind;
2. model digest and model-version digest;
3. layer range / tensor schema;
4. payload digest;
5. originating agent identity;
6. recipient capability;
7. the visible action or commitment, when one exists;
8. an event ID for causal audit.

It also binds the ESP transcript hash. The companion stream is therefore tied to
*this* session and *this* consent. The descriptor travels inside an authenticated ESP
packet (CONTROL) and is additionally signed by the agent identity (Ed25519, domain
``esp/agent/v1/descriptor``), so its provenance survives outside the session.

Body layout of 0x98 (big-endian, no padding)::

    version u8 = 1 · state_kind u8 · dtype u8 · rank u8 · layer_from u16 · layer_to u16
    shape u32[rank] · model_digest[32] · model_version_digest[32] · payload_digest[32]
    payload_len u64 · agent_pk[32] · recipient_capability_digest[32] · transcript_hash[32]
    event_id[16] · has_action u8 · action_digest[32 if has_action] · signature[64]

Body of 0x99 (agent event)::

    version u8 = 1 · kind u8 · event_id[16] · caused_by[16] (zero = none)
    subject_digest[32] · agent_pk[32] · signature[64]
"""

from __future__ import annotations

import dataclasses
import hashlib
import struct
import uuid
from dataclasses import dataclass
from enum import IntEnum, unique
from typing import Final

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv
from esp.crypto.primitives import SigningKey, ed25519_verify

OPAQUE_DESCRIPTOR_CODE: Final = 0x98
AGENT_EVENT_CODE: Final = 0x99
VERSION: Final = 1
MAX_RANK: Final = 8
_DESC_DOMAIN: Final = b"esp/agent/v1/descriptor"
_EVENT_DOMAIN: Final = b"esp/agent/v1/event"
_HEAD: Final = struct.Struct(">BBBBHH")
_TAIL: Final = struct.Struct(">32s32s32sQ32s32s32s16sB")
_EVENT: Final = struct.Struct(">BB16s16s32s32s")
_ZERO_ID: Final = uuid.UUID(int=0)


def digest(domain: bytes, data: bytes) -> bytes:
    return hashlib.blake2b(domain + data, digest_size=32).digest()


def payload_digest(payload: bytes) -> bytes:
    return digest(b"esp/agent/v1/payload", payload)


def capability_digest(receiver_capability_tlv: bytes | None) -> bytes:
    """Digest of the recipient capability (the canonical 0x22 TLV; default deny by name)."""
    return digest(b"esp/agent/v1/capability", receiver_capability_tlv or b"esp-default-deny-v1")


def action_digest(action: str) -> bytes:
    return digest(b"esp/agent/v1/action", action.encode())


@unique
class StateKind(IntEnum):
    HIDDEN_STATE = 1
    KV_CACHE = 2
    RESIDUAL_STREAM = 3
    LOGITS = 4
    EMBEDDING = 5


@unique
class DType(IntEnum):
    F32 = 1
    F16 = 2
    BF16 = 3
    INT8 = 4

    @property
    def itemsize(self) -> int:
        return {DType.F32: 4, DType.F16: 2, DType.BF16: 2, DType.INT8: 1}[self]


@dataclass(frozen=True, slots=True)
class TensorSchema:
    dtype: DType
    shape: tuple[int, ...]
    layer_from: int
    layer_to: int

    def __post_init__(self) -> None:
        if not 1 <= len(self.shape) <= MAX_RANK or any(not 0 < d < 2**32 for d in self.shape):
            msg = f"tensor shape must have rank 1..{MAX_RANK} and positive u32 dims"
            raise WireError(msg)
        if not 0 <= self.layer_from <= self.layer_to < 2**16:
            msg = "layer range must satisfy 0 <= from <= to < 2^16"
            raise WireError(msg)

    @property
    def nbytes(self) -> int:
        n = self.dtype.itemsize
        for d in self.shape:
            n *= d
        return n


@dataclass(frozen=True, slots=True)
class OpaqueLatentDescriptor:
    state_kind: StateKind
    schema: TensorSchema
    model_digest: bytes
    model_version_digest: bytes
    payload_digest: bytes
    payload_len: int
    agent_pk: bytes
    recipient_capability_digest: bytes
    transcript_hash: bytes
    event_id: uuid.UUID
    action_digest: bytes | None = None
    signature: bytes = b""

    def __post_init__(self) -> None:
        for name in (
            "model_digest",
            "model_version_digest",
            "payload_digest",
            "agent_pk",
            "recipient_capability_digest",
            "transcript_hash",
        ):
            v = getattr(self, name)
            if len(v) != 32 or v == bytes(32):
                msg = f"{name} must be 32 non-zero bytes (mandatory, V13 section 18.1)"
                raise WireError(msg)
        if self.action_digest is not None and len(self.action_digest) != 32:
            msg = "action_digest must be 32 bytes"
            raise WireError(msg)
        if self.event_id == _ZERO_ID:
            msg = "event_id is mandatory"
            raise WireError(msg)
        if self.payload_len != self.schema.nbytes:
            msg = "payload_len does not match the tensor schema"
            raise WireError(msg)

    def body(self) -> bytes:
        s = self.schema
        out = _HEAD.pack(
            VERSION, self.state_kind, s.dtype, len(s.shape), s.layer_from, s.layer_to
        ) + b"".join(struct.pack(">I", d) for d in s.shape)
        out += _TAIL.pack(
            self.model_digest,
            self.model_version_digest,
            self.payload_digest,
            self.payload_len,
            self.agent_pk,
            self.recipient_capability_digest,
            self.transcript_hash,
            self.event_id.bytes,
            self.action_digest is not None,
        )
        return out + (self.action_digest or b"")

    def signed(self, agent: SigningKey) -> OpaqueLatentDescriptor:
        if agent.public_bytes != self.agent_pk:
            msg = "the descriptor must be signed by the originating agent identity"
            raise WireError(msg)
        return dataclasses.replace(self, signature=agent.sign(_DESC_DOMAIN + self.body()))

    def verify(self) -> None:
        ed25519_verify(self.agent_pk, _DESC_DOMAIN + self.body(), self.signature)

    def encode(self) -> Tlv:
        if len(self.signature) != 64:
            msg = "descriptor is not signed"
            raise WireError(msg)
        return Tlv(OPAQUE_DESCRIPTOR_CODE, self.body() + self.signature)

    @classmethod
    def decode(cls, tlv: Tlv) -> OpaqueLatentDescriptor:
        """Strict parse and signature check."""
        v = tlv.value
        if tlv.code != OPAQUE_DESCRIPTOR_CODE or len(v) < _HEAD.size:
            msg = "malformed opaque-latent descriptor"
            raise WireError(msg)
        version, kind, dtype, rank, lf, lt = _HEAD.unpack_from(v)
        if version != VERSION:
            msg = f"unsupported descriptor version {version}"
            raise WireError(msg)
        if not 1 <= rank <= MAX_RANK:
            msg = "descriptor rank out of range"
            raise WireError(msg)
        off = _HEAD.size
        shape_end = off + 4 * rank
        tail_end = shape_end + _TAIL.size
        if len(v) < tail_end:
            msg = "truncated opaque-latent descriptor"
            raise WireError(msg)
        shape = struct.unpack_from(f">{rank}I", v, off)
        md, mvd, pd, plen, apk, rcd, th, eid, has_action = _TAIL.unpack_from(v, shape_end)
        if has_action not in (0, 1):
            msg = "has_action must be 0 or 1"
            raise WireError(msg)
        act_end = tail_end + 32 * has_action
        if len(v) != act_end + 64:
            msg = "opaque-latent descriptor has a wrong length"
            raise WireError(msg)
        try:
            desc = cls(
                state_kind=StateKind(kind),
                schema=TensorSchema(DType(dtype), tuple(shape), lf, lt),
                model_digest=md,
                model_version_digest=mvd,
                payload_digest=pd,
                payload_len=plen,
                agent_pk=apk,
                recipient_capability_digest=rcd,
                transcript_hash=th,
                event_id=uuid.UUID(bytes=eid),
                action_digest=v[tail_end:act_end] if has_action else None,
                signature=v[act_end:],
            )
        except ValueError as exc:
            msg = f"invalid descriptor field: {exc}"
            raise WireError(msg) from None
        desc.verify()
        return desc


@unique
class EventKind(IntEnum):
    LATENT_SENT = 1
    LATENT_RECEIVED = 2
    VISIBLE_ACTION = 3
    REFUSED = 4


@dataclass(frozen=True, slots=True)
class AgentEvent:
    """A signed, event-linked audit statement (TLV 0x99)."""

    kind: EventKind
    event_id: uuid.UUID
    caused_by: uuid.UUID | None
    subject_digest: bytes
    agent_pk: bytes
    signature: bytes = b""

    def body(self) -> bytes:
        return _EVENT.pack(
            VERSION,
            self.kind,
            self.event_id.bytes,
            (self.caused_by or _ZERO_ID).bytes,
            self.subject_digest,
            self.agent_pk,
        )

    def signed(self, agent: SigningKey) -> AgentEvent:
        if agent.public_bytes != self.agent_pk:
            msg = "an agent event must be signed by its agent"
            raise WireError(msg)
        return dataclasses.replace(self, signature=agent.sign(_EVENT_DOMAIN + self.body()))

    def encode(self) -> Tlv:
        if len(self.signature) != 64:
            msg = "agent event is not signed"
            raise WireError(msg)
        return Tlv(AGENT_EVENT_CODE, self.body() + self.signature)

    @classmethod
    def decode(cls, tlv: Tlv) -> AgentEvent:
        v = tlv.value
        if tlv.code != AGENT_EVENT_CODE or len(v) != _EVENT.size + 64:
            msg = "malformed agent event"
            raise WireError(msg)
        version, kind, eid, cause, subject, apk = _EVENT.unpack_from(v)
        if version != VERSION:
            msg = f"unsupported agent event version {version}"
            raise WireError(msg)
        try:
            ev = cls(
                EventKind(kind),
                uuid.UUID(bytes=eid),
                None if cause == bytes(16) else uuid.UUID(bytes=cause),
                subject,
                apk,
                v[_EVENT.size :],
            )
        except ValueError as exc:
            msg = f"invalid agent event field: {exc}"
            raise WireError(msg) from None
        if ev.event_id == _ZERO_ID:
            msg = "event_id is mandatory"
            raise WireError(msg)
        ed25519_verify(apk, _EVENT_DOMAIN + ev.body(), ev.signature)
        return ev
