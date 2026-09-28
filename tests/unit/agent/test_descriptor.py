# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-067: opaque-latent descriptor (0x98) and agent event (0x99)."""

import dataclasses
import struct
import uuid

import pytest

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
    payload_digest,
)
from esp.codec.errors import WireError
from esp.codec.tlv import ADDENDUM_V1_CODES, Tlv
from esp.core.errors import EspError
from esp.crypto.primitives import CryptoError, SigningKey
from esp.registry_service import ADDENDUM_TLV_CODES

pytestmark = pytest.mark.security
AGENT = SigningKey.from_seed(b"\x41" * 32)
OTHER = SigningKey.from_seed(b"\x42" * 32)
EVENT = uuid.UUID("12345678-1234-4234-8234-123456789abc")
MANDATORY_DIGESTS = (
    "model_digest",
    "model_version_digest",
    "payload_digest",
    "agent_pk",
    "recipient_capability_digest",
    "transcript_hash",
)


def descriptor(**kw: object) -> OpaqueLatentDescriptor:
    fields: dict[str, object] = {
        "state_kind": StateKind.KV_CACHE,
        "schema": TensorSchema(DType.F16, (2, 8, 4), 3, 5),
        "model_digest": b"\x01" * 32,
        "model_version_digest": b"\x02" * 32,
        "payload_digest": payload_digest(b"x" * 128),
        "payload_len": 128,
        "agent_pk": AGENT.public_bytes,
        "recipient_capability_digest": b"\x03" * 32,
        "transcript_hash": b"\x04" * 32,
        "event_id": EVENT,
    }
    return OpaqueLatentDescriptor(**(fields | kw))  # type: ignore[arg-type]


def test_codes_are_registered_in_the_addendum_range() -> None:
    assert {OPAQUE_DESCRIPTOR_CODE, AGENT_EVENT_CODE} == {0x98, 0x99}
    assert {0x98, 0x99} <= ADDENDUM_V1_CODES
    assert ADDENDUM_TLV_CODES[0x98] == "AGENT_OPAQUE_LATENT_DESCRIPTOR"
    assert ADDENDUM_TLV_CODES[0x99] == "AGENT_EVENT"


@pytest.mark.parametrize("action", [None, action_digest("close valve 7")])
def test_roundtrip_carries_every_mandatory_field(action: bytes | None) -> None:
    d = descriptor(action_digest=action).signed(AGENT)
    back = OpaqueLatentDescriptor.decode(d.encode())
    assert back == d
    assert back.schema.nbytes == 2 * 8 * 4 * 2
    for name in (*MANDATORY_DIGESTS, "state_kind", "schema", "event_id", "action_digest"):
        assert getattr(back, name) == getattr(d, name)


@pytest.mark.parametrize("field", MANDATORY_DIGESTS)
def test_mandatory_fields_cannot_be_empty(field: str) -> None:
    with pytest.raises(WireError, match="mandatory"):
        descriptor(**{field: bytes(32)})
    with pytest.raises(WireError, match="mandatory"):
        descriptor(**{field: b"\x01" * 31})


def test_field_validation() -> None:
    with pytest.raises(WireError, match="event_id"):
        descriptor(event_id=uuid.UUID(int=0))
    with pytest.raises(WireError, match="payload_len"):
        descriptor(payload_len=127)
    with pytest.raises(WireError, match="rank"):
        TensorSchema(DType.F32, (), 0, 0)
    with pytest.raises(WireError, match="layer range"):
        TensorSchema(DType.F32, (4,), 5, 3)
    with pytest.raises(WireError, match="signed by the originating agent"):
        descriptor().signed(OTHER)
    with pytest.raises(WireError, match="not signed"):
        descriptor().encode()


def test_any_modified_byte_is_refused() -> None:
    tlv = descriptor(action_digest=action_digest("a")).signed(AGENT).encode()
    for i in range(len(tlv.value)):
        mutated = bytearray(tlv.value)
        mutated[i] ^= 0x01
        with pytest.raises(EspError):
            OpaqueLatentDescriptor.decode(Tlv(OPAQUE_DESCRIPTOR_CODE, bytes(mutated)))


def test_malformed_descriptors() -> None:
    good = descriptor().signed(AGENT).encode().value
    cases = {
        "truncated": good[:40],
        "extra byte": good + b"\x00",
        "short head": good[:3],
    }
    for name, value in cases.items():
        with pytest.raises(WireError):
            OpaqueLatentDescriptor.decode(Tlv(OPAQUE_DESCRIPTOR_CODE, value)), name
    with pytest.raises(WireError, match="malformed"):
        OpaqueLatentDescriptor.decode(Tlv(AGENT_EVENT_CODE, good))
    # a re-signed body with an unknown version, rank or state kind is still refused
    body = descriptor().body()
    for offset, value, match in ((0, 2, "version"), (3, 0, "rank"), (1, 99, "invalid")):
        bad = bytearray(body)
        bad[offset] = value
        sig = AGENT.sign(b"esp/agent/v1/descriptor" + bytes(bad))
        with pytest.raises(WireError, match=match):
            OpaqueLatentDescriptor.decode(Tlv(OPAQUE_DESCRIPTOR_CODE, bytes(bad) + sig))


def test_wrong_signer_is_refused() -> None:
    d = descriptor()
    forged = dataclasses.replace(d, signature=OTHER.sign(b"esp/agent/v1/descriptor" + d.body()))
    with pytest.raises(CryptoError):
        OpaqueLatentDescriptor.decode(forged.encode())


def test_agent_event_roundtrip_and_integrity() -> None:
    ev = AgentEvent(
        EventKind.VISIBLE_ACTION, EVENT, uuid.uuid4(), action_digest("go"), AGENT.public_bytes
    ).signed(AGENT)
    assert AgentEvent.decode(ev.encode()) == ev
    genesis = dataclasses.replace(ev, caused_by=None, signature=b"").signed(AGENT)
    assert AgentEvent.decode(genesis.encode()).caused_by is None
    raw = ev.encode().value
    for i in range(len(raw)):
        mutated = bytearray(raw)
        mutated[i] ^= 0x80
        with pytest.raises(EspError):
            AgentEvent.decode(Tlv(AGENT_EVENT_CODE, bytes(mutated)))
    with pytest.raises(WireError, match="signed by its agent"):
        ev.signed(OTHER)
    zero = struct.pack(">BB16s16s32s32s", 1, 3, bytes(16), bytes(16), bytes(32), AGENT.public_bytes)
    with pytest.raises(WireError, match="event_id"):
        AgentEvent.decode(Tlv(AGENT_EVENT_CODE, zero + AGENT.sign(b"esp/agent/v1/event" + zero)))
