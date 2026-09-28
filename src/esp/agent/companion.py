# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Companion tensor stream bound to the ESP transcript (WP-067; V13 section 18.1).

The tensor itself travels on a companion stream, outside the ESP payload. The
descriptor (TLV 0x98, inside an authenticated ESP packet) binds:

- the payload digest and length;
- the ESP transcript hash (so the tensor belongs to *this* session);
- the recipient capability digest (so it belongs to *this* consent).

:func:`accept_opaque` refuses on any mismatch. Wrapping opaque bytes in ESP does
**not** make them TAOSS: :func:`describe` never attributes TAOSS types or TAOSS
consent guarantees to an opaque payload.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Final

from esp.agent.descriptor import (
    OpaqueLatentDescriptor,
    capability_digest,
    payload_digest,
)
from esp.core.errors import ErrorCode, EspError
from esp.frame.model import ExperienceFrame

OPAQUE_NOTICE: Final = (
    "opaque latent payload: not a TAOSS representation. ESP binds integrity, provenance, "
    "capability, transcript and event audit only; no typed consent, masking or leakage "
    "guarantee applies to its contents"
)


class CompanionError(EspError):
    code = ErrorCode.CRYPTO_AUTH_FAILED


@dataclass
class CompanionStream:
    """In-memory companion channel: event id → tensor bytes (the transport is out of scope)."""

    _items: dict[bytes, bytes] = field(default_factory=dict)

    def put(self, descriptor: OpaqueLatentDescriptor, payload: bytes) -> None:
        self._items[descriptor.event_id.bytes] = payload

    def take(self, descriptor: OpaqueLatentDescriptor) -> bytes:
        try:
            return self._items.pop(descriptor.event_id.bytes)
        except KeyError:
            msg = "no companion payload for this event"
            raise CompanionError(msg) from None


@dataclass(frozen=True, slots=True)
class OpaqueLatent:
    """An accepted opaque payload. It is never presented as TAOSS."""

    descriptor: OpaqueLatentDescriptor
    payload: bytes


def accept_opaque(
    descriptor: OpaqueLatentDescriptor,
    payload: bytes,
    *,
    transcript: bytes | None,
    receiver_capability_tlv: bytes | None,
    expected_agent: bytes,
) -> OpaqueLatent:
    """Verify a companion payload against its descriptor and the live session."""
    descriptor.verify()
    if descriptor.agent_pk != expected_agent:
        msg = "descriptor signed by an unexpected agent"
        raise CompanionError(msg)
    if transcript is None or descriptor.transcript_hash != transcript:
        msg = "descriptor is not bound to this ESP session transcript"
        raise CompanionError(msg)
    if descriptor.recipient_capability_digest != capability_digest(receiver_capability_tlv):
        msg = "descriptor names another recipient capability"
        raise CompanionError(msg)
    if len(payload) != descriptor.payload_len or payload_digest(payload) != (
        descriptor.payload_digest
    ):
        msg = "companion payload does not match the descriptor digest"
        raise CompanionError(msg)
    return OpaqueLatent(descriptor, payload)


def describe(item: OpaqueLatent | ExperienceFrame, *, adapter_audited: bool) -> dict[str, Any]:
    """UI/report view. Only typed frames from an audited ``g_agent`` are called TAOSS."""
    if isinstance(item, OpaqueLatent):
        d = item.descriptor
        return {
            "kind": "opaque",
            "taoss_types": [],
            "consent_guarantees": None,
            "notice": OPAQUE_NOTICE,
            "state_kind": d.state_kind.name,
            "event_id": str(d.event_id),
            "payload_bytes": d.payload_len,
        }
    typed = adapter_audited
    return {
        "kind": "typed" if typed else "unaudited",
        "taoss_types": [t.name for t in item.present_types] if typed else [],
        "consent_guarantees": "TAOSS typed consent (audited g_agent)" if typed else None,
        "event_id": str(item.frame_id),
    }
