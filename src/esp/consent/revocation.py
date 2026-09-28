# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Revocation intent (0x23) and deletion attestation (0x24). ``V13_NORMATIVE``.

Revocation is a first-class *request*: it can forbid future use, request
deletion of stored and derived data and terminate sessions. A deletion
attestation is a signed *claim* by the recipient, never a proof of erasure.

Scopes (V13 section 9.7):

- capability scope: ``timeline_id`` all-zero, ``capability_id`` non-zero —
  every cooperating recipient persists the revoked id and rejects all future
  sessions and packets under it. ``CONSENT_WITHDRAWN`` MUST use this scope.
- timeline scope: non-zero ``timeline_id`` revokes that timeline from
  ``revoke_from_seq`` on.
- all-zero ``capability_id``: timeline-local *technical* revocation only,
  signed by the session's authenticated master binding; never for consent.

Authority: the signer is the capability issuer or a verified, non-compromised
successor in its lineage. Revocations can only narrow rights.
"""

from __future__ import annotations

import struct
import uuid
from dataclasses import dataclass, field
from enum import IntEnum, IntFlag, unique
from typing import Final

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv
from esp.consent.capability import SenderCapability
from esp.crypto.primitives import CryptoError, blake2b
from esp.crypto.signed import Signer, sign_tlv, verify_signed_tlv
from esp.keys.lineage import KeyLineage

REVOCATION_CODE: Final = 0x23
DELETION_ATTESTATION_CODE: Final = 0x24
_REVOCATION: Final = struct.Struct(">B16s16sQBB32s32s")  # 107 bytes before sig
_ATTESTATION: Final = struct.Struct(">B16s16sB32s32sQ32s")  # 138 bytes before sig
ZERO16: Final = bytes(16)


@unique
class ConsentRevocationReason(IntEnum):
    COMPROMISED = 0
    CONSENT_WITHDRAWN = 1
    ERROR = 2


class Effects(IntFlag):
    REVOKE_FUTURE_USE = 1 << 0
    REQUEST_DELETE_STORED = 1 << 1
    REQUEST_DELETE_DERIVED = 1 << 2
    TERMINATE_SESSIONS = 1 << 3


class DeletionScope(IntFlag):
    LIVE_STATE = 1 << 0
    STORED_CAPSULES = 1 << 1
    DERIVED_ARTIFACTS = 1 << 2


@dataclass(frozen=True, slots=True)
class RevocationIntent:
    capability_id: uuid.UUID
    timeline_id: uuid.UUID
    revoke_from_seq: int
    reason: ConsentRevocationReason
    effects: Effects
    capability_issuer_pk: bytes
    signer_pk: bytes
    version: int = 1

    def __post_init__(self) -> None:
        if int(self.effects) & ~0x0F:
            msg = "effects_flags bits 4-7 must be zero"
            raise WireError(msg)
        cap_zero = self.capability_id.bytes == ZERO16
        timeline_zero = self.timeline_id.bytes == ZERO16
        if self.reason is ConsentRevocationReason.CONSENT_WITHDRAWN and (
            cap_zero or not timeline_zero
        ):
            msg = "CONSENT_WITHDRAWN must use capability scope"
            raise WireError(msg)
        if cap_zero and timeline_zero:
            msg = "revocation needs a capability or a timeline"
            raise WireError(msg)
        if not 0 <= self.revoke_from_seq <= 2**64 - 1:
            msg = "revoke_from_seq out of range"
            raise WireError(msg)
        if len(self.capability_issuer_pk) != 32 or len(self.signer_pk) != 32:
            msg = "keys must be 32 bytes"
            raise WireError(msg)

    @property
    def capability_scope(self) -> bool:
        return self.timeline_id.bytes == ZERO16

    def body(self) -> bytes:
        return _REVOCATION.pack(
            self.version,
            self.capability_id.bytes,
            self.timeline_id.bytes,
            self.revoke_from_seq,
            self.reason,
            int(self.effects),
            self.capability_issuer_pk,
            self.signer_pk,
        )

    def sign(self, signer: Signer) -> Tlv:
        return sign_tlv(REVOCATION_CODE, self.body(), signer)

    @classmethod
    def verify(cls, tlv: Tlv) -> RevocationIntent:
        if tlv.code != REVOCATION_CODE or len(tlv.value) != _REVOCATION.size + 64:
            msg = "malformed revocation intent"
            raise WireError(msg)
        ver, cid, tid, seq, reason, effects, issuer, signer = _REVOCATION.unpack(
            tlv.value[: _REVOCATION.size]
        )
        try:
            intent = cls(
                capability_id=uuid.UUID(bytes=cid),
                timeline_id=uuid.UUID(bytes=tid),
                revoke_from_seq=seq,
                reason=ConsentRevocationReason(reason),
                effects=Effects(effects),
                capability_issuer_pk=issuer,
                signer_pk=signer,
                version=ver,
            )
        except ValueError as exc:
            raise WireError(str(exc)) from None
        verify_signed_tlv(tlv, signer)
        return intent


@dataclass(slots=True)
class RevocationRegistry:
    """Persisted by every cooperating recipient."""

    revoked_capabilities: set[bytes] = field(default_factory=set)
    revoked_timelines: dict[bytes, int] = field(default_factory=dict)
    deletion_requests: list[RevocationIntent] = field(default_factory=list)

    def apply(
        self,
        tlv: Tlv,
        *,
        capability: SenderCapability | None,
        lineage: KeyLineage | None,
        session_master_pk: bytes | None = None,
    ) -> RevocationIntent:
        intent = RevocationIntent.verify(tlv)
        if intent.capability_id.bytes == ZERO16:
            if session_master_pk is None or intent.signer_pk != session_master_pk:
                msg = "technical revocation must be signed by the session master binding"
                raise CryptoError(msg)
        else:
            if capability is None or capability.capability_id != intent.capability_id:
                msg = "revocation references an unknown capability"
                raise CryptoError(msg)
            if intent.capability_issuer_pk != capability.issuer_pk:
                msg = "capability_issuer_pk does not match the capability"
                raise CryptoError(msg)
            authorized = intent.signer_pk == capability.issuer_pk or (
                lineage is not None and lineage.can_reduce(capability.issuer_pk, intent.signer_pk)
            )
            if not authorized or (lineage is not None and lineage.is_compromised(intent.signer_pk)):
                msg = "signer is neither the issuer nor a verified non-compromised successor"
                raise CryptoError(msg)
        if intent.capability_scope:
            self.revoked_capabilities.add(intent.capability_id.bytes)
        else:
            tid = intent.timeline_id.bytes
            previous = self.revoked_timelines.get(tid)
            self.revoked_timelines[tid] = (
                intent.revoke_from_seq
                if previous is None
                else min(previous, intent.revoke_from_seq)
            )
        if intent.effects & (Effects.REQUEST_DELETE_STORED | Effects.REQUEST_DELETE_DERIVED):
            self.deletion_requests.append(intent)
        return intent

    def is_revoked(self, capability_id: uuid.UUID, timeline_id: uuid.UUID, seq: int) -> bool:
        if capability_id.bytes in self.revoked_capabilities:
            return True
        start = self.revoked_timelines.get(timeline_id.bytes)
        return start is not None and seq >= start


@dataclass(frozen=True, slots=True)
class DeletionAttestation:
    """A recipient's signed *claim* to have executed a deletion request."""

    capability_id: uuid.UUID
    timeline_id: uuid.UUID
    scope: DeletionScope
    request_digest: bytes
    target_digest: bytes
    attested_at_ns: int
    signer_pk: bytes
    version: int = 1

    def body(self) -> bytes:
        return _ATTESTATION.pack(
            self.version,
            self.capability_id.bytes,
            self.timeline_id.bytes,
            int(self.scope),
            self.request_digest,
            self.target_digest,
            self.attested_at_ns,
            self.signer_pk,
        )

    def sign(self, signer: Signer) -> Tlv:
        if int(self.scope) & ~0x07:
            msg = "scope_flags bits 3-7 must be zero"
            raise WireError(msg)
        return sign_tlv(DELETION_ATTESTATION_CODE, self.body(), signer)

    @classmethod
    def verify(cls, tlv: Tlv, *, request: Tlv) -> DeletionAttestation:
        """Verify the claim and that it binds exactly this revocation request."""
        if tlv.code != DELETION_ATTESTATION_CODE or len(tlv.value) != _ATTESTATION.size + 64:
            msg = "malformed deletion attestation"
            raise WireError(msg)
        ver, cid, tid, scope, req, target, at, signer = _ATTESTATION.unpack(
            tlv.value[: _ATTESTATION.size]
        )
        if scope & ~0x07:
            msg = "scope_flags bits 3-7 must be zero"
            raise WireError(msg)
        verify_signed_tlv(tlv, signer)
        if req != request_digest(request):
            msg = "attestation does not bind this request"
            raise CryptoError(msg)
        return cls(
            capability_id=uuid.UUID(bytes=cid),
            timeline_id=uuid.UUID(bytes=tid),
            scope=DeletionScope(scope),
            request_digest=req,
            target_digest=target,
            attested_at_ns=at,
            signer_pk=signer,
            version=ver,
        )


def request_digest(request: Tlv) -> bytes:
    """Digest of the canonical revocation/deletion request (its exact TLV bytes)."""
    return blake2b(request.encode())
