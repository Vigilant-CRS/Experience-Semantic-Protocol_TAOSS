# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GATED_CEK reference gate, tombstones and recall (WP-068; GAP-018 reference proposal).

``access_material`` for ``GATED_CEK`` = ``gate_id[16] ‖ wrap_nonce[12] ‖ wrapped_cek[48]``:
the per-capsule CEK encrypted with ChaCha20-Poly1305 under the gate secret,
AAD = ``"esp/xcf/v1/gate" ‖ gate_id ‖ envelope prefix``. The gate secret is
never in the capsule. A :class:`Gate` holds it (or a guardian quorum holds
Shamir shares of it). Release requires:

1. a valid capsule signature;
2. no tombstone for the CID;
3. a live, non-revoked capability that covers the capsule's types.

The CEK is then re-wrapped to a session-bound X25519 recipient key (HPKE).
Destroying the gate secret prevents future first-time release; it cannot
revoke CEKs or plaintext already released (V13).

Tombstones are signed by the capsule's lineage master (``sender_binding``)
over ``"esp/xcf/v1/tombstone" ‖ CID``. Recall (V13 "Recall Path") checks
capability, types, DP budget and expiry, and denies if ``NO_REPLAY`` is set
anywhere in the lineage; the ``RECALL_FRAME`` TLV (0x51) points to
``cid, offset_ns, span_ns``.
"""

from __future__ import annotations

import hashlib
import math
import os
import struct
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Final

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from esp.codec.tlv import Tlv
from esp.consent.accept import audience_proof_ok
from esp.consent.capability import AudienceMode, Rights, SenderCapability
from esp.consent.revocation import RevocationRegistry
from esp.core.taoss_types import bitmap_to_types
from esp.crypto.primitives import CryptoError, SigningKey, ed25519_verify
from esp.keys.custody import Share, combine_shares, split_secret
from esp.xcf.capsule import HPKE_SUITE, PREFIX_LEN, Capsule, EnvelopeAlg, XcfError

RECALL_FRAME_CODE: Final = 0x51
_ZERO: Final = uuid.UUID(int=0)
_RECALL: Final = struct.Struct(">32sQQI")


class GateRefused(XcfError):  # noqa: N818 - a protocol outcome
    pass


def gated_access(
    gate_id: bytes, gate_secret: bytes, wrap_nonce: bytes | None = None
) -> Callable[[bytes, bytes], bytes]:
    if len(gate_id) != 16 or len(gate_secret) != 32:
        msg = "gate_id must be 16 bytes and the gate secret 32 bytes"
        raise XcfError(msg)

    def material(cek: bytes, prefix: bytes) -> bytes:
        nonce = os.urandom(12) if wrap_nonce is None else wrap_nonce  # fixed only for vectors
        wrapped = ChaCha20Poly1305(gate_secret).encrypt(
            nonce, cek, b"esp/xcf/v1/gate" + gate_id + prefix
        )
        return gate_id + nonce + wrapped

    return material


@dataclass(frozen=True, slots=True)
class Tombstone:
    cid: bytes
    signer_pk: bytes
    signature: bytes

    @classmethod
    def create(cls, cid: bytes, master: SigningKey) -> Tombstone:
        return cls(cid, master.public_bytes, master.sign(b"esp/xcf/v1/tombstone" + cid))

    def verify(self) -> None:
        ed25519_verify(self.signer_pk, b"esp/xcf/v1/tombstone" + self.cid, self.signature)


@dataclass(frozen=True, slots=True)
class ReleaseRequest:
    """Recipient proof binding a signed grant, CID and HPKE key (local gate API)."""

    recipient_pk: bytes
    valid_until_ns: int
    signature: bytes

    @staticmethod
    def _message(capsule: Capsule, grant: Tlv, key: X25519PublicKey, until: int) -> bytes:
        return (
            b"esp/xcf/v1/release-request"
            + capsule.cid
            + hashlib.sha256(grant.encode()).digest()
            + key.public_bytes_raw()
            + struct.pack(">Q", until)
        )

    @classmethod
    def create(
        cls,
        capsule: Capsule,
        grant: Tlv,
        recipient: X25519PublicKey,
        identity: SigningKey,
        *,
        valid_until_ns: int,
    ) -> ReleaseRequest:
        return cls(
            identity.public_bytes,
            valid_until_ns,
            identity.sign(cls._message(capsule, grant, recipient, valid_until_ns)),
        )

    def verify(self, capsule: Capsule, grant: Tlv, key: X25519PublicKey, now_ns: int) -> None:
        if now_ns > self.valid_until_ns:
            msg = "recipient release request expired"
            raise GateRefused(msg)
        ed25519_verify(
            self.recipient_pk,
            self._message(capsule, grant, key, self.valid_until_ns),
            self.signature,
        )


def _check_audience(
    cap: SenderCapability,
    recipient_pk: bytes,
    proof: Sequence[tuple[bytes, bool]] | None,
) -> None:
    ok = (
        cap.audience_value == recipient_pk
        if cap.audience_mode is AudienceMode.RECIPIENT_PUBKEY
        else proof is not None and audience_proof_ok(cap.audience_value, recipient_pk, proof)
    )
    if not ok:
        msg = "recipient not in capability audience"
        raise GateRefused(msg)


@dataclass
class Gate:
    """Reference gate service holding gate secrets (single operator or guardian quorum)."""

    owners: dict[bytes, bytes] = field(default_factory=dict)
    secrets: dict[bytes, bytes] = field(default_factory=dict)
    quorum: dict[bytes, tuple[int, list[Share]]] = field(default_factory=dict)
    tombstones: dict[bytes, Tombstone] = field(default_factory=dict)
    released: list[bytes] = field(default_factory=list)

    def new_gate(
        self, owner_pk: bytes, *, guardians: int = 0, threshold: int = 0
    ) -> tuple[bytes, bytes]:
        """Create a gate; with guardians, only Shamir shares are kept (no single secret)."""
        if len(owner_pk) != 32:
            msg = "gate owner must be an Ed25519 public key"
            raise GateRefused(msg)
        gate_id, secret = os.urandom(16), os.urandom(32)
        self.owners[gate_id] = owner_pk
        if guardians:
            self.quorum[gate_id] = (threshold, split_secret(secret, threshold, guardians))
        else:
            self.secrets[gate_id] = secret
        return gate_id, secret

    def destroy(self, gate_id: bytes) -> None:
        """Destroy the gate secret: no future first-time release is possible."""
        self.secrets.pop(gate_id, None)
        self.quorum.pop(gate_id, None)

    def tombstone(self, capsule: Capsule, ts: Tombstone, lineage_master: bytes) -> None:
        capsule.verify_signature()
        owner = self.owners.get(capsule.envelope[PREFIX_LEN : PREFIX_LEN + 16])
        ts.verify()
        if ts.cid != capsule.cid or ts.signer_pk != lineage_master or lineage_master != owner:
            msg = "tombstone must be signed by the capsule's lineage master"
            raise GateRefused(msg)
        self.tombstones[ts.cid] = ts

    def _secret(self, gate_id: bytes, guardian_shares: Sequence[Share] | None) -> bytes:
        if gate_id in self.secrets:
            return self.secrets[gate_id]
        if gate_id in self.quorum:
            threshold, _ = self.quorum[gate_id]
            if guardian_shares is None or len(guardian_shares) < threshold:
                msg = "guardian quorum not reached"
                raise GateRefused(msg)
            return combine_shares(guardian_shares)
        msg = "gate secret destroyed or unknown"
        raise GateRefused(msg)

    def release(
        self,
        capsule: Capsule,
        capability: Tlv,
        recipient: X25519PublicKey,
        *,
        now_ns: int,
        revocations: RevocationRegistry,
        request: ReleaseRequest,
        audience_proof: Sequence[tuple[bytes, bool]] | None = None,
        guardian_shares: Sequence[Share] | None = None,
    ) -> bytes:
        """Validate, then re-wrap the CEK to ``recipient`` (HPKE). Returns the wrapped CEK."""
        grant = capability
        cap = SenderCapability.verify(grant)
        request.verify(capsule, grant, recipient, now_ns)
        _check_audience(cap, request.recipient_pk, audience_proof)
        capsule.verify_signature()
        h = capsule.header
        if h.key_envelope_alg is not EnvelopeAlg.GATED_CEK:
            msg = "not a GATED_CEK capsule"
            raise GateRefused(msg)
        if capsule.cid in self.tombstones:
            msg = "capsule is tombstoned"
            raise GateRefused(msg)
        if cap.valid_until_ns < now_ns or revocations.is_revoked(cap.capability_id, _ZERO, 0):
            msg = "capability expired or revoked"
            raise GateRefused(msg)
        if not set(bitmap_to_types(h.types_bitmap)) <= set(cap.types):
            msg = "capability does not cover the capsule types"
            raise GateRefused(msg)
        env = capsule.envelope
        gate_id, nonce, wrapped = (
            env[PREFIX_LEN : PREFIX_LEN + 16],
            env[PREFIX_LEN + 16 : PREFIX_LEN + 28],
            env[PREFIX_LEN + 28 :],
        )
        if self.owners.get(gate_id) != cap.issuer_pk:
            msg = "capability issuer is not the registered gate owner"
            raise GateRefused(msg)
        secret = self._secret(gate_id, guardian_shares)
        try:
            cek = ChaCha20Poly1305(secret).decrypt(
                nonce, wrapped, b"esp/xcf/v1/gate" + gate_id + env[:PREFIX_LEN]
            )
        except Exception as exc:
            msg = "gate unwrap failed"
            raise CryptoError(msg) from exc
        self.released.append(capsule.cid)
        return HPKE_SUITE.encrypt(cek, recipient, info=b"esp/xcf/v1/gate-release" + capsule.cid)


def unwrap_release(capsule: Capsule, released: bytes, recipient: X25519PrivateKey) -> bytes:
    return HPKE_SUITE.decrypt(released, recipient, info=b"esp/xcf/v1/gate-release" + capsule.cid)


# --- recall --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class RecallFrame:
    cid: bytes
    offset_ns: int
    span_ns: int
    flags: int = 0

    def encode(self) -> Tlv:
        if self.flags:
            msg = "RECALL_FRAME flags are reserved in v1"
            raise XcfError(msg)
        return Tlv(
            RECALL_FRAME_CODE, _RECALL.pack(self.cid, self.offset_ns, self.span_ns, self.flags)
        )

    @classmethod
    def decode(cls, tlv: Tlv) -> RecallFrame:
        if tlv.code != RECALL_FRAME_CODE or len(tlv.value) != _RECALL.size:
            msg = "malformed RECALL_FRAME"
            raise XcfError(msg)
        cid, off, span, flags = _RECALL.unpack(tlv.value)
        if flags:
            msg = "RECALL_FRAME flags are reserved in v1"
            raise XcfError(msg)
        return cls(cid, off, span, flags)


@dataclass(frozen=True, slots=True)
class RecallPolicy:
    no_replay: Mapping[bytes, bool]
    issuers: Mapping[bytes, bytes]
    """CID -> whether the capsule's policy carries NO_REPLAY."""


def recall(
    store: Mapping[bytes, Capsule],
    cid: bytes,
    capability: Tlv,
    *,
    recipient_pk: bytes,
    revocations: RevocationRegistry,
    audience_proof: Sequence[tuple[bytes, bool]] | None = None,
    now_ns: int,
    policy: RecallPolicy,
    epsilon_budget: float,
    offset_ns: int = 0,
    span_ns: int = 0,
) -> RecallFrame:
    """V13 recall path: fetch by CID, check capability/types/DP budget/expiry, walk the lineage."""
    cap = SenderCapability.verify(capability)
    _check_audience(cap, recipient_pk, audience_proof)
    if not cap.rights & Rights.ALLOW_REPLAY:
        msg = "recall requires ALLOW_REPLAY consent"
        raise GateRefused(msg)
    if revocations.is_revoked(cap.capability_id, _ZERO, 0):
        msg = "capability revoked"
        raise GateRefused(msg)
    capsule = store.get(cid)
    if capsule is None:
        msg = "unknown CID"
        raise GateRefused(msg)
    h = capsule.header
    if cap.valid_until_ns < now_ns:
        msg = "capability expired"
        raise GateRefused(msg)
    if not set(bitmap_to_types(h.types_bitmap)) <= set(cap.types):
        msg = "capability does not cover the capsule types"
        raise GateRefused(msg)
    if not math.isfinite(epsilon_budget) or h.dp_eps_spent > min(
        epsilon_budget, cap.dp_epsilon_ceiling
    ):
        msg = "DP budget exceeded"
        raise GateRefused(msg)
    node: bytes | None = cid
    seen = set()
    while node is not None and node != bytes(32):
        if node in seen:
            msg = "lineage cycle"
            raise GateRefused(msg)
        seen.add(node)
        if policy.no_replay.get(node, True):
            msg = "NO_REPLAY is set in the lineage"
            raise GateRefused(msg)
        parent = store.get(node)
        if parent is None or parent.cid != node:
            msg = "incomplete or mismatched capsule lineage"
            raise GateRefused(msg)
        parent.verify_signature()
        if policy.issuers.get(node) != cap.issuer_pk:
            msg = "capability issuer is not authorized for this lineage"
            raise GateRefused(msg)
        node = parent.header.parent_cid
    return RecallFrame(cid, offset_ns, span_ns)
