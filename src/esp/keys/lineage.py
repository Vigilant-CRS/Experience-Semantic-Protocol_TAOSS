# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Master-key lifecycle: rotation bindings (0x42), key revocation (0x41), lineage.

V13 section 9.6 governing rule:

    Rights may be granted only by the currently active master key. Rights may
    be reduced by the original grant issuer or by any non-compromised verified
    successor in that issuer's rotation lineage.

- ``TLV_ROTATION_BINDING``: ``sig_new`` is mandatory over
  ``m_rot = "esp/v1/rotation" || version || mode || old_pk || new_pk ||
  effective_ns || evidence_digest``; ``sig_old`` is mode dependent (all-zero
  when not required); external evidence must authenticate the same tuple.
- ``TLV_KEY_REVOKED``: ``SELF`` (signed by the revoked key, successor and
  digest all-zero) or ``SUCCESSOR_BOUND`` (signed by the successor, requires a
  verified rotation binding whose digest matches). An arbitrary fresh key can
  never revoke another identity.
"""

from __future__ import annotations

import struct
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from enum import Enum, IntEnum, unique
from typing import Final

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv
from esp.crypto.primitives import CryptoError, blake2b, ed25519_verify
from esp.crypto.signed import Signer, sign_tlv, verify_signed_tlv

ROTATION_BINDING_CODE: Final = 0x42
KEY_REVOKED_CODE: Final = 0x41
ZERO32: Final = bytes(32)
ZERO64: Final = bytes(64)
MAX_EVIDENCE: Final = 64 * 1024


@unique
class BindingMode(IntEnum):
    PRE_REGISTERED = 0
    HW_ATTESTED = 1
    WITNESS_QUORUM = 2
    PROFILE_DEFINED = 3


@unique
class RevocationReason(IntEnum):
    COMPROMISED = 0
    RETIRED = 1
    LOST = 2
    PROFILE_DEFINED = 3


@unique
class AuthMode(IntEnum):
    SELF = 0
    SUCCESSOR_BOUND = 1


class KeyState(Enum):
    ACTIVE = "active"
    ROTATED = "rotated"
    REVOKED = "revoked"


#: Evidence verifier: ``(mode, old_pk, new_pk, effective_ns, evidence) -> bool``.
EvidenceVerifier = Callable[[BindingMode, bytes, bytes, int, bytes], bool]


@dataclass(frozen=True, slots=True)
class RotationBinding:
    mode: BindingMode
    old_pk: bytes
    new_pk: bytes
    effective_ns: int
    evidence: bytes
    sig_old: bytes
    sig_new: bytes
    version: int = 1

    @property
    def evidence_digest(self) -> bytes:
        return blake2b(self.evidence)

    def core(self) -> bytes:
        return rotation_core(
            version=self.version,
            mode=self.mode,
            old_pk=self.old_pk,
            new_pk=self.new_pk,
            effective_ns=self.effective_ns,
            digest=self.evidence_digest,
        )

    def encode(self) -> Tlv:
        body = (
            struct.pack(">BB", self.version, self.mode)
            + self.old_pk
            + self.new_pk
            + struct.pack(">Q", self.effective_ns)
            + self.evidence_digest
            + struct.pack(">I", len(self.evidence))
            + self.evidence
            + self.sig_old
            + self.sig_new
        )
        return Tlv(ROTATION_BINDING_CODE, body)

    def digest(self) -> bytes:
        """Canonical digest referenced by ``rotation_binding_digest``."""
        return blake2b(self.encode().encode())

    @classmethod
    def decode(cls, tlv: Tlv) -> RotationBinding:
        v = tlv.value
        fixed = 2 + 32 + 32 + 8 + 32 + 4
        if tlv.code != ROTATION_BINDING_CODE or len(v) < fixed + 128:
            msg = "malformed rotation binding"
            raise WireError(msg)
        version, mode = struct.unpack_from(">BB", v, 0)
        (evidence_len,) = struct.unpack_from(">I", v, fixed - 4)
        if evidence_len > MAX_EVIDENCE or len(v) != fixed + evidence_len + 128:
            msg = "rotation evidence length overflow/truncation"
            raise WireError(msg)
        try:
            binding_mode = BindingMode(mode)
        except ValueError:
            msg = "unrecognized rotation binding mode"
            raise WireError(msg) from None
        evidence = v[fixed : fixed + evidence_len]
        out = cls(
            mode=binding_mode,
            old_pk=v[2:34],
            new_pk=v[34:66],
            effective_ns=struct.unpack_from(">Q", v, 66)[0],
            evidence=evidence,
            sig_old=v[fixed + evidence_len : fixed + evidence_len + 64],
            sig_new=v[fixed + evidence_len + 64 :],
            version=version,
        )
        if v[74:106] != out.evidence_digest:
            msg = "evidence digest mismatch"
            raise WireError(msg)
        return out


def rotation_core(
    *,
    version: int,
    mode: BindingMode,
    old_pk: bytes,
    new_pk: bytes,
    effective_ns: int,
    digest: bytes,
) -> bytes:
    return (
        b"esp/v1/rotation"
        + struct.pack(">BB", version, mode)
        + old_pk
        + new_pk
        + struct.pack(">Q", effective_ns)
        + digest
    )


def make_rotation(
    *,
    mode: BindingMode,
    old: Signer | None,
    old_pk: bytes,
    new: Signer,
    new_pk: bytes,
    effective_ns: int,
    evidence: bytes = b"",
) -> RotationBinding:
    """Create a binding; ``old`` co-signs when given, otherwise ``sig_old`` is all-zero."""
    core = rotation_core(
        version=1,
        mode=mode,
        old_pk=old_pk,
        new_pk=new_pk,
        effective_ns=effective_ns,
        digest=blake2b(evidence),
    )
    return RotationBinding(
        mode=mode,
        old_pk=old_pk,
        new_pk=new_pk,
        effective_ns=effective_ns,
        evidence=evidence,
        sig_old=old.sign(core) if old is not None else ZERO64,
        sig_new=new.sign(core),
    )


@dataclass(frozen=True, slots=True)
class KeyRevoked:
    auth_mode: AuthMode
    revoked_pk: bytes
    successor_pk: bytes
    revoked_after_ns: int
    reason: RevocationReason
    rotation_binding_digest: bytes
    version: int = 1

    def body(self) -> bytes:
        return (
            struct.pack(">BB", self.version, self.auth_mode)
            + self.revoked_pk
            + self.successor_pk
            + struct.pack(">QB", self.revoked_after_ns, self.reason)
            + self.rotation_binding_digest
        )

    def sign(self, signer: Signer) -> Tlv:
        return sign_tlv(KEY_REVOKED_CODE, self.body(), signer)

    @classmethod
    def decode(cls, tlv: Tlv) -> KeyRevoked:
        v = tlv.value
        if tlv.code != KEY_REVOKED_CODE or len(v) != 2 + 32 + 32 + 9 + 32 + 64:
            msg = "malformed key-revoked notice"
            raise WireError(msg)
        version, auth = struct.unpack_from(">BB", v, 0)
        after, reason = struct.unpack_from(">QB", v, 66)
        try:
            return cls(
                auth_mode=AuthMode(auth),
                revoked_pk=v[2:34],
                successor_pk=v[34:66],
                revoked_after_ns=after,
                reason=RevocationReason(reason),
                rotation_binding_digest=v[75:107],
                version=version,
            )
        except ValueError:
            msg = "unknown auth mode or reason"
            raise WireError(msg) from None


@dataclass(slots=True)
class KeyLineage:
    """Tracks key states and verified successor edges for one identity family."""

    requires_old_cosignature: Mapping[BindingMode, bool] = field(
        default_factory=lambda: {
            BindingMode.PRE_REGISTERED: False,
            BindingMode.HW_ATTESTED: False,
            BindingMode.WITNESS_QUORUM: False,
            BindingMode.PROFILE_DEFINED: True,
        }
    )
    evidence_verifier: EvidenceVerifier | None = None
    grandfather_logged_on_compromise: bool = False
    """V13 table: a profile MAY grandfather grants with trusted transparency
    inclusion strictly before the compromise checkpoint. Default: fail closed."""
    _state: dict[bytes, KeyState] = field(default_factory=dict)
    _compromised: set[bytes] = field(default_factory=set)
    _successor: dict[bytes, bytes] = field(default_factory=dict)
    _effective: dict[bytes, int] = field(default_factory=dict)
    _bindings: dict[bytes, RotationBinding] = field(default_factory=dict)
    unauthenticated_claims: list[KeyRevoked] = field(default_factory=list)

    def enroll(self, pk: bytes) -> None:
        if pk in self._state:
            msg = "key already enrolled"
            raise CryptoError(msg)
        self._state[pk] = KeyState.ACTIVE

    def state(self, pk: bytes) -> KeyState | None:
        return self._state.get(pk)

    def is_compromised(self, pk: bytes) -> bool:
        return pk in self._compromised

    # --- rotation -------------------------------------------------------------

    def apply_rotation(self, binding: RotationBinding) -> None:
        if self._state.get(binding.old_pk) is not KeyState.ACTIVE:
            msg = "only an active key can be rotated"
            raise CryptoError(msg)
        if binding.new_pk in self._state:
            msg = "successor key already known"
            raise CryptoError(msg)
        core = binding.core()
        ed25519_verify(binding.new_pk, core, binding.sig_new)  # proof of possession
        if self.requires_old_cosignature[binding.mode]:
            ed25519_verify(binding.old_pk, core, binding.sig_old)
        elif binding.sig_old != ZERO64:
            msg = "sig_old must be all-zero when the profile does not require it"
            raise CryptoError(msg)
        if binding.mode is not BindingMode.PROFILE_DEFINED:
            verifier = self.evidence_verifier
            ok = verifier is not None and verifier(
                binding.mode, binding.old_pk, binding.new_pk, binding.effective_ns, binding.evidence
            )
            if not ok:
                msg = "rotation evidence does not authenticate the rotation core"
                raise CryptoError(msg)
        self._state[binding.old_pk] = KeyState.ROTATED
        self._state[binding.new_pk] = KeyState.ACTIVE
        self._successor[binding.old_pk] = binding.new_pk
        self._effective[binding.old_pk] = binding.effective_ns
        self._bindings[binding.digest()] = binding

    # --- key revocation ------------------------------------------------------------

    def apply_key_revoked(self, tlv: Tlv) -> KeyRevoked:
        notice = KeyRevoked.decode(tlv)
        if notice.auth_mode is AuthMode.SELF:
            if notice.successor_pk != ZERO32 or notice.rotation_binding_digest != ZERO32:
                msg = "SELF revocation must have all-zero successor and digest"
                raise CryptoError(msg)
            verify_signed_tlv(tlv, notice.revoked_pk)
        else:
            binding = self._bindings.get(notice.rotation_binding_digest)
            valid_edge = (
                binding is not None
                and binding.old_pk == notice.revoked_pk
                and binding.new_pk == notice.successor_pk
                and notice.successor_pk not in self._compromised
            )
            if not valid_edge:
                # Logged only as an unauthenticated claim; no state change (V13 closure).
                self.unauthenticated_claims.append(notice)
                msg = "successor-bound revocation without a verified rotation binding"
                raise CryptoError(msg)
            verify_signed_tlv(tlv, notice.successor_pk)
        if notice.revoked_pk not in self._state:
            msg = "unknown key"
            raise CryptoError(msg)
        self._state[notice.revoked_pk] = KeyState.REVOKED
        if notice.reason is RevocationReason.COMPROMISED:
            self._compromised.add(notice.revoked_pk)
        return notice

    # --- authority -------------------------------------------------------------------

    def can_grant(self, issuer_pk: bytes) -> bool:
        """Rights-increasing grants need the currently active key."""
        return self._state.get(issuer_pk) is KeyState.ACTIVE and issuer_pk not in self._compromised

    def admit_grant(
        self, issuer_pk: bytes, *, previously_accepted: bool, logged_before_cutoff: bool
    ) -> bool:
        """May a presented grant signed by ``issuer_pk`` be honoured (V13 section 9.6)?

        - ACTIVE, non-compromised issuer: yes.
        - ROTATED issuer: only if the grant object was accepted before, or has a
          transparency-log inclusion proof from before the rotation effective time
          (``logged_before_cutoff``). A self-asserted old signature is not enough.
        - COMPROMISED issuer: fail closed until a verified successor re-issues;
          only if the profile enables ``grandfather_logged_on_compromise`` may a
          grant logged before the compromise checkpoint be honoured.
        """
        state = self._state.get(issuer_pk)
        if state is None:
            return False
        if issuer_pk in self._compromised:
            return self.grandfather_logged_on_compromise and logged_before_cutoff
        if state is KeyState.ACTIVE:
            return True
        return previously_accepted or logged_before_cutoff

    def can_reduce(self, issuer_pk: bytes, signer_pk: bytes) -> bool:
        """Issuer itself or a verified, non-compromised successor in its lineage."""
        if signer_pk in self._compromised:
            return False
        node: bytes | None = issuer_pk
        seen: set[bytes] = set()
        while node is not None and node not in seen:
            if node == signer_pk:
                return True
            seen.add(node)
            node = self._successor.get(node)
        return False


def successor_pre_registration(old_pk: bytes, new_pk: bytes) -> bytes:
    """Log entry that pre-registers ``new_pk`` as the successor of ``old_pk``."""
    return b"esp/v1/pre-registered-successor" + old_pk + new_pk
