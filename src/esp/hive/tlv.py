# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Typed-Hive control TLVs 0x70-0x73 (V13 "Protocol Objects and Episode Lifecycle"; WP-070).

All integers are big-endian and all floats canonical IEEE-754 binary32.
Variable arrays follow the set bits of ``hive_types``, least-significant bit
first. Byte layouts (value part, after ``t u8 || length u32``):

``HIVE_GRANT`` (0x70), ``153 + 9·n`` bytes, where ``n = popcount(hive_types)``::

    capability_id[16] episode_id[16] hive_types u16 emergence_types u16 n_types u8
    privacy_mode u8 membership_mode u8 lambda_max f32[n] epsilon_member f32[n]
    delta_member f32 op_id u8[n] min_group u16 quorum_min u16 rule_id u8
    exit_policy u8 membership_root[32] valid_until_ns u64 sig[64]

``sig = Ed25519(sk_M, "esp/v1/hive-grant" || t || length || all previous fields)``
(ADR-0015 canonical signed TLV).

``HIVE_CONTRIBUTION`` (0x71), ``92 + proof_len`` bytes::

    episode_id[16] member_ref[32] mls_epoch u64 contribution_commitment[32]
    proof_len u32 proof[proof_len]

``HIVE_EXIT`` (0x72), ``52 + proof_len`` bytes::

    episode_id[16] member_ref[32] proof_len u32 proof[proof_len]

``COLLECTIVE_INTENT`` (0x73), 169 bytes::

    episode_id[16] capsule_cid[32] rule_id u8 epsilon_used f32 n_contributors u32
    member_ref_root[32] group_key_id[16] frost_sig[64]

``frost_sig`` is a FROST(Ed25519, SHA-512) signature over
``"esp/v1/collective-intent" || t || length || all previous fields``. It
verifies as a plain Ed25519 signature under the group key (ADR-0021).

Every parser rejects truncation, length overflow and trailing bytes. Proofs
are bounded by :data:`MAX_PROOF_LEN` (profile maximum).
"""

from __future__ import annotations

import hashlib
import math
import struct
import uuid
from dataclasses import dataclass
from enum import IntEnum, unique
from typing import Final

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv
from esp.consent.capability import SenderCapability
from esp.consent.revocation import RevocationRegistry
from esp.core.errors import ErrorCode, EspError
from esp.core.taoss_types import TaossType, bitmap_to_types
from esp.crypto.primitives import SIG_LEN
from esp.crypto.signed import DOMAINS, Signer, sign_tlv, verify_signed_tlv

HIVE_GRANT: Final = 0x70
HIVE_CONTRIBUTION: Final = 0x71
HIVE_EXIT: Final = 0x72
COLLECTIVE_INTENT: Final = 0x73

MAX_PROOF_LEN: Final = 16 * 1024
"""Profile maximum for proof fields (``esp-hive-reference-v1``)."""
MIN_GROUP_FLOOR: Final = 2
_ZERO_UUID: Final = uuid.UUID(int=0)


class HiveError(EspError):
    """A hive object or action violates the Typed-Hive rules."""

    code = ErrorCode.CONSENT_DENIED


@unique
class PrivacyMode(IntEnum):
    SECAGG_DISTRIBUTED = 0
    SECAGG_CENTRAL = 1
    LOCAL = 2
    PROFILE_DEFINED = 3


@unique
class MembershipMode(IntEnum):
    IDENTIFIED = 0
    ANONYMOUS = 1


@unique
class ExitPolicy(IntEnum):
    IMMEDIATE = 0
    NEXT_ROUND = 1


@unique
class Rule(IntEnum):
    """INT social-choice rules (registry ``esp-hive-rules-v1``)."""

    NONE = 0
    MAJORITY_BINARY = 1
    EXPONENTIAL_MECHANISM = 2


@unique
class Operator(IntEnum):
    """Aggregation operators ``G_t`` (registry ``esp-hive-operators-v1``)."""

    COVARIANCE_INTERSECTION = 1
    INVERSE_VARIANCE = 2
    """Only under declared independent evidence (V13 precision proposition)."""
    SOCIAL_CHOICE = 3
    EMO_DP_HISTOGRAM = 4
    PROVENANCE_UNION = 5
    SEN_COMPOSITION = 6
    TEM_PHASE_ORDER = 7


#: Which operators each type may declare. EMO has no centroid operator by construction:
#: the collective affect object is a DP distribution over anchor bins (V13 typed aggregation).
ALLOWED_OPERATORS: Final = {
    TaossType.KNO: frozenset({Operator.COVARIANCE_INTERSECTION, Operator.INVERSE_VARIANCE}),
    TaossType.INT: frozenset({Operator.SOCIAL_CHOICE}),
    TaossType.EMO: frozenset({Operator.EMO_DP_HISTOGRAM}),
    TaossType.CTX: frozenset(
        {
            Operator.PROVENANCE_UNION,
            Operator.COVARIANCE_INTERSECTION,
            Operator.INVERSE_VARIANCE,
        }
    ),
    TaossType.SEN: frozenset({Operator.SEN_COMPOSITION}),
    TaossType.TEM: frozenset({Operator.TEM_PHASE_ORDER}),
}


def _f32(name: str, v: float) -> None:
    if not math.isfinite(v) or struct.unpack(">f", struct.pack(">f", v))[0] != v:
        msg = f"{name} must be a finite binary32 value"
        raise WireError(msg)


def _types(bitmap: int) -> tuple[TaossType, ...]:
    try:
        return bitmap_to_types(bitmap)
    except ValueError as exc:
        raise WireError(str(exc)) from None


def _enum[E: IntEnum](cls: type[E], value: int, name: str) -> E:
    try:
        return cls(value)
    except ValueError:
        msg = f"unknown {name} {value}"
        raise WireError(msg) from None


# --- 0x70 HIVE_GRANT -----------------------------------------------------------------------------

_G_HEAD: Final = struct.Struct(">16s16sHHBBB")  # 39 bytes
_G_TAIL: Final = struct.Struct(">HHBB32sQ")  # 46 bytes


@dataclass(frozen=True, slots=True)
class HiveGrant:
    capability_id: uuid.UUID
    episode_id: uuid.UUID
    hive_types: int
    emergence_types: int
    privacy_mode: PrivacyMode
    membership_mode: MembershipMode
    lambda_max: tuple[float, ...]
    epsilon_member: tuple[float, ...]
    delta_member: float
    op_id: tuple[Operator, ...]
    min_group: int
    quorum_min: int
    rule_id: Rule
    exit_policy: ExitPolicy
    membership_root: bytes
    valid_until_ns: int

    def __post_init__(self) -> None:
        types = _types(self.hive_types)
        if not types:
            msg = "hive_types must be non-empty"
            raise WireError(msg)
        emergence = _types(self.emergence_types)
        if not emergence or self.emergence_types & ~self.hive_types:
            msg = "emergence_types must be a non-empty subset of hive_types"
            raise WireError(msg)
        self._check_per_type(types)
        self._check_scalars(TaossType.INT in types)

    def _check_per_type(self, types: tuple[TaossType, ...]) -> None:
        n = len(types)
        if not len(self.lambda_max) == len(self.epsilon_member) == len(self.op_id) == n:
            msg = "per-type arrays must have popcount(hive_types) entries"
            raise WireError(msg)
        for t, lam, eps, op in zip(
            types, self.lambda_max, self.epsilon_member, self.op_id, strict=True
        ):
            _f32("lambda_max", lam)
            _f32("epsilon_member", eps)
            if not 0.0 <= lam < 1.0:
                msg = "lambda_max entries must lie in [0, 1)"
                raise WireError(msg)
            if t is TaossType.EMO and lam != 0.0:
                msg = "EMO lambda_max must be 0: no EMO state mixing into human members (v1)"
                raise HiveError(msg)
            if eps < 0.0:
                msg = "epsilon_member must be non-negative"
                raise WireError(msg)
            if Operator(op) not in ALLOWED_OPERATORS[t]:
                msg = f"operator {Operator(op).name} is not allowed for {t.name}"
                raise HiveError(msg)

    def _check_scalars(self, has_int: bool) -> None:
        _f32("delta_member", self.delta_member)
        if not 0.0 <= self.delta_member < 1.0:
            msg = "delta_member must lie in [0, 1)"
            raise WireError(msg)
        if not MIN_GROUP_FLOOR <= self.min_group <= 0xFFFF:
            msg = f"min_group must be at least {MIN_GROUP_FLOOR}"
            raise WireError(msg)
        if has_int and (self.quorum_min < 2 or self.rule_id is Rule.NONE):
            msg = "an INT grant needs quorum_min >= 2 and a social-choice rule"
            raise WireError(msg)
        if not has_int and (self.quorum_min != 0 or self.rule_id is not Rule.NONE):
            msg = "quorum_min and rule_id must be zero without INT"
            raise WireError(msg)
        if self.quorum_min > 0xFFFF or not 0 <= self.valid_until_ns < 2**64:
            msg = "field out of range"
            raise WireError(msg)
        if len(self.membership_root) != 32:
            msg = "membership_root must be 32 bytes"
            raise WireError(msg)
        if self.membership_mode is MembershipMode.ANONYMOUS and self.membership_root == bytes(32):
            msg = "ANONYMOUS mode requires a credential membership_root"
            raise WireError(msg)
        if _ZERO_UUID in (self.capability_id, self.episode_id):
            msg = "capability_id and episode_id must be non-zero"
            raise WireError(msg)

    @property
    def types(self) -> tuple[TaossType, ...]:
        return _types(self.hive_types)

    def lambda_for(self, t: TaossType) -> float:
        return self.lambda_max[self.types.index(t)]

    def epsilon_for(self, t: TaossType) -> float:
        return self.epsilon_member[self.types.index(t)]

    def operator_for(self, t: TaossType) -> Operator:
        return self.op_id[self.types.index(t)]

    def body(self) -> bytes:
        n = len(self.types)
        out = _G_HEAD.pack(
            self.capability_id.bytes,
            self.episode_id.bytes,
            self.hive_types,
            self.emergence_types,
            n,
            int(self.privacy_mode),
            int(self.membership_mode),
        )
        out += struct.pack(f">{n}f", *self.lambda_max)
        out += struct.pack(f">{n}f", *self.epsilon_member)
        out += struct.pack(">f", self.delta_member)
        out += bytes(int(o) for o in self.op_id)
        return out + _G_TAIL.pack(
            self.min_group,
            self.quorum_min,
            int(self.rule_id),
            int(self.exit_policy),
            self.membership_root,
            self.valid_until_ns,
        )

    def sign(self, master: Signer) -> Tlv:
        return sign_tlv(HIVE_GRANT, self.body(), master)

    @classmethod
    def parse(cls, tlv: Tlv) -> HiveGrant:
        """Decode without verifying the signature (see :func:`verify_grant`)."""
        v = tlv.value
        if tlv.code != HIVE_GRANT or len(v) < _G_HEAD.size:
            msg = "malformed HIVE_GRANT"
            raise WireError(msg)
        cid, eid, hive, emerg, n, pmode, mmode = _G_HEAD.unpack_from(v, 0)
        if n != len(_types(hive)):
            msg = "n_types must equal popcount(hive_types)"
            raise WireError(msg)
        if len(v) != 153 + 9 * n:
            msg = "HIVE_GRANT length mismatch"
            raise WireError(msg)
        off = _G_HEAD.size
        lam = struct.unpack_from(f">{n}f", v, off)
        eps = struct.unpack_from(f">{n}f", v, off + 4 * n)
        (delta,) = struct.unpack_from(">f", v, off + 8 * n)
        ops = v[off + 8 * n + 4 : off + 9 * n + 4]
        off += 9 * n + 4
        min_group, quorum, rule, exit_p, root, until = _G_TAIL.unpack_from(v, off)
        return cls(
            capability_id=uuid.UUID(bytes=cid),
            episode_id=uuid.UUID(bytes=eid),
            hive_types=hive,
            emergence_types=emerg,
            privacy_mode=_enum(PrivacyMode, pmode, "privacy_mode"),
            membership_mode=_enum(MembershipMode, mmode, "membership_mode"),
            lambda_max=tuple(lam),
            epsilon_member=tuple(eps),
            delta_member=delta,
            op_id=tuple(_enum(Operator, o, "op_id") for o in ops),
            min_group=min_group,
            quorum_min=quorum,
            rule_id=_enum(Rule, rule, "rule_id"),
            exit_policy=_enum(ExitPolicy, exit_p, "exit_policy"),
            membership_root=root,
            valid_until_ns=until,
        )


def verify_grant(
    tlv: Tlv,
    base: SenderCapability,
    *,
    now_ns: int,
    revocations: RevocationRegistry | None = None,
) -> HiveGrant:
    """Parse, verify under the base capability's issuer and enforce *narrowing only*.

    The base ESP Capability stays authoritative (V13): the grant must reference
    it, be signed by the same master key, and be no broader in types, expiry
    or privacy budget. A widening grant is rejected, never clipped.
    """
    grant = HiveGrant.parse(tlv)
    verify_signed_tlv(tlv, base.issuer_pk)
    if grant.capability_id != base.capability_id:
        msg = "grant references another base capability"
        raise HiveError(msg)
    if grant.hive_types & ~base.types_allowed:
        msg = "grant widens the base capability types"
        raise HiveError(msg)
    if grant.valid_until_ns > base.valid_until_ns:
        msg = "grant outlives the base capability"
        raise HiveError(msg)
    if math.fsum(grant.epsilon_member) > base.dp_epsilon_ceiling:
        msg = "grant privacy budget exceeds the base dp_epsilon_ceiling"
        raise HiveError(msg)
    if now_ns > grant.valid_until_ns or now_ns > base.valid_until_ns:
        msg = "grant or base capability expired"
        raise HiveError(msg)
    if revocations is not None and revocations.is_revoked(base.capability_id, _ZERO_UUID, 0):
        msg = "base capability revoked"
        raise HiveError(msg)
    return grant


# --- 0x71 / 0x72 ---------------------------------------------------------------------------------

_C_HEAD: Final = struct.Struct(">16s32sQ32sI")  # 92 bytes
_X_HEAD: Final = struct.Struct(">16s32sI")  # 52 bytes


def _proof(proof: bytes) -> None:
    if len(proof) > MAX_PROOF_LEN:
        msg = "proof exceeds the profile maximum"
        raise WireError(msg)


@dataclass(frozen=True, slots=True)
class HiveContribution:
    episode_id: uuid.UUID
    member_ref: bytes
    mls_epoch: int
    contribution_commitment: bytes
    proof: bytes

    def __post_init__(self) -> None:
        if len(self.member_ref) != 32 or len(self.contribution_commitment) != 32:
            msg = "member_ref and contribution_commitment must be 32 bytes"
            raise WireError(msg)
        if not 0 <= self.mls_epoch < 2**64:
            msg = "mls_epoch out of range"
            raise WireError(msg)
        _proof(self.proof)

    def signed_fields(self) -> bytes:
        """Fields a proof authorizes (everything before ``proof_len``)."""
        return _C_HEAD.pack(
            self.episode_id.bytes,
            self.member_ref,
            self.mls_epoch,
            self.contribution_commitment,
            0,
        )[:-4]

    def encode(self) -> Tlv:
        return Tlv(
            HIVE_CONTRIBUTION,
            self.signed_fields() + struct.pack(">I", len(self.proof)) + self.proof,
        )

    @classmethod
    def decode(cls, tlv: Tlv) -> HiveContribution:
        v = tlv.value
        if tlv.code != HIVE_CONTRIBUTION or len(v) < _C_HEAD.size:
            msg = "malformed HIVE_CONTRIBUTION"
            raise WireError(msg)
        eid, ref, epoch, comm, n = _C_HEAD.unpack_from(v, 0)
        if n > MAX_PROOF_LEN or len(v) != _C_HEAD.size + n:
            msg = "HIVE_CONTRIBUTION proof length mismatch"
            raise WireError(msg)
        return cls(uuid.UUID(bytes=eid), ref, epoch, comm, v[_C_HEAD.size :])


@dataclass(frozen=True, slots=True)
class HiveExit:
    episode_id: uuid.UUID
    member_ref: bytes
    proof: bytes

    def __post_init__(self) -> None:
        if len(self.member_ref) != 32:
            msg = "member_ref must be 32 bytes"
            raise WireError(msg)
        _proof(self.proof)

    def signed_fields(self) -> bytes:
        return self.episode_id.bytes + self.member_ref

    def encode(self) -> Tlv:
        return Tlv(
            HIVE_EXIT, self.signed_fields() + struct.pack(">I", len(self.proof)) + self.proof
        )

    @classmethod
    def decode(cls, tlv: Tlv) -> HiveExit:
        v = tlv.value
        if tlv.code != HIVE_EXIT or len(v) < _X_HEAD.size:
            msg = "malformed HIVE_EXIT"
            raise WireError(msg)
        eid, ref, n = _X_HEAD.unpack_from(v, 0)
        if n > MAX_PROOF_LEN or len(v) != _X_HEAD.size + n:
            msg = "HIVE_EXIT proof length mismatch"
            raise WireError(msg)
        return cls(uuid.UUID(bytes=eid), ref, v[_X_HEAD.size :])


# --- 0x73 COLLECTIVE_INTENT ----------------------------------------------------------------------

_CIC: Final = struct.Struct(">16s32sBfI32s16s")  # 105 bytes before the signature
CIC_LEN: Final = _CIC.size + SIG_LEN


@dataclass(frozen=True, slots=True)
class CollectiveIntent:
    episode_id: uuid.UUID
    capsule_cid: bytes
    rule_id: Rule
    epsilon_used: float
    n_contributors: int
    member_ref_root: bytes
    group_key_id: bytes

    def __post_init__(self) -> None:
        if self.rule_id is Rule.NONE:
            msg = "a collective intent needs a declared social-choice rule"
            raise WireError(msg)
        _f32("epsilon_used", self.epsilon_used)
        if self.epsilon_used < 0.0 or not 0 <= self.n_contributors < 2**32:
            msg = "field out of range"
            raise WireError(msg)
        if len(self.capsule_cid) != 32 or len(self.member_ref_root) != 32:
            msg = "capsule_cid and member_ref_root must be 32 bytes"
            raise WireError(msg)
        if len(self.group_key_id) != 16:
            msg = "group_key_id must be 16 bytes"
            raise WireError(msg)

    def body(self) -> bytes:
        return _CIC.pack(
            self.episode_id.bytes,
            self.capsule_cid,
            int(self.rule_id),
            self.epsilon_used,
            self.n_contributors,
            self.member_ref_root,
            self.group_key_id,
        )

    def signing_message(self) -> bytes:
        """The exact bytes FROST signs: domain || t || length || body (ADR-0015 form)."""
        return (
            DOMAINS[COLLECTIVE_INTENT]
            + struct.pack(">BI", COLLECTIVE_INTENT, CIC_LEN)
            + self.body()
        )

    def encode(self, frost_sig: bytes) -> Tlv:
        if len(frost_sig) != SIG_LEN:
            msg = "frost_sig must be 64 bytes"
            raise WireError(msg)
        return Tlv(COLLECTIVE_INTENT, self.body() + frost_sig)

    @classmethod
    def decode(cls, tlv: Tlv) -> CollectiveIntent:
        if tlv.code != COLLECTIVE_INTENT or len(tlv.value) != CIC_LEN:
            msg = "malformed COLLECTIVE_INTENT"
            raise WireError(msg)
        eid, cid, rule, eps, n, root, gk = _CIC.unpack_from(tlv.value, 0)
        return cls(uuid.UUID(bytes=eid), cid, _enum(Rule, rule, "rule_id"), eps, n, root, gk)


def verify_collective_intent(tlv: Tlv, group_public: bytes) -> CollectiveIntent:
    """Decode and verify ``frost_sig`` as a plain Ed25519 signature under the group key."""
    cic = CollectiveIntent.decode(tlv)
    if hashlib.blake2b(b"esp/v1/hive-group-key" + group_public, digest_size=32).digest()[:16] != (
        cic.group_key_id
    ):
        msg = "group_key_id does not match the group key"
        raise HiveError(msg)
    verify_signed_tlv(tlv, group_public)
    return cic
