# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Experience Legacy policy objects (WP-071; V13 "Experience Legacy: Lifespan Decoupling").

V13 treats lifespan decoupling as a governance horizon, not a feature. A legacy
profile MUST:

- rest on an explicit **ex-ante policy**, signed by the originator while they
  can consent;
- declare the permitted **types**, **recipient classes**, **activation
  conditions**, **retention horizon**, **renderer rights**, and whether
  **machine-generated continuation** is allowed;
- keep provenance that separates recorded human state from later synthetic
  inference (:class:`LegacyOrigin`);
- be activated by an **executor or independent witness quorum**, never by
  unilateral platform discretion.

Posthumous synthesis of EMO, or claims about "what the person would feel",
MUST NOT follow from other types surviving. It needs its own explicit prior
consent (``posthumous_emo_synthesis``).

Time locks, successor keys and estate law are companion-profile research
questions (V13), so nothing here is a wire field. Class ``FUTURE``: policy
objects and validation only. The module makes no claim to preserve a person.
"""

from __future__ import annotations

import dataclasses
import struct
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum, IntFlag, unique
from typing import Final

from esp.core.taoss_types import TaossType, types_to_bitmap
from esp.crypto.primitives import CryptoError, SigningKey, blake2b, ed25519_verify

CLAIM_CLASS: Final = "FUTURE"
_POLICY_DOMAIN: Final = b"esp/legacy/v1/policy"
_ACTIVATION_DOMAIN: Final = b"esp/legacy/v1/activation"


class LegacyRefused(ValueError):  # noqa: N818 - a policy outcome, like GateRefused
    pass


@unique
class RecipientClass(IntEnum):
    NAMED_PERSON = 1
    FAMILY = 2
    EXECUTOR = 3
    RESEARCH_ARCHIVE = 4
    PUBLIC = 5


@unique
class ActivationCondition(IntEnum):
    DEATH_CERTIFIED = 1
    INCAPACITY_CERTIFIED = 2
    DATE_REACHED = 3


class RendererRight(IntFlag):
    TEXT = 1
    VISUALIZATION = 2
    AUDIO = 4
    IMMERSIVE = 8


@unique
class LegacyOrigin(IntEnum):
    """Provenance classes that a legacy renderer must keep apart (V13, L∞)."""

    RECORDED_HUMAN_STATE = 1
    LIVING_CONTRIBUTION = 2
    LATER_SYNTHETIC_INFERENCE = 3


@dataclass(frozen=True, slots=True)
class ActivationRule:
    condition: ActivationCondition
    not_before_ns: int = 0

    def __post_init__(self) -> None:
        if self.not_before_ns < 0:
            msg = "not_before_ns must be non-negative"
            raise LegacyRefused(msg)
        if self.condition is ActivationCondition.DATE_REACHED and self.not_before_ns == 0:
            msg = "DATE_REACHED needs a date"
            raise LegacyRefused(msg)


@dataclass(frozen=True, slots=True)
class Quorum:
    """Executors or independent witnesses; ``threshold`` of them must attest activation."""

    members: tuple[bytes, ...]
    threshold: int

    def __post_init__(self) -> None:
        if any(len(m) != 32 for m in self.members):
            msg = "quorum members are Ed25519 public keys"
            raise LegacyRefused(msg)
        if len(set(self.members)) != len(self.members):
            msg = "quorum members must be distinct"
            raise LegacyRefused(msg)
        if not 2 <= self.threshold <= len(self.members):
            msg = "activation needs a quorum of at least 2 (no unilateral activation)"
            raise LegacyRefused(msg)


@dataclass(frozen=True, slots=True)
class LegacyPolicy:
    policy_id: uuid.UUID
    originator_pk: bytes
    created_ns: int
    types: frozenset[TaossType]
    recipients: frozenset[RecipientClass]
    activation: tuple[ActivationRule, ...]
    retention_until_ns: int
    renderer_rights: RendererRight
    machine_continuation: bool
    posthumous_emo_synthesis: bool
    quorum: Quorum
    signature: bytes = b""

    def __post_init__(self) -> None:
        if len(self.originator_pk) != 32:
            msg = "originator key must be an Ed25519 public key"
            raise LegacyRefused(msg)
        if self.originator_pk in self.quorum.members:
            msg = "the originator cannot be a member of their own activation quorum"
            raise LegacyRefused(msg)
        if not self.types:
            msg = "a legacy policy must name its permitted types"
            raise LegacyRefused(msg)
        if not self.recipients:
            msg = "a legacy policy must name recipient classes"
            raise LegacyRefused(msg)
        if not self.activation:
            msg = "a legacy policy must declare activation conditions"
            raise LegacyRefused(msg)
        if len({r.condition for r in self.activation}) != len(self.activation):
            msg = "one rule per activation condition"
            raise LegacyRefused(msg)
        if self.retention_until_ns <= self.created_ns:
            msg = "retention horizon must lie after policy creation"
            raise LegacyRefused(msg)
        if not self.renderer_rights:
            msg = "a legacy policy must declare renderer rights"
            raise LegacyRefused(msg)
        if self.posthumous_emo_synthesis and not self.machine_continuation:
            msg = "posthumous EMO synthesis is machine continuation; allow both explicitly"
            raise LegacyRefused(msg)

    def body(self) -> bytes:
        """Canonical bytes covered by the originator signature."""
        out = _POLICY_DOMAIN + self.policy_id.bytes + self.originator_pk
        out += struct.pack(
            ">QBQBBB",
            self.created_ns,
            types_to_bitmap(self.types),
            self.retention_until_ns,
            int(self.renderer_rights),
            int(self.machine_continuation),
            int(self.posthumous_emo_synthesis),
        )
        recipients = sorted(self.recipients)
        out += bytes([len(recipients), *recipients])
        rules = sorted(self.activation, key=lambda r: r.condition)
        out += bytes([len(rules)])
        for r in rules:
            out += struct.pack(">BQ", r.condition, r.not_before_ns)
        out += struct.pack(">BB", self.quorum.threshold, len(self.quorum.members))
        return out + b"".join(sorted(self.quorum.members))

    def digest(self) -> bytes:
        return blake2b(self.body())

    def signed(self, originator: SigningKey) -> LegacyPolicy:
        if originator.public_bytes != self.originator_pk:
            msg = "only the originator can sign their legacy policy"
            raise LegacyRefused(msg)
        return dataclasses.replace(self, signature=originator.sign(self.body()))

    def verify(self) -> None:
        try:
            ed25519_verify(self.originator_pk, self.body(), self.signature)
        except (CryptoError, ValueError) as exc:
            msg = "legacy policy is not signed by the originator"
            raise LegacyRefused(msg) from exc


@dataclass(frozen=True, slots=True)
class Attestation:
    member_pk: bytes
    signature: bytes


def _activation_message(policy: LegacyPolicy, condition: ActivationCondition, at_ns: int) -> bytes:
    return _ACTIVATION_DOMAIN + policy.digest() + struct.pack(">BQ", condition, at_ns)


def attest_activation(
    policy: LegacyPolicy, condition: ActivationCondition, at_ns: int, member: SigningKey
) -> Attestation:
    return Attestation(
        member.public_bytes, member.sign(_activation_message(policy, condition, at_ns))
    )


@dataclass(frozen=True, slots=True)
class Activation:
    policy_digest: bytes
    condition: ActivationCondition
    at_ns: int
    attesters: frozenset[bytes]


def activate(
    policy: LegacyPolicy,
    condition: ActivationCondition,
    at_ns: int,
    attestations: Sequence[Attestation],
) -> Activation:
    """Activate a signed policy once a quorum of distinct members attests ``condition``."""
    policy.verify()
    rule = next((r for r in policy.activation if r.condition is condition), None)
    if rule is None:
        msg = f"{condition.name} is not an activation condition of this policy"
        raise LegacyRefused(msg)
    if at_ns < rule.not_before_ns or at_ns <= policy.created_ns:
        msg = "activation before the permitted time"
        raise LegacyRefused(msg)
    if at_ns >= policy.retention_until_ns:
        msg = "retention horizon has passed"
        raise LegacyRefused(msg)
    message = _activation_message(policy, condition, at_ns)
    valid: set[bytes] = set()
    for a in attestations:
        if a.member_pk not in policy.quorum.members:
            continue
        try:
            ed25519_verify(a.member_pk, message, a.signature)
        except (CryptoError, ValueError):
            continue
        valid.add(a.member_pk)
    if len(valid) < policy.quorum.threshold:
        msg = f"quorum not reached ({len(valid)}/{policy.quorum.threshold})"
        raise LegacyRefused(msg)
    return Activation(policy.digest(), condition, at_ns, frozenset(valid))


@dataclass(frozen=True, slots=True)
class UseRequest:
    recipient: RecipientClass
    types: frozenset[TaossType]
    renderer: RendererRight
    origin: LegacyOrigin
    now_ns: int
    emo_synthesis: bool = False
    """True for any synthesized EMO or statement about what the person would feel."""


def authorize_use(
    policy: LegacyPolicy, activation: Activation, request: UseRequest
) -> LegacyOrigin:
    """Check one use against the activated policy. Returns the provenance label to render."""
    policy.verify()
    if activation.policy_digest != policy.digest():
        msg = "activation belongs to another policy"
        raise LegacyRefused(msg)
    if not activation.at_ns <= request.now_ns < policy.retention_until_ns:
        msg = "outside the activated retention window"
        raise LegacyRefused(msg)
    if request.recipient not in policy.recipients:
        msg = f"recipient class {request.recipient.name} not permitted"
        raise LegacyRefused(msg)
    if not request.types or not request.types <= policy.types:
        msg = "requested types exceed the policy"
        raise LegacyRefused(msg)
    if request.renderer not in policy.renderer_rights or not request.renderer:
        msg = "renderer not permitted"
        raise LegacyRefused(msg)
    if request.origin is LegacyOrigin.LATER_SYNTHETIC_INFERENCE and not policy.machine_continuation:
        msg = "machine-generated continuation is not permitted"
        raise LegacyRefused(msg)
    synthesizes_emo = request.emo_synthesis or (
        TaossType.EMO in request.types and request.origin is LegacyOrigin.LATER_SYNTHETIC_INFERENCE
    )
    if synthesizes_emo and not policy.posthumous_emo_synthesis:
        msg = "posthumous EMO synthesis needs its own explicit prior consent"
        raise LegacyRefused(msg)
    return request.origin
