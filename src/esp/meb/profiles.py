# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""``T_mach``, MEB domain profiles and machine-to-human defaults (V13 section 17).

Normative constraints implemented here:

- machine-authored packets exclude EMO:
  ``T_mach ⊆ T \\ {EMO} = {KNO, INT, CTX, SEN, TEM}`` (eq. tmach);
- every domain profile is a pinned custom type-set profile
  (:data:`esp.session.profiles.CUSTOM_PROFILES`) with EMO *mandatorily masked*,
  so the endpoints refuse an EMO bit or a missing ``EMO_MASKED`` before decoding;
- ``MEB-HANDOVER`` = {INT, CTX, TEM, SEN}: no KNO (not SF4);
- ``MEB-SURGICAL``: ``NO_REPLAY`` mandatory; capabilities with ``ALLOW_REPLAY``
  are refused;
- M2H (section 17.6): a machine may *offer* {KNO, CTX, TEM}; what is sent is the
  offer ∩ the receiver capability. Without a receiver capability the protocol
  default deny leaves at most {KNO, CTX}. Machine SEN needs an explicit user opt-in;
- the assistive-device EMO *relay* is human-to-human communication through a
  machine: it is never part of ``T_mach`` and needs ``MACHINE_RELAY`` scope with
  human-origin references at L2+ (:func:`check_assistive_relay`).
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from esp.consent.capability import ReceiverPolicy, Rights, SenderCapability
from esp.core.errors import ErrorCode, EspError
from esp.core.provenance import AffectScope
from esp.core.taoss_types import TaossType
from esp.frame.model import PROFILE_L2
from esp.semantics.affect import AffectiveDescriptor
from esp.session.profiles import CUSTOM_PROFILES, TypeSetProfile

K, I, E, C, S, T = (  # noqa: E741 - TAOSS abbreviations
    TaossType.KNO,
    TaossType.INT,
    TaossType.EMO,
    TaossType.CTX,
    TaossType.SEN,
    TaossType.TEM,
)

#: V13 eq. (tmach): machines never author EMO.
T_MACH: Final = frozenset({K, I, C, S, T})
#: M2H baseline offer (V13 section 17.6).
M2H_BASELINE: Final = frozenset({K, C, T})


class MebError(EspError):
    code = ErrorCode.CONSENT_DENIED


def check_machine_types(types: Iterable[TaossType]) -> frozenset[TaossType]:
    """Refuse any machine-authored type set outside ``T_mach`` (EMO above all)."""
    ts = frozenset(types)
    if E in ts:
        msg = "machines never author EMO (V13 eq. tmach); relay human EMO via MACHINE_RELAY"
        raise MebError(msg)
    if not ts <= T_MACH:  # pragma: no cover - TaossType has no other members today
        msg = "types outside T_mach"
        raise MebError(msg)
    return ts


@dataclass(frozen=True, slots=True)
class DomainProfile:
    """A V13 section 17.5 domain profile bound to its pinned type-set registry entry."""

    name: str
    registry: str
    """Pinned custom type-set profile (session descriptor ``registries``)."""
    purpose: str
    bundle_mode: bool = False
    no_replay: bool = False

    @property
    def type_set(self) -> TypeSetProfile:
        return CUSTOM_PROFILES[self.registry]

    @property
    def types(self) -> frozenset[TaossType]:
        return self.type_set.allowed

    def check_capability(self, cap: SenderCapability) -> None:
        """A machine sender capability must stay inside the profile (and ``T_mach``)."""
        granted = check_machine_types(cap.types)
        if not self.type_set.required <= granted:
            missing = sorted(t.name for t in self.type_set.required - granted)
            msg = f"{self.name}: capability does not cover required types {missing}"
            raise MebError(msg)
        if self.no_replay and cap.rights & Rights.ALLOW_REPLAY:
            msg = f"{self.name}: NO_REPLAY is mandatory; ALLOW_REPLAY must not be granted"
            raise MebError(msg)


VEHICLE_HANDOVER: Final = DomainProfile(
    "Vehicle-to-Driver Handover",
    "esp-typeset-meb-handover-v1",
    "INT trajectory, CTX traffic, TEM handover timing, SEN urgency/confidence; no KNO",
)
ROBOTIC_SKILL: Final = DomainProfile(
    "Robotic Skill Transfer",
    "esp-typeset-meb-robotic-v1",
    "INT motor goals, SEN proprioception/haptics, TEM rhythm, KNO task model",
)
SURGICAL: Final = DomainProfile(
    "Surgical Assistance",
    "esp-typeset-meb-surgical-v1",
    "INT procedural intent, SEN force/position, TEM phase, KNO anatomy/tool model",
    no_replay=True,
)
DRONE_SWARM: Final = DomainProfile(
    "Drone Swarm Coordination",
    "esp-typeset-meb-swarm-v1",
    "INT collective intent, CTX mission, TEM phase; KNO/SEN optional",
    bundle_mode=True,
)
ASSISTIVE: Final = DomainProfile(
    "Assistive Device",
    "esp-typeset-meb-assistive-v1",
    "CTX environment, SEN perceptual cues, INT user-intent estimate; EMO only as human relay",
)
DOMAIN_PROFILES: Final = MappingProxyType(
    {p.registry: p for p in (VEHICLE_HANDOVER, ROBOTIC_SKILL, SURGICAL, DRONE_SWARM, ASSISTIVE)}
)


def m2h_types(
    receiver: ReceiverPolicy | None,
    *,
    sen_opt_in: bool = False,
    offer: Iterable[TaossType] = M2H_BASELINE,
) -> frozenset[TaossType]:
    """Types a machine may send to a human (V13 section 17.6).

    ``offer`` ∩ receiver capability, where no capability means the protocol
    default deny ({KNO, CTX}). SEN only with ``sen_opt_in``; EMO never.
    """
    offered = check_machine_types(offer)
    if S in offered and not sen_opt_in:
        offered -= {S}
    policy = receiver if receiver is not None else ReceiverPolicy.default_deny()
    return offered & policy.accept_types


def check_assistive_relay(affect: AffectiveDescriptor, *, frame_profile: int) -> None:
    """A relayed human EMO statement: MACHINE_RELAY scope, human-origin refs, L2+ only."""
    if affect.affect_scope is not AffectScope.MACHINE_RELAY:
        msg = "an assistive device may only relay EMO with affect_scope=machine_relay"
        raise MebError(msg)
    if not affect.provenance.source_refs:
        msg = "a relayed EMO statement must reference its human-origin statement"
        raise MebError(msg)
    if frame_profile < PROFILE_L2:
        msg = "EMO relay needs L2+ (medical-grade) consent"
        raise MebError(msg)
