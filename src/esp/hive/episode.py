# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Typed-Hive episode lifecycle (V13: Discovery → Join → Rounds → Audit → Seal → Publish → Exit).

The base ESP Capability stays authoritative. A member participates only in
the types that both its Hive Grant and the episode declare, at no more
coupling, budget or looseness than it granted. Normative rules enforced here:

- **EMO mixing = 0** for human state mixing (config, grant and dynamics).
  Machines never author EMO.
- **Minimum group size.** No release and no rounds below ``min_group``.
- **Honest-noise threshold.** A round aborts below ``honest_min`` qualifying
  contributions.
- **Commitments.** A contribution is accepted only against its hiding
  commitment ``BLAKE2b-256("esp/v1/hive-contribution" || episode_id ||
  canonical(x) || r)``, where ``canonical(x) = type u8 || round u32 ||
  float32_be[d]``.
- **INT** is off by default. A Collective Intent needs the declared rule, the
  distinct-member quorum, a FROST group signature and a proposal that does not
  target a natural person. It is advisory: nothing actuates.
- **Exit precedes execution.** An exit during the ratification window
  invalidates the pending CIC. Exited members are excluded from the next
  round, or immediately when the policy says so.
- **Seal.** Only an episode whose audit passes may be sealed and labelled a
  Hive Capsule; otherwise the capsule is labelled a Collective Capsule.

Without an MLS group, ``mls_epoch`` carries the round number (reference mode).
With an MLS group bound (:class:`MlsEpochSource`, implemented by
:class:`esp.hive.mls.HiveGroup`), a contribution must carry the group's *current*
RFC 9420 epoch, stale or future epochs are refused, and every secure-aggregation
round is keyed by the MLS exporter round secret (ADR-0021). A join in ANONYMOUS mode is a
``HIVE_CONTRIBUTION`` at epoch 0 whose commitment is the join commitment.
"""

from __future__ import annotations

import hashlib
import json
import struct
import time
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Final, Protocol

import numpy as np
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from numpy.typing import NDArray

from esp.codec.tlv import Tlv
from esp.consent.capability import SenderCapability
from esp.core.taoss_types import TaossType, bitmap_to_types, types_to_bitmap
from esp.crypto.primitives import ed25519_verify
from esp.hive import frost
from esp.hive.aggregation import (
    AffectDistribution,
    MemberInput,
    RoundAborted,
    RoundRelease,
    emo_histogram,
    exponential_mechanism,
    majority_binary,
    secure_round,
)
from esp.hive.audit import (
    AuditReport,
    EmergencePrereg,
    Macro,
    Thresholds,
    TypeAudit,
    admissibility,
    emergence_test,
)
from esp.hive.dynamics import (
    autonomy,
    check_coupling,
    equilibrium_matrix,
    fj_step,
    normalized_diversity,
    social_power,
    uniform_w,
)
from esp.hive.membership import (
    MEMBER_KEY_BINDING,
    CredentialSuite,
    identified_ref,
    member_ref_root,
    verify_identified,
)
from esp.hive.tlv import (
    ALLOWED_OPERATORS,
    CollectiveIntent,
    ExitPolicy,
    HiveContribution,
    HiveError,
    HiveExit,
    HiveGrant,
    MembershipMode,
    Operator,
    PrivacyMode,
    Rule,
    verify_collective_intent,
    verify_grant,
)
from esp.xcf.capsule import Capsule, CapsuleSpec, EnvelopeAlg, PrivateBody, hpke_access, seal

F64 = NDArray[np.float64]
HIVE_CAPSULE: Final = "esp-hive-capsule-v1"
COLLECTIVE_CAPSULE: Final = "esp-collective-capsule-v1"
_ENCODER: Final = uuid.UUID("7a11e000-0000-4000-8000-000000000070")
_ANCHORS: Final = uuid.UUID("7a11e000-0000-4000-8000-000000000071")


class Phase(StrEnum):
    DISCOVERY = "discovery"
    JOIN = "join"
    ROUNDS = "rounds"
    AUDIT = "audit"
    SEAL = "seal"
    PUBLISH = "publish"
    CLOSED = "closed"


_NEXT: Final = {
    Phase.DISCOVERY: {Phase.JOIN},
    Phase.JOIN: {Phase.ROUNDS},
    Phase.ROUNDS: {Phase.AUDIT},
    Phase.AUDIT: {Phase.SEAL},
    Phase.SEAL: {Phase.PUBLISH},
    Phase.PUBLISH: set(),
}


class MemberKind(StrEnum):
    HUMAN = "human"
    MACHINE = "machine"


class TargetKind(StrEnum):
    TASK = "task"
    RESOURCE = "resource"
    POLICY = "policy"
    NATURAL_PERSON = "natural_person"


def contribution_commitment(
    episode_id: uuid.UUID, t: TaossType, round_no: int, x: F64, opening: bytes
) -> bytes:
    if len(opening) != 32:
        msg = "the commitment opening must be 32 random bytes"
        raise HiveError(msg)
    v = np.asarray(x, dtype=np.float64).ravel()
    canonical = struct.pack(">BI", int(t), round_no) + struct.pack(f">{v.size}f", *v)
    return hashlib.blake2b(
        b"esp/v1/hive-contribution" + episode_id.bytes + canonical + opening, digest_size=32
    ).digest()


def join_commitment(episode_id: uuid.UUID, member_ref: bytes) -> bytes:
    return hashlib.blake2b(
        b"esp/v1/hive-join" + episode_id.bytes + member_ref, digest_size=32
    ).digest()


@dataclass(frozen=True, slots=True)
class EpisodeConfig:
    """Fixed at Discovery (V13 lifecycle step 1)."""

    episode_id: uuid.UUID
    hive_types: int
    emergence_types: int
    operators: Mapping[TaossType, Operator]
    coupling: Mapping[TaossType, float]
    epsilon: Mapping[TaossType, float]
    """Per-type episode budget (all releases of the type together)."""
    delta: float
    privacy_mode: PrivacyMode
    membership_mode: MembershipMode
    min_group: int
    honest_min: int
    clip: float
    sigma: float
    prereg_digest: str
    thresholds: Thresholds = field(default_factory=Thresholds)
    quorum_min: int = 0
    rule: Rule = Rule.NONE
    exit_policy: ExitPolicy = ExitPolicy.NEXT_ROUND
    anchors: tuple[str, ...] = ()
    rounds: int = 1
    """Declared number of release rounds; EMO spends ``epsilon[EMO] / rounds`` per release."""

    def __post_init__(self) -> None:
        types = self.types
        if not types or self.emergence_types & ~self.hive_types or not self.emergence_types:
            msg = "emergence types must be a non-empty subset of the hive types"
            raise HiveError(msg)
        for t in types:
            if self.operators.get(t) not in ALLOWED_OPERATORS[t]:
                msg = f"missing or disallowed operator for {t.name}"
                raise HiveError(msg)
            lam = self.coupling.get(t, 0.0)
            if not 0.0 <= lam < 1.0:
                msg = "coupling must lie in [0, 1)"
                raise HiveError(msg)
            if t is TaossType.EMO and lam != 0.0:
                msg = "EMO mixing must be 0 (v1)"
                raise HiveError(msg)
            if self.epsilon.get(t, 0.0) < 0.0:
                msg = "epsilon must be non-negative"
                raise HiveError(msg)
        if not 1 <= self.honest_min <= self.min_group or self.min_group < 2:
            msg = "require 1 <= honest_min <= min_group and min_group >= 2"
            raise HiveError(msg)
        if (TaossType.INT in types) != (self.rule is not Rule.NONE) or (
            TaossType.INT in types and self.quorum_min < 2
        ):
            msg = "INT needs a declared rule and quorum_min >= 2 (and only INT may declare one)"
            raise HiveError(msg)
        if self.rounds < 1:
            msg = "at least one round"
            raise HiveError(msg)
        if TaossType.EMO in types and not self.anchors:
            msg = "EMO needs the anchor bins of its distribution"
            raise HiveError(msg)

    @property
    def types(self) -> tuple[TaossType, ...]:
        return bitmap_to_types(self.hive_types)

    def member_types(self, grant: HiveGrant) -> tuple[TaossType, ...]:
        """Check that ``grant`` authorizes this episode; return the member's participating types."""
        if grant.episode_id != self.episode_id:
            msg = "grant is for another episode"
            raise HiveError(msg)
        if (grant.privacy_mode, grant.membership_mode) != (self.privacy_mode, self.membership_mode):
            msg = "grant privacy or membership mode differs from the episode"
            raise HiveError(msg)
        types = tuple(t for t in self.types if t in grant.types)
        if not types:
            msg = "grant covers none of the episode types"
            raise HiveError(msg)
        for t in types:
            if self.coupling.get(t, 0.0) > grant.lambda_for(t):
                msg = f"episode coupling for {t.name} exceeds the member's lambda_max"
                raise HiveError(msg)
            if self.operators[t] is not grant.operator_for(t):
                msg = f"episode operator for {t.name} differs from the grant"
                raise HiveError(msg)
            if self.epsilon.get(t, 0.0) > grant.epsilon_for(t):
                msg = f"episode epsilon for {t.name} exceeds the member's budget"
                raise HiveError(msg)
            if t.bit & self.emergence_types and not t.bit & grant.emergence_types:
                msg = f"member did not consent to the emergence audit of {t.name}"
                raise HiveError(msg)
        if self.delta > grant.delta_member or self.min_group < grant.min_group:
            msg = "episode delta or minimum group is looser than the grant"
            raise HiveError(msg)
        if TaossType.INT in types and (
            self.quorum_min < grant.quorum_min or self.rule is not grant.rule_id
        ):
            msg = "episode INT quorum or rule differs from the grant"
            raise HiveError(msg)
        if (
            grant.exit_policy is ExitPolicy.IMMEDIATE
            and self.exit_policy is not ExitPolicy.IMMEDIATE
        ):
            msg = "member requires immediate exit"
            raise HiveError(msg)
        return types

    def require_all_types(self, grant: HiveGrant) -> None:
        """ANONYMOUS registrar policy: the grant must authorize every episode type."""
        if set(self.member_types(grant)) != set(self.types):
            msg = "ANONYMOUS enrollment requires consent to every episode type"
            raise HiveError(msg)


@dataclass(frozen=True, slots=True)
class Release:
    """One privacy-relevant release (the episode's privacy ledger)."""

    type: str
    round: int
    n: int
    epsilon: float


@dataclass
class Member:
    ref: bytes
    kind: MemberKind
    types: tuple[TaossType, ...]
    caps: dict[TaossType, float]
    member_pk: bytes | None = None
    master_pk: bytes | None = None


@dataclass(frozen=True, slots=True)
class Proposal:
    title: str
    target_kind: TargetKind
    options: tuple[str, ...]

    def canonical(self) -> bytes:
        return json.dumps(
            {
                "title": self.title,
                "target_kind": self.target_kind.value,
                "options": list(self.options),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()


@dataclass
class PendingIntent:
    intent: CollectiveIntent
    proposal: Proposal
    decision: str
    voters: tuple[bytes, ...]
    capsule: Capsule
    exit_epoch: int
    ratified: bool = False


class MlsEpochSource(Protocol):
    """An MLS group as seen by an episode: its epoch and its per-round exporter secret."""

    def epoch(self) -> int: ...

    def round_secret(self, episode_id: uuid.UUID, type_code: int, round_no: int) -> bytes: ...


@dataclass
class Episode:
    config: EpisodeConfig
    guardians: frost.GroupInfo | None = None
    """FROST group that signs Collective Intents (INT episodes)."""
    mls: MlsEpochSource | None = None
    """RFC 9420 group of the members; ``None`` is the reference mode (epoch = round)."""
    suite: CredentialSuite | None = None
    membership_root: bytes | None = None
    test_only_transparent: bool = False
    phase: Phase = Phase.DISCOVERY
    round_no: int = 0
    members: dict[bytes, Member] = field(default_factory=dict)
    exited: set[bytes] = field(default_factory=set)
    pending_exit: set[bytes] = field(default_factory=set)
    initial: dict[TaossType, dict[bytes, F64]] = field(default_factory=dict)
    states: dict[TaossType, dict[bytes, F64]] = field(default_factory=dict)
    submitted: dict[tuple[bytes, TaossType, int], MemberInput] = field(default_factory=dict)
    releases: list[Release] = field(default_factory=list)
    pending: PendingIntent | None = None
    exit_epoch: int = 0
    report: AuditReport | None = None
    _masters: set[bytes] = field(default_factory=set)

    def __post_init__(self) -> None:
        c = self.config
        if c.membership_mode is MembershipMode.ANONYMOUS:
            if self.suite is None or self.membership_root is None:
                msg = "ANONYMOUS mode needs a credential suite and the authorized membership root"
                raise HiveError(msg)
            if not self.suite.provides_anonymity and not self.test_only_transparent:
                msg = f"{self.suite.suite_id} provides no anonymity; refusing ANONYMOUS mode"
                raise HiveError(msg)
        if TaossType.INT in c.types and self.guardians is None:
            msg = "an INT episode needs a FROST guardian group"
            raise HiveError(msg)

    # --- lifecycle -------------------------------------------------------------------------------

    def _to(self, phase: Phase) -> None:
        if phase is Phase.CLOSED or phase in _NEXT.get(self.phase, set()):
            self.phase = phase
            return
        msg = f"illegal episode transition {self.phase} -> {phase}"
        raise HiveError(msg)

    def _require(self, *phases: Phase) -> None:
        if self.phase not in phases:
            msg = f"not allowed in phase {self.phase}"
            raise HiveError(msg)

    def open_join(self) -> None:
        self._to(Phase.JOIN)

    @property
    def active(self) -> list[bytes]:
        return sorted(r for r in self.members if r not in self.exited)

    @property
    def anonymity(self) -> str:
        if self.config.membership_mode is MembershipMode.IDENTIFIED:
            return "IDENTIFIED (verifier knows member identities)"
        if self.suite is not None and self.suite.provides_anonymity:
            return f"ANONYMOUS ({self.suite.suite_id})"
        return "NOT PROVIDED: ANONYMOUS mode on a transparent test suite"

    # --- join ------------------------------------------------------------------------------------

    def join_identified(
        self,
        base_tlv: Tlv,
        grant_tlv: Tlv,
        member_pk: bytes,
        key_binding: bytes,
        *,
        kind: MemberKind,
        now_ns: int,
    ) -> bytes:
        self._require(Phase.JOIN)
        if self.config.membership_mode is not MembershipMode.IDENTIFIED:
            msg = "ANONYMOUS episodes never receive the directly signed grant"
            raise HiveError(msg)
        base = SenderCapability.verify(base_tlv)
        grant = verify_grant(grant_tlv, base, now_ns=now_ns)
        types = self.config.member_types(grant)
        ed25519_verify(
            base.issuer_pk,
            MEMBER_KEY_BINDING + self.config.episode_id.bytes + member_pk,
            key_binding,
        )
        if base.issuer_pk in self._masters:
            msg = "duplicate member (one membership per authenticated master key)"
            raise HiveError(msg)
        if kind is MemberKind.MACHINE:
            types = tuple(t for t in types if t is not TaossType.EMO)
        ref = identified_ref(self.config.episode_id, member_pk)
        self._masters.add(base.issuer_pk)
        self.members[ref] = Member(
            ref, kind, types, {t: grant.lambda_for(t) for t in types}, member_pk, base.issuer_pk
        )
        return ref

    def join_anonymous(self, join_tlv: Tlv, *, kind: MemberKind) -> bytes:
        self._require(Phase.JOIN)
        if self.suite is None or self.membership_root is None:
            msg = "not an ANONYMOUS episode"
            raise HiveError(msg)
        obj = HiveContribution.decode(join_tlv)
        if obj.episode_id != self.config.episode_id or obj.mls_epoch != 0:
            msg = "join must be epoch 0 of this episode"
            raise HiveError(msg)
        if obj.contribution_commitment != join_commitment(obj.episode_id, obj.member_ref):
            msg = "bad join commitment"
            raise HiveError(msg)
        self.suite.verify(obj, self.membership_root)
        if obj.member_ref in self.members:
            msg = "duplicate nullifier for this episode scope"
            raise HiveError(msg)
        types = self.config.types
        if kind is MemberKind.MACHINE:
            types = tuple(t for t in types if t is not TaossType.EMO)
        caps = {t: self.config.coupling.get(t, 0.0) for t in types}  # registrar-enforced bound
        self.members[obj.member_ref] = Member(obj.member_ref, kind, types, caps)
        return obj.member_ref

    def _authorize(self, obj: HiveContribution | HiveExit) -> Member:
        if obj.episode_id != self.config.episode_id:
            msg = "object belongs to another episode"
            raise HiveError(msg)
        m = self.members.get(obj.member_ref)
        if m is None:
            msg = "unknown member reference"
            raise HiveError(msg)
        if m.member_pk is not None:
            verify_identified(obj, m.member_pk)
        else:
            if self.suite is None or self.membership_root is None:  # pragma: no cover - guarded
                raise HiveError("no credential suite")
            self.suite.verify(obj, self.membership_root)
        return m

    # --- rounds ----------------------------------------------------------------------------------

    @property
    def current_epoch(self) -> int:
        """The ``mls_epoch`` a contribution must carry now."""
        return self.round_no if self.mls is None else self.mls.epoch()

    def start_rounds(self) -> None:
        self._require(Phase.JOIN)
        if len(self.active) < self.config.min_group:
            msg = f"{len(self.active)} members, minimum group is {self.config.min_group}"
            raise RoundAborted(msg)
        self._to(Phase.ROUNDS)
        self.round_no = 1

    def next_round(self) -> None:
        self._require(Phase.ROUNDS)
        self.exited |= self.pending_exit
        self.pending_exit.clear()
        if self.round_no >= self.config.rounds:
            msg = "all declared rounds have run"
            raise HiveError(msg)
        self.round_no += 1
        if len(self.active) < self.config.min_group:
            msg = "group fell below the minimum size"
            raise RoundAborted(msg)

    def contribute(
        self,
        t: TaossType,
        tlv: Tlv,
        state: F64,
        opening: bytes,
        *,
        adds_noise: bool = True,
    ) -> None:
        self._require(Phase.ROUNDS)
        obj = HiveContribution.decode(tlv)
        m = self._authorize(obj)
        if obj.member_ref in self.exited:
            msg = "member has exited"
            raise HiveError(msg)
        if t is TaossType.EMO and m.kind is MemberKind.MACHINE:
            msg = "machines never author EMO"
            raise HiveError(msg)
        if t not in m.types:
            msg = f"member has no {t.name} consent in this episode"
            raise HiveError(msg)
        if obj.mls_epoch != self.current_epoch:
            msg = (
                "contribution is for another MLS epoch"
                if self.mls is not None
                else "contribution is for another round"
            )
            raise HiveError(msg)
        x = np.asarray(state, dtype=np.float64)
        if contribution_commitment(self.config.episode_id, t, self.round_no, x, opening) != (
            obj.contribution_commitment
        ):
            msg = "contribution does not open its commitment"
            raise HiveError(msg)
        key = (obj.member_ref, t, self.round_no)
        if key in self.submitted:
            msg = "one contribution per member, type and round"
            raise HiveError(msg)
        self.submitted[key] = MemberInput(0, x, adds_noise)
        self.initial.setdefault(t, {}).setdefault(obj.member_ref, x)
        self.states.setdefault(t, {})[obj.member_ref] = x

    def release(self, t: TaossType, rng: np.random.Generator) -> RoundRelease | AffectDistribution:
        """Release the round's collective object for ``t`` (DP, minimum group, honest threshold)."""
        self._require(Phase.ROUNDS)
        c = self.config
        refs = [r for r in self.active if (r, t, self.round_no) in self.submitted]
        inputs = [
            MemberInput(
                i,
                self.submitted[(r, t, self.round_no)].state,
                self.submitted[(r, t, self.round_no)].adds_noise,
            )
            for i, r in enumerate(refs)
        ]
        out: RoundRelease | AffectDistribution
        if c.operators[t] is Operator.EMO_DP_HISTOGRAM:
            out = emo_histogram(
                [i.state for i in inputs],
                c.anchors,
                epsilon=c.epsilon[t] / c.rounds,
                min_group=c.min_group,
                rng=rng,
            )
            eps = out.epsilon
        else:
            out = secure_round(
                inputs,
                clip_norm=c.clip,
                sigma=c.sigma,
                honest_min=c.honest_min,
                delta=c.delta,
                rng=rng,
                round_id=c.episode_id.bytes + struct.pack(">BI", int(t), self.round_no),
                min_group=c.min_group,
                epoch_secret=(
                    None
                    if self.mls is None
                    else self.mls.round_secret(c.episode_id, int(t), self.round_no)
                ),
            )
            eps = out.epsilon
        spent = self.spent(t) + eps
        if spent > c.epsilon[t] + 1e-9:
            msg = f"episode budget for {t.name} exhausted ({spent:.4f} > {c.epsilon[t]})"
            raise HiveError(msg)
        self.releases.append(Release(t.name, self.round_no, len(inputs), eps))
        return out

    def spent(self, t: TaossType) -> float:
        """Episode privacy spend of ``t`` (linear composition across releases, conservative)."""
        return sum(r.epsilon for r in self.releases if r.type == t.name)

    def _participants(self, t: TaossType) -> list[bytes]:
        return [r for r in self.active if r in self.states.get(t, {})]

    def couple(self, t: TaossType) -> dict[bytes, F64]:
        """One FJ step on the members' current states: the hive-derived signal each receives."""
        self._require(Phase.ROUNDS)
        refs = self._participants(t)
        n = len(refs)
        if n < self.config.min_group:
            msg = "too few members to couple"
            raise RoundAborted(msg)
        lam = [self.config.coupling.get(t, 0.0)] * n
        w = uniform_w(n)
        check_coupling(t, w, lam, [self.members[r].caps.get(t, 0.0) for r in refs])
        x = np.stack([self.states[t][r] for r in refs])
        x0 = np.stack([self.initial[t][r] for r in refs])
        new = fj_step(x, x0, w, lam)
        for r, v in zip(refs, new, strict=True):
            self.states[t][r] = v
        return dict(zip(refs, new, strict=True))

    # --- exit ------------------------------------------------------------------------------------

    def exit(self, tlv: Tlv) -> None:
        obj = HiveExit.decode(tlv)
        self._authorize(obj)
        if obj.member_ref in self.exited:
            return
        if self.config.exit_policy is ExitPolicy.IMMEDIATE or self.phase is not Phase.ROUNDS:
            self.exited.add(obj.member_ref)
        else:
            self.pending_exit.add(obj.member_ref)
        self.exit_epoch += 1  # invalidates any pending CIC (exit precedes execution)

    # --- INT: collective intent ------------------------------------------------------------------

    def propose(
        self,
        proposal: Proposal,
        ballots: Mapping[bytes, str],
        *,
        rng: np.random.Generator,
        archive: X25519PublicKey,
        now_ns: int | None = None,
    ) -> PendingIntent:
        self._require(Phase.ROUNDS, Phase.AUDIT)
        c = self.config
        if TaossType.INT not in c.types or self.guardians is None:
            msg = "INT is off: no collective intent in this episode"
            raise HiveError(msg)
        if proposal.target_kind is TargetKind.NATURAL_PERSON:
            msg = "a collective intent must not designate a natural person"
            raise HiveError(msg)
        voters = tuple(sorted(ballots))
        for r in voters:
            m = self.members.get(r)
            if (
                m is None
                or r in self.exited
                or r in self.pending_exit
                or TaossType.INT not in m.types
            ):
                msg = "ballot from a member without active INT consent"
                raise HiveError(msg)
            if ballots[r] not in proposal.options:
                msg = "ballot for an undeclared option"
                raise HiveError(msg)
        if len(voters) < c.quorum_min:
            msg = f"{len(voters)} distinct members, quorum is {c.quorum_min}"
            raise HiveError(msg)
        eps = 0.0
        if c.rule is Rule.MAJORITY_BINARY:
            if proposal.options != ("no", "yes"):
                msg = "binary majority needs options ('no', 'yes')"
                raise HiveError(msg)
            decision = "yes" if majority_binary([ballots[r] == "yes" for r in voters]) else "no"
        else:
            eps = c.epsilon[TaossType.INT] - self.spent(TaossType.INT)
            if eps <= 0.0:
                msg = "INT privacy budget exhausted"
                raise HiveError(msg)
            counts = {o: float(sum(1 for r in voters if ballots[r] == o)) for o in proposal.options}
            decision = exponential_mechanism(counts, epsilon=eps, sensitivity=1.0, rng=rng)
        record = json.dumps(
            {
                "episode_id": str(c.episode_id),
                "proposal": json.loads(proposal.canonical()),
                "decision": decision,
                "rule": c.rule.name,
                "advisory": True,
            },
            sort_keys=True,
        ).encode()
        capsule, _ = seal(
            CapsuleSpec(
                types_bitmap=TaossType.INT.bit,
                encoder_id=_ENCODER,
                anchor_set_id=_ANCHORS,
                created_ns=time.time_ns() if now_ns is None else now_ns,
                dp_eps_spent=float(np.float32(eps)),
            ),
            PrivateBody(policy_id=uuid.uuid4(), timeline_id=c.episode_id, payload=record),
            envelope_alg=EnvelopeAlg.DIRECT_HPKE,
            access_material=hpke_access(archive),
        )
        intent = CollectiveIntent(
            episode_id=c.episode_id,
            capsule_cid=capsule.cid,
            rule_id=c.rule,
            epsilon_used=float(np.float32(eps)),
            n_contributors=len(voters),
            member_ref_root=member_ref_root(voters),
            group_key_id=frost.group_key_id(self.guardians.group_public),
        )
        if eps > 0.0:
            self.releases.append(Release("INT", self.round_no, len(voters), eps))
        self.pending = PendingIntent(intent, proposal, decision, voters, capsule, self.exit_epoch)
        return self.pending

    def ratify(self, cic_tlv: Tlv) -> PendingIntent:
        """Accept a FROST-signed CIC for the pending proposal. Advisory: never actuates."""
        p = self.pending
        if p is None or self.guardians is None:
            msg = "no pending collective intent"
            raise HiveError(msg)
        if self.exit_epoch != p.exit_epoch:
            self.pending = None
            msg = "an exit during the ratification window invalidated the pending CIC; recompute"
            raise HiveError(msg)
        validate_collective_intent(
            cic_tlv,
            group_public=self.guardians.group_public,
            quorum_min=self.config.quorum_min,
            voters=p.voters,
            proposal=p.proposal,
            capsule=p.capsule,
        )
        if CollectiveIntent.decode(cic_tlv) != p.intent:
            msg = "signed CIC differs from the pending proposal"
            raise HiveError(msg)
        p.ratified = True
        return p

    # --- audit, seal, publish --------------------------------------------------------------------

    def run_audit(
        self,
        prereg: EmergencePrereg,
        audit_episodes: Mapping[str, F64],
        macros: Mapping[TaossType, Macro],
    ) -> AuditReport:
        self._to(Phase.AUDIT)
        c = self.config
        if prereg.digest() != c.prereg_digest:
            msg = "audit configuration differs from the preregistration fixed at Discovery"
            raise HiveError(msg)
        emergence = bitmap_to_types(c.emergence_types)
        if types_to_bitmap(prereg.emergence_types) != c.emergence_types:
            msg = "preregistered emergence types differ from the episode"
            raise HiveError(msg)
        audits = []
        eps_ok = {t: self.spent(t) <= c.epsilon[t] + 1e-9 for t in c.types}
        for t in c.types:
            em = (
                emergence_test(prereg, c.prereg_digest, t, audit_episodes, macros[t])
                if t in emergence
                else None
            )
            refs = [r for r in self.active if t in self.members[r].types]
            if len(refs) < 2:
                msg = f"too few {t.name} participants to audit"
                raise HiveError(msg)
            lam = [c.coupling.get(t, 0.0)] * len(refs)
            p = equilibrium_matrix(uniform_w(len(refs)), lam)
            a_min, pi_max = float(autonomy(p).min()), float(social_power(p).max())
            with_state = self._participants(t)
            nd = None
            if len(with_state) >= 2:
                x0 = np.stack([self.initial[t][r] for r in with_state])
                xk = np.stack([self.states[t][r] for r in with_state])
                nd = normalized_diversity(x0, xk)
            audits.append(
                TypeAudit(
                    t,
                    em,
                    nd,
                    a_min,
                    pi_max,
                    eps_ok[t],
                    c.coupling.get(TaossType.EMO, 0.0) if t is TaossType.EMO else 0.0,
                )
            )
        self.report = admissibility(audits, emergence, c.thresholds, self.anonymity)
        return self.report

    def seal(self, archive: X25519PublicKey, *, now_ns: int | None = None) -> tuple[Capsule, str]:
        """Seal the episode record as XCF. The Hive label requires a passing audit."""
        self._to(Phase.SEAL)
        if self.report is None:  # pragma: no cover - guarded by the transition order
            raise HiveError("audit first")
        kind = HIVE_CAPSULE if self.report.label == "hive" else COLLECTIVE_CAPSULE
        record = {
            "kind": kind,
            "episode_id": str(self.config.episode_id),
            "prereg_digest": self.config.prereg_digest,
            "operators": {t.name: op.name for t, op in self.config.operators.items()},
            "coupling": {t.name: v for t, v in self.config.coupling.items()},
            "privacy": {
                "mode": self.config.privacy_mode.name,
                "releases": [asdict(r) for r in self.releases],
            },
            "audit": self.report.as_dict(),
            "cic": None
            if self.pending is None or not self.pending.ratified
            else self.pending.intent.capsule_cid.hex(),
        }
        spent = sum(r.epsilon for r in self.releases)
        capsule, _ = seal(
            CapsuleSpec(
                types_bitmap=self.config.hive_types,
                encoder_id=_ENCODER,
                anchor_set_id=_ANCHORS,
                created_ns=time.time_ns() if now_ns is None else now_ns,
                packets_count=max(1, len(self.releases)),
                dp_eps_spent=float(np.float32(spent)),
                dp_delta=float(np.float32(self.config.delta)),
            ),
            PrivateBody(
                policy_id=uuid.uuid4(),
                timeline_id=self.config.episode_id,
                payload=json.dumps(record, sort_keys=True).encode(),
            ),
            envelope_alg=EnvelopeAlg.DIRECT_HPKE,
            access_material=hpke_access(archive),
        )
        return capsule, kind

    def publish(self) -> None:
        self._to(Phase.PUBLISH)

    def close(self) -> None:
        self._to(Phase.CLOSED)


def validate_collective_intent(
    tlv: Tlv,
    *,
    group_public: bytes,
    quorum_min: int,
    voters: Sequence[bytes],
    proposal: Proposal,
    capsule: Capsule,
) -> CollectiveIntent:
    """Third-party CIC validation: FROST signature (plain Ed25519), quorum, refs, target.

    Also checks that ``capsule_cid`` is the CID of the (signed) decision capsule.
    """
    cic = verify_collective_intent(tlv, group_public)
    if cic.n_contributors < quorum_min or cic.n_contributors != len(voters):
        msg = "collective intent below quorum or with a wrong contributor count"
        raise HiveError(msg)
    if cic.member_ref_root != member_ref_root(list(voters)):
        msg = "member_ref_root does not commit to the accepted members"
        raise HiveError(msg)
    if proposal.target_kind is TargetKind.NATURAL_PERSON:
        msg = "a collective intent must not designate a natural person"
        raise HiveError(msg)
    capsule.verify_signature()
    if capsule.cid != cic.capsule_cid:
        msg = "capsule_cid does not match the decision capsule"
        raise HiveError(msg)
    return cic


def frost_sign_intent(
    intent: CollectiveIntent,
    group: frost.GroupInfo,
    signers: Sequence[frost.KeyShare],
) -> Tlv:
    """Coordinator: run both FROST rounds with ``signers`` and return the signed 0x73 TLV."""
    msg = intent.signing_message()
    signers = sorted(signers, key=lambda s: s.identifier)
    rounds = [frost.commit(s) for s in signers]
    comms = [c for _, c in rounds]
    shares = {
        s.identifier: frost.sign(s, n, msg, comms)
        for s, (n, _) in zip(signers, rounds, strict=True)
    }
    return intent.encode(frost.aggregate(group, comms, msg, shares))
