# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Synthetic Typed-Hive episode with >= 5 members (WP-070 reference simulation).

Members are synthetic: each holds an independent AR(1) KNO/CTX state, an
EMO anchor-coordinate vector and an INT ballot. One member can be a machine;
it never authors EMO. The episode runs every lifecycle step with real objects:

- signed base Capabilities and Hive Grants;
- commitments and IDENTIFIED proofs;
- secure-aggregation rounds with distributed noise;
- the EMO DP histogram;
- Friedkin-Johnsen coupling;
- a preregistered emergence audit on held-out synthetic episodes;
- a FROST-signed Collective Intent;
- sealing.

Nothing here is evidence about humans. The data are synthetic by construction.
"""

from __future__ import annotations

import os
import uuid
from dataclasses import asdict, dataclass, field

import numpy as np
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from numpy.typing import NDArray

from esp.codec.tlv import Tlv
from esp.consent.capability import AudienceMode, Rights, SenderCapability
from esp.core.taoss_types import TaossType, types_to_bitmap
from esp.crypto.primitives import SigningKey
from esp.hive import dkg, frost
from esp.hive.audit import AuditReport, EmergencePrereg, Thresholds
from esp.hive.episode import (
    Episode,
    EpisodeConfig,
    MemberKind,
    PendingIntent,
    Proposal,
    TargetKind,
    contribution_commitment,
    frost_sign_intent,
)
from esp.hive.membership import identified_proof, member_key_binding
from esp.hive.tlv import (
    ExitPolicy,
    HiveContribution,
    HiveExit,
    HiveGrant,
    MembershipMode,
    Operator,
    PrivacyMode,
    Rule,
)
from esp.xcf.capsule import Capsule

F64 = NDArray[np.float64]
T = TaossType
TYPES = (T.KNO, T.INT, T.EMO, T.CTX)
OPERATORS = {
    T.KNO: Operator.COVARIANCE_INTERSECTION,
    T.INT: Operator.SOCIAL_CHOICE,
    T.EMO: Operator.EMO_DP_HISTOGRAM,
    T.CTX: Operator.PROVENANCE_UNION,
}
COUPLING = {T.KNO: 0.25, T.INT: 0.0, T.EMO: 0.0, T.CTX: 0.25}
BUDGET = {T.KNO: 3.0, T.INT: 0.5, T.EMO: 3.0, T.CTX: 3.0}
ANCHORS = ("joy", "trust", "fear", "surprise", "sadness", "disgust", "anger", "anticipation")
DIM = 4
NOW = 1_800_000_000 * 10**9
HOUR = 3600 * 10**9


def base_capability(
    master: SigningKey, audience: bytes, *, ceiling: float = 10.0
) -> tuple[SenderCapability, Tlv]:
    cap = SenderCapability(
        capability_id=uuid.uuid4(),
        types_allowed=0x3F,
        rights=Rights(0),
        max_segments=1000,
        dp_epsilon_ceiling=ceiling,
        valid_until_ns=NOW + 24 * HOUR,
        audience_mode=AudienceMode.RECIPIENT_PUBKEY,
        audience_value=audience,
        issuer_pk=master.public_bytes,
        nonce=os.urandom(16),
    )
    return cap, cap.sign(master)


def grant_for(
    cap: SenderCapability,
    episode_id: uuid.UUID,
    *,
    types: tuple[TaossType, ...] = TYPES,
    lambda_max: float = 0.5,
    membership: MembershipMode = MembershipMode.IDENTIFIED,
    root: bytes = bytes(32),
    min_group: int = 5,
) -> HiveGrant:
    ts = tuple(t for t in TaossType if t in types)
    return HiveGrant(
        capability_id=cap.capability_id,
        episode_id=episode_id,
        hive_types=types_to_bitmap(ts),
        emergence_types=T.KNO.bit,
        privacy_mode=PrivacyMode.SECAGG_DISTRIBUTED,
        membership_mode=membership,
        lambda_max=tuple(0.0 if t in (T.EMO, T.INT) else float(np.float32(lambda_max)) for t in ts),
        epsilon_member=tuple(BUDGET.get(t, 1.0) for t in ts),
        delta_member=float(np.float32(1e-5)),
        op_id=tuple(OPERATORS.get(t, Operator.SEN_COMPOSITION) for t in ts),
        min_group=min_group,
        quorum_min=3 if T.INT in ts else 0,
        rule_id=Rule.EXPONENTIAL_MECHANISM if T.INT in ts else Rule.NONE,
        exit_policy=ExitPolicy.NEXT_ROUND,
        membership_root=root,
        valid_until_ns=NOW + 12 * HOUR,
    )


def prereg(n_members: int, audit_episodes: int = 16) -> EmergencePrereg:
    return EmergencePrereg(
        primary_type=T.KNO,
        emergence_types=(T.KNO,),
        lag=1,
        task=f"synthetic-ar1-mean-forecast-n{n_members}",
        fit_episodes=("fit-0", "fit-1"),
        audit_episodes=tuple(f"audit-{i}" for i in range(audit_episodes)),
        n_boot=80,
        n_null=8,
        seed=7,
    )


def episode_config(
    episode_id: uuid.UUID, pre: EmergencePrereg, rounds: int = 3, **kw: object
) -> EpisodeConfig:
    fields: dict[str, object] = {
        "rounds": rounds,
        "episode_id": episode_id,
        "hive_types": types_to_bitmap(TYPES),
        "emergence_types": T.KNO.bit,
        "operators": OPERATORS,
        "coupling": COUPLING,
        "epsilon": BUDGET,
        "delta": float(np.float32(1e-5)),
        "privacy_mode": PrivacyMode.SECAGG_DISTRIBUTED,
        "membership_mode": MembershipMode.IDENTIFIED,
        "min_group": 5,
        "honest_min": 4,
        "clip": 1.0,
        "sigma": 12.0,
        "prereg_digest": pre.digest(),
        "thresholds": Thresholds(d_min=0.2, a_min=0.5, pi_max=0.5),
        "quorum_min": 3,
        "rule": Rule.EXPONENTIAL_MECHANISM,
        "exit_policy": ExitPolicy.NEXT_ROUND,
        "anchors": ANCHORS,
    }
    return EpisodeConfig(**(fields | kw))  # type: ignore[arg-type]


def ar_episode(rng: np.random.Generator, n: int, steps: int, a: float = 0.9) -> F64:
    """Independent AR(1) members, shape ``(steps, n, DIM)``."""
    x = np.zeros((steps, n, DIM))
    z = rng.normal(size=(n, DIM))
    for k in range(steps):
        z = a * z + np.sqrt(1 - a * a) * rng.normal(size=(n, DIM))
        x[k] = z
    return x


def member_mean(states: F64) -> F64:
    """``G_KNO`` of the simulation: the member mean (a supervenient macro variable)."""
    return np.asarray(states).mean(axis=0)


@dataclass
class SimMember:
    master: SigningKey
    key: SigningKey
    kind: MemberKind
    ref: bytes = b""


@dataclass
class SimulationResult:
    episode: Episode
    members: list[SimMember]
    report: AuditReport
    capsule: Capsule
    capsule_kind: str
    intent: PendingIntent
    cic_tlv: Tlv
    guardians: frost.GroupInfo
    releases: list[dict[str, object]] = field(default_factory=list)
    """The privacy ledger as plain records."""


def contribute(ep: Episode, m: SimMember, t: TaossType, x: F64, *, adds_noise: bool = True) -> None:
    opening = os.urandom(32)
    obj = HiveContribution(
        ep.config.episode_id,
        m.ref,
        ep.round_no,
        contribution_commitment(ep.config.episode_id, t, ep.round_no, x, opening),
        b"",
    )
    obj = HiveContribution(
        obj.episode_id,
        obj.member_ref,
        obj.mls_epoch,
        obj.contribution_commitment,
        identified_proof(m.key, obj),
    )
    ep.contribute(t, obj.encode(), x, opening, adds_noise=adds_noise)


def exit_tlv(ep: Episode, m: SimMember) -> Tlv:
    obj = HiveExit(ep.config.episode_id, m.ref, b"")
    return HiveExit(obj.episode_id, obj.member_ref, identified_proof(m.key, obj)).encode()


def build_episode(
    n: int = 6, *, machines: int = 1, rounds: int = 3, **config: object
) -> tuple[Episode, list[SimMember], EmergencePrereg, list[frost.KeyShare]]:
    """Discovery and Join for ``n`` synthetic members (the last ``machines`` are machines)."""
    episode_id = uuid.uuid4()
    pre = prereg(n)
    guardians, shares = dkg.run_local(5, 3, episode_id.bytes)  # no trusted dealer (GAP-017)
    ep = Episode(episode_config(episode_id, pre, rounds, **config), guardians=guardians)
    ep.open_join()
    members = []
    for i in range(n):
        master, key = SigningKey.generate(), SigningKey.generate()
        kind = MemberKind.MACHINE if i >= n - machines else MemberKind.HUMAN
        cap, cap_tlv = base_capability(master, key.public_bytes)
        grant_tlv = grant_for(cap, episode_id).sign(master)
        m = SimMember(master, key, kind)
        m.ref = ep.join_identified(
            cap_tlv,
            grant_tlv,
            key.public_bytes,
            member_key_binding(master, episode_id, key.public_bytes),
            kind=kind,
            now_ns=NOW,
        )
        members.append(m)
    return ep, members, pre, shares


def simulate(n: int = 6, *, machines: int = 1, rounds: int = 3, seed: int = 0) -> SimulationResult:
    rng = np.random.default_rng(seed)
    ep, members, pre, shares = build_episode(n, machines=machines, rounds=rounds)
    guardians = ep.guardians
    if guardians is None:  # pragma: no cover - build_episode always creates guardians
        raise RuntimeError("INT episode without guardians")
    ep.start_rounds()
    trajectory = ar_episode(rng, n, rounds)
    for k in range(rounds):
        if k:
            ep.next_round()
        for i, m in enumerate(members):
            contribute(ep, m, T.KNO, trajectory[k, i])
            contribute(ep, m, T.CTX, rng.normal(size=DIM) * 0.5)
            if m.kind is MemberKind.HUMAN:
                emo = np.zeros(len(ANCHORS))
                emo[rng.integers(0, 3)] = 1.0
                contribute(ep, m, T.EMO, emo)
        for t in (T.KNO, T.CTX, T.EMO):
            ep.release(t, rng)
        ep.couple(T.KNO)
        ep.couple(T.CTX)
    archive = X25519PrivateKey.generate()
    proposal = Proposal("allocate shared compute", TargetKind.RESOURCE, ("pool-a", "pool-b"))
    ballots = {m.ref: ("pool-a" if i % 3 else "pool-b") for i, m in enumerate(members)}
    pending = ep.propose(proposal, ballots, rng=rng, archive=archive.public_key(), now_ns=NOW)
    cic = frost_sign_intent(pending.intent, guardians, [shares[0], shares[2], shares[4]])
    ep.ratify(cic)
    audit_eps = {name: ar_episode(rng, n, 80) for name in pre.audit_episodes}
    report = ep.run_audit(pre, audit_eps, {T.KNO: member_mean})
    capsule, kind = ep.seal(archive.public_key(), now_ns=NOW)
    ep.publish()
    return SimulationResult(
        ep,
        members,
        report,
        capsule,
        kind,
        pending,
        cic,
        guardians,
        [asdict(r) for r in ep.releases],
    )
