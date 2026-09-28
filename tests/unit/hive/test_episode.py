# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Episode lifecycle with >= 5 synthetic members: consent, rounds, exit, CIC, audit, seal."""

import dataclasses
import json
import os
import uuid

import numpy as np
import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from esp.codec.tlv import Tlv
from esp.core.taoss_types import TaossType as T
from esp.crypto.primitives import CryptoError, SigningKey
from esp.hive import frost
from esp.hive.aggregation import AffectDistribution, RoundAborted, RoundRelease
from esp.hive.episode import (
    COLLECTIVE_CAPSULE,
    HIVE_CAPSULE,
    Episode,
    MemberKind,
    Phase,
    Proposal,
    TargetKind,
    contribution_commitment,
    frost_sign_intent,
    validate_collective_intent,
)
from esp.hive.membership import identified_proof, member_key_binding, member_ref_root
from esp.hive.simulation import (
    ANCHORS,
    NOW,
    SimMember,
    ar_episode,
    base_capability,
    build_episode,
    contribute,
    episode_config,
    exit_tlv,
    grant_for,
    member_mean,
    prereg,
    simulate,
)
from esp.hive.tlv import ExitPolicy, HiveContribution, HiveError, Operator, Rule
from esp.xcf.capsule import hpke_unwrap

pytestmark = pytest.mark.security


def test_full_synthetic_episode_earns_the_hive_label() -> None:
    r = simulate(n=6, machines=1, rounds=3, seed=0)
    assert len(r.members) >= 5
    assert r.report.label == "hive"
    assert not r.report.flags
    assert r.capsule_kind == HIVE_CAPSULE
    assert r.episode.phase is Phase.PUBLISH
    kno = next(t for t in r.report.types if t.type is T.KNO)
    assert kno.emergence is not None
    assert kno.emergence.lower_bound > 0
    assert kno.min_autonomy >= 0.75 - 1e-9  # 1 - lambda with lambda = 0.25
    emo = next(t for t in r.report.types if t.type is T.EMO)
    assert emo.emo_mixing == 0.0
    assert emo.min_autonomy == 1.0
    assert r.intent.ratified
    assert r.intent.decision in ("pool-a", "pool-b")
    # budgets: every type within its declared episode budget
    for t in (T.KNO, T.CTX, T.EMO, T.INT):
        assert r.episode.spent(t) <= r.episode.config.epsilon[t] + 1e-9


def test_sealed_record_is_readable_by_the_archive_only() -> None:
    ep, members, pre, _ = build_episode(5, machines=0, rounds=1)
    rng = np.random.default_rng(1)
    ep.start_rounds()
    traj = ar_episode(rng, 5, 1)
    for i, m in enumerate(members):
        contribute(ep, m, T.KNO, traj[0, i])
    ep.release(T.KNO, rng)
    archive = X25519PrivateKey.generate()
    iid = {name: rng.normal(size=(40, 5, 4)) for name in pre.audit_episodes}
    report = ep.run_audit(pre, iid, {T.KNO: member_mean})
    assert report.label == "collective"
    assert "no-emergence" in report.flags
    capsule, kind = ep.seal(archive.public_key(), now_ns=NOW)
    assert kind == COLLECTIVE_CAPSULE  # a failed audit never yields a Hive Capsule
    body = capsule.open_with_cek(hpke_unwrap(capsule, archive))
    record = json.loads(body.payload)
    assert record["kind"] == COLLECTIVE_CAPSULE
    assert record["audit"]["label"] == "collective"
    assert record["prereg_digest"] == pre.digest()


def test_min_group_and_honest_threshold() -> None:
    ep, members, _, _ = build_episode(5, machines=0)
    ep.exit(exit_tlv(ep, members[0]))  # JOIN phase: effective immediately
    with pytest.raises(RoundAborted, match="minimum group"):
        ep.start_rounds()
    ep2, members2, _, _ = build_episode(6, machines=0)
    ep2.start_rounds()
    rng = np.random.default_rng(2)
    for i, m in enumerate(members2):
        contribute(ep2, m, T.KNO, rng.normal(size=4), adds_noise=i < 3)  # only 3 honest, 4 needed
    with pytest.raises(RoundAborted, match="qualifying noise"):
        ep2.release(T.KNO, rng)


def test_contribution_rules() -> None:
    ep, members, _, _ = build_episode(6, machines=1)
    ep.start_rounds()
    m = members[0]
    x = np.ones(4) * 0.1
    opening = os.urandom(32)
    commit = contribution_commitment(ep.config.episode_id, T.KNO, 1, x, opening)
    c = HiveContribution(ep.config.episode_id, m.ref, 1, commit, b"")
    c = HiveContribution(c.episode_id, c.member_ref, 1, commit, identified_proof(m.key, c))
    with pytest.raises(HiveError, match="does not open"):
        ep.contribute(T.KNO, c.encode(), x + 0.5, opening)  # state differs from the commitment
    with pytest.raises(HiveError, match="does not open"):
        ep.contribute(T.CTX, c.encode(), x, opening)  # type is inside the commitment
    ep.contribute(T.KNO, c.encode(), x, opening)
    with pytest.raises(HiveError, match="one contribution"):
        ep.contribute(T.KNO, c.encode(), x, opening)
    forged = HiveContribution(
        c.episode_id, c.member_ref, 1, commit, identified_proof(members[1].key, c)
    )
    with pytest.raises(HiveError):
        ep.contribute(T.KNO, forged.encode(), x, opening)
    later = HiveContribution(c.episode_id, c.member_ref, 2, commit, b"")
    later = HiveContribution(c.episode_id, c.member_ref, 2, commit, identified_proof(m.key, later))
    with pytest.raises(HiveError, match="another round"):
        ep.contribute(T.KNO, later.encode(), x, opening)
    machine = members[-1]
    with pytest.raises(HiveError, match="machines never author EMO"):
        contribute(ep, machine, T.EMO, np.eye(len(ANCHORS))[0])


def test_join_consent_is_narrowing() -> None:
    episode_id = uuid.uuid4()
    pre = prereg(5)
    group, _ = frost.trusted_dealer_keygen(3, 2)
    ep = Episode(episode_config(episode_id, pre), guardians=group)
    ep.open_join()
    master, key = SigningKey.generate(), SigningKey.generate()
    cap, cap_tlv = base_capability(master, key.public_bytes)
    binding = member_key_binding(master, episode_id, key.public_bytes)

    def join(grant_tlv: Tlv) -> bytes:
        return ep.join_identified(
            cap_tlv, grant_tlv, key.public_bytes, binding, kind=MemberKind.HUMAN, now_ns=NOW
        )

    timid = grant_for(cap, episode_id, lambda_max=0.1)  # episode couples at 0.25
    with pytest.raises(HiveError, match="exceeds the member's lambda_max"):
        join(timid.sign(master))
    with pytest.raises(HiveError, match="another episode"):
        join(grant_for(cap, uuid.uuid4()).sign(master))
    kno_only = grant_for(cap, episode_id, types=(T.KNO,))
    ref = join(kno_only.sign(master))
    assert ep.members[ref].types == (T.KNO,)  # joins KNO without EMO/INT/CTX consent
    with pytest.raises(HiveError, match="duplicate member"):
        join(grant_for(cap, episode_id).sign(master))
    loose = grant_for(cap, episode_id, min_group=9)
    other_master = SigningKey.generate()
    ocap, ocap_tlv = base_capability(other_master, key.public_bytes)
    with pytest.raises(HiveError, match="minimum group"):
        ep.join_identified(
            ocap_tlv,
            grant_for(ocap, episode_id, min_group=9).sign(other_master),
            key.public_bytes,
            member_key_binding(other_master, episode_id, key.public_bytes),
            kind=MemberKind.HUMAN,
            now_ns=NOW,
        )
    assert loose.min_group == 9
    with pytest.raises(CryptoError):
        ep.join_identified(
            ocap_tlv,
            grant_for(ocap, episode_id).sign(other_master),
            key.public_bytes,
            b"\x00" * 64,
            kind=MemberKind.HUMAN,
            now_ns=NOW,
        )


def _ready_int_episode() -> tuple[Episode, list[SimMember], list[frost.KeyShare]]:
    ep, members, _, shares = build_episode(6, machines=0)
    ep.start_rounds()
    return ep, members, shares


def test_collective_intent_quorum_target_and_signature() -> None:
    ep, members, shares = _ready_int_episode()
    rng = np.random.default_rng(3)
    archive = X25519PrivateKey.generate().public_key()
    task = Proposal("rotate on-call duty", TargetKind.TASK, ("a", "b"))
    with pytest.raises(HiveError, match="natural person"):
        ep.propose(
            Proposal("sanction X", TargetKind.NATURAL_PERSON, ("a", "b")),
            {m.ref: "a" for m in members},
            rng=rng,
            archive=archive,
        )
    with pytest.raises(HiveError, match="quorum"):
        ep.propose(task, {m.ref: "a" for m in members[:2]}, rng=rng, archive=archive)
    with pytest.raises(HiveError, match="undeclared option"):
        ep.propose(task, {m.ref: "c" for m in members}, rng=rng, archive=archive)
    pending = ep.propose(task, {m.ref: "a" for m in members}, rng=rng, archive=archive)
    assert ep.guardians is not None
    with pytest.raises(frost.FrostError, match="MIN_PARTICIPANTS"):
        frost_sign_intent(pending.intent, ep.guardians, shares[:2])  # 2 of a 3-of-5 group
    rogue, rogue_shares = frost.trusted_dealer_keygen(5, 3)
    forged = frost_sign_intent(pending.intent, rogue, rogue_shares[:3])
    with pytest.raises(CryptoError):
        ep.ratify(forged)
    cic = frost_sign_intent(pending.intent, ep.guardians, shares[1:4])
    ratified = ep.ratify(cic)
    assert ratified.ratified
    # a third party validates independently, and a wrong voter set is caught
    validate_collective_intent(
        cic,
        group_public=ep.guardians.group_public,
        quorum_min=3,
        voters=pending.voters,
        proposal=task,
        capsule=pending.capsule,
    )
    with pytest.raises(HiveError, match=r"member_ref_root|contributor count"):
        validate_collective_intent(
            cic,
            group_public=ep.guardians.group_public,
            quorum_min=3,
            voters=pending.voters[:-1],
            proposal=task,
            capsule=pending.capsule,
        )


def test_exit_during_ratification_invalidates_pending_cic() -> None:
    ep, members, shares = _ready_int_episode()
    rng = np.random.default_rng(4)
    archive = X25519PrivateKey.generate().public_key()
    task = Proposal("pick a dataset", TargetKind.RESOURCE, ("x", "y"))
    pending = ep.propose(task, {m.ref: "x" for m in members}, rng=rng, archive=archive)
    assert ep.guardians is not None
    cic = frost_sign_intent(pending.intent, ep.guardians, shares[:3])
    ep.exit(exit_tlv(ep, members[2]))
    with pytest.raises(HiveError, match="exit during the ratification window"):
        ep.ratify(cic)
    assert ep.pending is None
    with pytest.raises(HiveError, match="without active INT consent"):
        ep.propose(task, {m.ref: "x" for m in members}, rng=rng, archive=archive)  # exiting member


def test_exit_policies() -> None:
    ep, members, _, _ = build_episode(7, machines=0)
    ep.start_rounds()
    ep.exit(exit_tlv(ep, members[0]))
    assert members[0].ref in ep.active  # NEXT_ROUND: still in this round
    ep.next_round()
    assert members[0].ref not in ep.active
    with pytest.raises(HiveError, match="exited"):
        contribute(ep, members[0], T.KNO, np.zeros(4))
    imm, imembers, _, _ = build_episode(6, machines=0, exit_policy=ExitPolicy.IMMEDIATE)
    imm.start_rounds()
    imm.exit(exit_tlv(imm, imembers[0]))
    assert imembers[0].ref not in imm.active


def test_emo_never_coupled_and_released_as_distribution() -> None:
    ep, members, _, _ = build_episode(6, machines=1)
    ep.start_rounds()
    rng = np.random.default_rng(5)
    for m in members[:-1]:
        contribute(ep, m, T.EMO, np.eye(len(ANCHORS))[rng.integers(0, 2)])
    out = ep.release(T.EMO, rng)
    assert isinstance(out, AffectDistribution)
    assert out.n_members == 5
    before = {r: v.copy() for r, v in ep.states[T.EMO].items()}
    ep.couple(T.EMO)  # coupling is 0: the members' EMO signals are untouched
    assert all(np.array_equal(before[r], ep.states[T.EMO][r]) for r in before)


def test_budget_exhaustion_and_rounds_limit() -> None:
    ep, members, _, _ = build_episode(5, machines=0, rounds=1)
    ep.start_rounds()
    rng = np.random.default_rng(6)
    for m in members:
        contribute(ep, m, T.KNO, rng.normal(size=4))
    rel = ep.release(T.KNO, rng)
    assert isinstance(rel, RoundRelease)
    assert rel.n == 5
    with pytest.raises(HiveError, match="declared rounds"):
        ep.next_round()
    for _ in range(2):
        ep.release(T.KNO, rng)
    with pytest.raises(HiveError, match="budget"):
        ep.release(T.KNO, rng)


def test_phase_machine() -> None:
    ep, members, _, _ = build_episode(5, machines=0)
    assert ep.phase is Phase.JOIN
    with pytest.raises(HiveError, match="illegal"):
        ep.open_join()
    with pytest.raises(HiveError, match="illegal"):
        ep.seal(X25519PrivateKey.generate().public_key())
    with pytest.raises(HiveError, match="not allowed"):
        ep.release(T.KNO, np.random.default_rng(0))
    ep.close()
    assert ep.phase is Phase.CLOSED
    with pytest.raises(HiveError, match="not allowed"):
        contribute(ep, members[0], T.KNO, np.zeros(4))


def test_int_is_off_without_int_types() -> None:
    episode_id = uuid.uuid4()
    pre = prereg(5)
    cfg = episode_config(
        episode_id,
        pre,
        hive_types=T.KNO.bit | T.CTX.bit,
        quorum_min=0,
        rule=Rule.NONE,
    )
    ep = Episode(cfg)
    ep.open_join()
    ep.phase = Phase.ROUNDS
    with pytest.raises(HiveError, match="INT is off"):
        ep.propose(
            Proposal("t", TargetKind.TASK, ("no", "yes")),
            {},
            rng=np.random.default_rng(0),
            archive=X25519PrivateKey.generate().public_key(),
        )


def test_config_rejects_emo_coupling_and_centroid() -> None:
    pre = prereg(5)
    with pytest.raises(HiveError, match="EMO mixing"):
        episode_config(uuid.uuid4(), pre, coupling={T.KNO: 0.2, T.CTX: 0.2, T.EMO: 0.1, T.INT: 0.0})
    with pytest.raises(HiveError, match="operator for EMO"):
        episode_config(
            uuid.uuid4(),
            pre,
            operators={
                T.KNO: Operator.COVARIANCE_INTERSECTION,
                T.INT: Operator.SOCIAL_CHOICE,
                T.EMO: Operator.INVERSE_VARIANCE,
                T.CTX: Operator.PROVENANCE_UNION,
            },
        )


def test_collective_intent_below_quorum_is_invalid_even_if_signed() -> None:
    ep, members, shares = _ready_int_episode()
    rng = np.random.default_rng(7)
    archive = X25519PrivateKey.generate().public_key()
    task = Proposal("choose a venue", TargetKind.RESOURCE, ("a", "b"))
    pending = ep.propose(task, {m.ref: "a" for m in members}, rng=rng, archive=archive)
    assert ep.guardians is not None
    voters = pending.voters[:2]  # a consistent, validly signed CIC over only 2 voters
    small = dataclasses.replace(
        pending.intent, n_contributors=len(voters), member_ref_root=member_ref_root(list(voters))
    )
    cic = frost_sign_intent(small, ep.guardians, shares[:3])
    with pytest.raises(HiveError, match="below quorum"):
        validate_collective_intent(
            cic,
            group_public=ep.guardians.group_public,
            quorum_min=3,
            voters=voters,
            proposal=task,
            capsule=pending.capsule,
        )
    with pytest.raises(HiveError):
        ep.ratify(cic)
