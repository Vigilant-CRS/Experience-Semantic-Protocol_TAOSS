# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""IDENTIFIED proofs, the ANONYMOUS registrar/test suite and its honest non-anonymity."""

import uuid

import pytest

from esp.core.taoss_types import TaossType as T
from esp.crypto.primitives import CryptoError, SigningKey
from esp.hive import frost
from esp.hive.episode import Episode, MemberKind, join_commitment
from esp.hive.membership import (
    Registrar,
    TransparentTestSuite,
    enroll_binding,
    identified_proof,
    identified_ref,
    member_ref_root,
    transparent_nullifier,
    verify_identified,
)
from esp.hive.simulation import NOW, base_capability, episode_config, grant_for, prereg
from esp.hive.tlv import HiveContribution, HiveError, HiveExit, MembershipMode, PrivacyMode

pytestmark = pytest.mark.security
EP = uuid.UUID("61616161-6161-4161-8161-616161616161")


def test_identified_proof_binds_member_and_fields() -> None:
    key = SigningKey.generate()
    ref = identified_ref(EP, key.public_bytes)
    c = HiveContribution(EP, ref, 1, b"\x01" * 32, b"")
    c = HiveContribution(EP, ref, 1, b"\x01" * 32, identified_proof(key, c))
    verify_identified(c, key.public_bytes)
    tampered = HiveContribution(EP, ref, 2, b"\x01" * 32, c.proof)  # other round
    with pytest.raises(CryptoError):
        verify_identified(tampered, key.public_bytes)
    other = SigningKey.generate()
    with pytest.raises(HiveError):
        verify_identified(c, other.public_bytes)
    # a contribution proof cannot be replayed as an exit proof (domain separation)
    x = HiveExit(EP, ref, c.proof)
    with pytest.raises((CryptoError, HiveError)):
        verify_identified(x, key.public_bytes)


def _anonymous_setup(n: int = 5):  # type: ignore[no-untyped-def]
    pre = prereg(n)
    cfg = episode_config(EP, pre, membership_mode=MembershipMode.ANONYMOUS)
    reg = Registrar(EP, cfg.require_all_types)
    people = []
    for _ in range(n):
        master, cred = SigningKey.generate(), SigningKey.generate()
        cap, cap_tlv = base_capability(master, b"\x01" * 32)
        reg.register(cap_tlv, cred.public_bytes, enroll_binding(master, EP, cred.public_bytes))
        people.append((master, cred, cap, cap_tlv))
    root = reg.close()
    for master, _, cap, cap_tlv in people:
        g = grant_for(cap, EP, membership=MembershipMode.ANONYMOUS, root=root)
        reg.authorize(cap_tlv, g.sign(master), now_ns=NOW)
    return cfg, reg, people


def _join(reg: Registrar, cred: SigningKey) -> HiveContribution:
    nf = transparent_nullifier(EP, cred.public_bytes)
    c = HiveContribution(EP, nf, 0, join_commitment(EP, nf), b"")
    proof = TransparentTestSuite.prove(
        cred, c, reg.index_of(cred.public_bytes), reg.authorized_leaves
    )
    return HiveContribution(EP, nf, 0, c.contribution_commitment, proof)


def test_anonymous_mode_refuses_transparent_suite_by_default() -> None:
    cfg, reg, _ = _anonymous_setup()
    with pytest.raises(HiveError, match="no anonymity"):
        Episode(cfg, suite=TransparentTestSuite(), membership_root=reg.authorized_root())


def test_anonymous_join_uniqueness_and_honest_label() -> None:
    cfg, reg, people = _anonymous_setup()
    group, _ = frost.trusted_dealer_keygen(3, 2)
    ep = Episode(
        cfg,
        guardians=group,
        suite=TransparentTestSuite(),
        membership_root=reg.authorized_root(),
        test_only_transparent=True,
    )
    assert ep.anonymity.startswith("NOT PROVIDED")
    ep.open_join()
    for _, cred, _, _ in people:
        ep.join_anonymous(_join(reg, cred).encode(), kind=MemberKind.HUMAN)
    with pytest.raises(HiveError, match="duplicate nullifier"):
        ep.join_anonymous(_join(reg, people[0][1]).encode(), kind=MemberKind.HUMAN)
    stranger = SigningKey.generate()
    nf = transparent_nullifier(EP, stranger.public_bytes)
    c = HiveContribution(EP, nf, 0, join_commitment(EP, nf), b"")
    fake = TransparentTestSuite.prove(stranger, c, 0, [*reg.authorized_leaves])
    with pytest.raises(HiveError, match="not enrolled"):
        ep.join_anonymous(
            HiveContribution(EP, nf, 0, c.contribution_commitment, fake).encode(),
            kind=MemberKind.HUMAN,
        )
    # the episode never saw a master key or a signed grant
    assert all(m.master_pk is None and m.member_pk is None for m in ep.members.values())


def test_nullifier_must_derive_from_credential() -> None:
    _, reg, people = _anonymous_setup()
    cred = people[0][1]
    good = _join(reg, cred)
    forged_nf = b"\x09" * 32
    c = HiveContribution(EP, forged_nf, 0, join_commitment(EP, forged_nf), b"")
    proof = TransparentTestSuite.prove(
        cred, c, reg.index_of(cred.public_bytes), reg.authorized_leaves
    )
    with pytest.raises(HiveError, match="nullifier"):
        TransparentTestSuite().verify(
            HiveContribution(EP, forged_nf, 0, c.contribution_commitment, proof),
            reg.authorized_root(),
        )
    TransparentTestSuite().verify(good, reg.authorized_root())
    # nullifiers are scope-bound: another episode gives another nullifier
    assert transparent_nullifier(uuid.uuid4(), cred.public_bytes) != good.member_ref


def test_registrar_rules() -> None:
    cfg, reg, people = _anonymous_setup(2)
    master, cred, cap, cap_tlv = people[0]
    with pytest.raises(HiveError, match="closed"):
        reg.register(cap_tlv, cred.public_bytes, enroll_binding(master, EP, cred.public_bytes))
    fresh = Registrar(EP, cfg.require_all_types)
    fresh.register(cap_tlv, cred.public_bytes, enroll_binding(master, EP, cred.public_bytes))
    with pytest.raises(HiveError, match="duplicate enrollment"):
        fresh.register(cap_tlv, b"\x07" * 32, enroll_binding(master, EP, b"\x07" * 32))
    with pytest.raises(CryptoError):
        fresh.register(
            base_capability(SigningKey.generate(), b"\x01" * 32)[1], b"\x08" * 32, b"\x00" * 64
        )
    root = fresh.close()
    partial = grant_for(
        cap, EP, types=(T.KNO, T.CTX), membership=MembershipMode.ANONYMOUS, root=root
    )
    with pytest.raises(HiveError, match="every episode type"):
        fresh.authorize(cap_tlv, partial.sign(master), now_ns=NOW)
    wrong_root = grant_for(cap, EP, membership=MembershipMode.ANONYMOUS, root=b"\x0a" * 32)
    with pytest.raises(HiveError, match="membership root"):
        fresh.authorize(cap_tlv, wrong_root.sign(master), now_ns=NOW)
    identified = grant_for(cap, EP)
    with pytest.raises(HiveError, match="ANONYMOUS grants only"):
        fresh.authorize(cap_tlv, identified.sign(master), now_ns=NOW)
    assert PrivacyMode.SECAGG_DISTRIBUTED == 0


def test_member_ref_root_is_order_independent_and_unique() -> None:
    refs = [bytes([i]) * 32 for i in range(5)]
    assert member_ref_root(refs) == member_ref_root(list(reversed(refs)))
    assert member_ref_root(refs) != member_ref_root(refs[:4])
    with pytest.raises(HiveError, match="duplicate"):
        member_ref_root([*refs, refs[0]])
