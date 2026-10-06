# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GAP-017: anonymous Hive membership with blind BBS credentials and per-episode pseudonyms."""

import os
import subprocess
import uuid
from pathlib import Path

import pytest

from esp.hive import frost
from esp.hive.credentials import (
    SUITE_ID,
    AnonymousCredential,
    BbsCredentialSuite,
    CredentialError,
    CredentialTool,
    Issuer,
    issuer_root,
)
from esp.hive.episode import Episode, MemberKind, join_commitment
from esp.hive.mls import cargo
from esp.hive.simulation import episode_config, prereg
from esp.hive.tlv import HiveContribution, HiveError, HiveExit, MembershipMode

pytestmark = [pytest.mark.integration, pytest.mark.security]
ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "rust" / "esp-rs"
CARGO = cargo()

if CARGO is None:  # pragma: no cover
    pytest.skip("Rust toolchain not available", allow_module_level=True)

EP = uuid.UUID("62626262-6262-4262-8262-626262626262")
CLASS = "panel-a"


@pytest.fixture(scope="module")
def tool() -> CredentialTool:
    assert CARGO is not None
    subprocess.run([CARGO, "build", "--release", "--quiet"], cwd=CRATE, check=True, timeout=1800)
    target = Path(os.environ.get("CARGO_TARGET_DIR", CRATE / "target"))
    return CredentialTool(target / "release" / "esp-rs")


@pytest.fixture(scope="module")
def issuer(tool: CredentialTool) -> Issuer:
    return Issuer.create(CLASS, tool)


@pytest.fixture(scope="module")
def members(issuer: Issuer, tool: CredentialTool) -> list[AnonymousCredential]:
    return [AnonymousCredential.obtain(issuer, tool) for _ in range(5)]


def join(cred: AnonymousCredential, episode_id: uuid.UUID = EP) -> HiveContribution:
    ref = cred.member_ref(episode_id)
    bare = HiveContribution(episode_id, ref, 0, join_commitment(episode_id, ref), b"")
    return HiveContribution(episode_id, ref, 0, bare.contribution_commitment, cred.authorize(bare))


def episode(issuer: Issuer, tool: CredentialTool, episode_id: uuid.UUID = EP) -> Episode:
    cfg = episode_config(episode_id, prereg(5), membership_mode=MembershipMode.ANONYMOUS)
    group, _ = frost.trusted_dealer_keygen(3, 2)
    ep = Episode(
        cfg,
        guardians=group,
        suite=BbsCredentialSuite(issuer.pk, CLASS, tool),
        membership_root=issuer.root,
    )
    ep.open_join()
    return ep


def test_suite_provides_anonymity_and_needs_no_test_flag(
    issuer: Issuer, tool: CredentialTool
) -> None:
    ep = episode(issuer, tool)
    assert ep.suite is not None
    assert ep.suite.suite_id == SUITE_ID
    assert ep.suite.provides_anonymity
    assert not ep.anonymity.startswith("NOT PROVIDED")


def test_five_members_join_anonymously_and_contribute(
    issuer: Issuer, tool: CredentialTool, members: list[AnonymousCredential]
) -> None:
    ep = episode(issuer, tool)
    refs = [ep.join_anonymous(join(c).encode(), kind=MemberKind.HUMAN) for c in members]
    assert len(set(refs)) == 5
    # the episode never sees a key, signature or identity of the member
    assert all(m.master_pk is None and m.member_pk is None for m in ep.members.values())
    # a later contribution and an exit are authorized by fresh proofs under the same pseudonym
    c = members[0]
    ref = c.member_ref(EP)
    bare = HiveContribution(EP, ref, 1, b"\x11" * 32, b"")
    contribution = HiveContribution(EP, ref, 1, bare.contribution_commitment, c.authorize(bare))
    assert ep._authorize(contribution).ref == ref
    bare_exit = HiveExit(EP, ref, b"")
    assert ep._authorize(HiveExit(EP, ref, c.authorize(bare_exit))).ref == ref


def test_same_credential_cannot_join_twice(
    issuer: Issuer, tool: CredentialTool, members: list[AnonymousCredential]
) -> None:
    ep = episode(issuer, tool)
    ep.join_anonymous(join(members[1]).encode(), kind=MemberKind.HUMAN)
    with pytest.raises(HiveError, match="duplicate nullifier"):
        ep.join_anonymous(join(members[1]).encode(), kind=MemberKind.HUMAN)


def test_pseudonyms_are_stable_per_episode_and_unlinkable_across(
    members: list[AnonymousCredential],
) -> None:
    other = uuid.uuid4()
    c = members[2]
    assert c.pseudonym(EP) == c.pseudonym(EP)
    assert c.pseudonym(EP) != c.pseudonym(other)
    refs_a = {m.member_ref(EP) for m in members}
    refs_b = {m.member_ref(other) for m in members}
    assert not refs_a & refs_b  # nothing to join two episodes' member sets on


def test_tampered_or_replayed_proofs_are_refused(
    issuer: Issuer, tool: CredentialTool, members: list[AnonymousCredential]
) -> None:
    suite = BbsCredentialSuite(issuer.pk, CLASS, tool)
    good = join(members[3])
    suite.verify(good, issuer.root)
    flipped = bytearray(good.proof)
    flipped[-10] ^= 1
    with pytest.raises(CredentialError):
        suite.verify(
            HiveContribution(EP, good.member_ref, 0, good.contribution_commitment, bytes(flipped)),
            issuer.root,
        )
    # the join proof does not authorize a different object (presentation header binding)
    with pytest.raises(CredentialError):
        suite.verify(
            HiveContribution(EP, good.member_ref, 7, b"\x22" * 32, good.proof), issuer.root
        )
    # nor another episode (context binding)
    other = uuid.uuid4()
    with pytest.raises(CredentialError):
        suite.verify(
            HiveContribution(other, good.member_ref, 0, good.contribution_commitment, good.proof),
            issuer.root,
        )
    # a pseudonym swapped in from another member does not match the member_ref
    alien = join(members[4])
    with pytest.raises(CredentialError, match="member_ref"):
        suite.verify(
            HiveContribution(
                EP,
                good.member_ref,
                0,
                good.contribution_commitment,
                alien.proof[:48] + good.proof[48:],
            ),
            issuer.root,
        )


def test_wrong_issuer_or_class_is_refused(
    issuer: Issuer, tool: CredentialTool, members: list[AnonymousCredential]
) -> None:
    rogue = Issuer.create(CLASS, tool)
    stranger = AnonymousCredential.obtain(rogue, tool)
    ep = episode(issuer, tool)
    with pytest.raises(CredentialError):
        ep.join_anonymous(join(stranger).encode(), kind=MemberKind.HUMAN)
    other_class = Issuer("panel-b", issuer.sk, issuer.pk, tool)
    wrong_class = AnonymousCredential.obtain(other_class, tool)
    with pytest.raises(CredentialError):
        ep.join_anonymous(join(wrong_class).encode(), kind=MemberKind.HUMAN)
    suite = BbsCredentialSuite(issuer.pk, CLASS, tool)
    with pytest.raises(CredentialError, match="membership root"):
        suite.verify(join(members[0]), issuer_root(rogue.pk, CLASS))


def test_issuer_refuses_a_forged_commitment(issuer: Issuer, tool: CredentialTool) -> None:
    c = tool.one({"op": "commit", "committed": []})
    forged = bytearray(bytes.fromhex(c["commitment"]))
    forged[60] ^= 1
    with pytest.raises(CredentialError):
        issuer.blind_sign(bytes(forged))
