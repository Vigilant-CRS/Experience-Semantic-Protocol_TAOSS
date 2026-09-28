# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GAP-017: FROST DKG (Pedersen with proofs of knowledge) replaces the trusted dealer."""

import dataclasses
import itertools

import pytest

from esp.hive import dkg, frost

pytestmark = pytest.mark.security
CTX = b"episode-7f"


def _sign(info: frost.GroupInfo, signers: list[frost.KeyShare], msg: bytes) -> bytes:
    rounds = [frost.commit(s) for s in signers]
    comms = [c for _, c in rounds]
    shares = {
        s.identifier: frost.sign(s, n, msg, comms)
        for s, (n, _) in zip(signers, rounds, strict=True)
    }
    return frost.aggregate(info, comms, msg, shares)


def test_dkg_shares_sign_as_plain_ed25519_for_every_threshold_subset() -> None:
    info, shares = dkg.run_local(5, 3, CTX)
    assert info.min_participants == 3
    assert set(info.participant_publics) == {1, 2, 3, 4, 5}
    for subset in itertools.combinations(shares, 3):
        sig = _sign(info, list(subset), b"collective intent")
        assert frost.verify(info.group_public, b"collective intent", sig)
        assert not frost.verify(info.group_public, b"other message", sig)


def test_every_participant_derives_the_same_group() -> None:
    rounds = [dkg.round1(i, 2, 3, CTX) for i in (1, 2, 3)]
    broadcasts = [b for _, b in rounds]
    results = [
        dkg.finish(i, 2, broadcasts, {s.identifier: s.share_for(i) for s, _ in rounds}, CTX)
        for i in (1, 2, 3)
    ]
    assert all(r[0] == results[0][0] for r in results)
    for info, share in results:
        assert info.participant_publics[share.identifier] == share.public


def test_no_single_participant_knows_the_group_secret() -> None:
    info, shares = dkg.run_local(3, 2, CTX)
    for s in shares:
        assert frost.serialize_element(frost.base_mult(s.secret)) != info.group_public


def test_bad_proof_of_knowledge_names_the_culprit() -> None:
    rounds = [dkg.round1(i, 2, 3, CTX) for i in (1, 2, 3)]
    forged = dataclasses.replace(rounds[1][1], proof_mu=frost.serialize_scalar(12345))
    broadcasts = [rounds[0][1], forged, rounds[2][1]]
    with pytest.raises(dkg.DkgComplaint) as exc:
        dkg.finish(1, 2, broadcasts, {s.identifier: s.share_for(1) for s, _ in rounds}, CTX)
    assert exc.value.culprit == 2


def test_proof_is_bound_to_the_context_and_identifier() -> None:
    _, b = dkg.round1(1, 2, 3, CTX)
    dkg.verify_round1(b, 2, CTX)
    with pytest.raises(dkg.DkgComplaint):
        dkg.verify_round1(b, 2, b"another episode")
    with pytest.raises(dkg.DkgComplaint):
        dkg.verify_round1(dataclasses.replace(b, identifier=2), 2, CTX)


def test_rogue_key_without_knowledge_is_refused() -> None:
    """Participant 3 cancels participant 1's key (C_30 = X - C_10) but cannot prove knowledge."""
    rounds = [dkg.round1(i, 2, 3, CTX) for i in (1, 2, 3)]
    c10 = frost.deserialize_element(rounds[0][1].commitments[0])
    neg = frost._mul(frost.L - 1, c10)
    target = frost._add(frost.base_mult(7), neg)
    rogue = dataclasses.replace(
        rounds[2][1], commitments=(frost.serialize_element(target), *rounds[2][1].commitments[1:])
    )
    with pytest.raises(dkg.DkgComplaint) as exc:
        dkg.verify_round1(rogue, 2, CTX)
    assert exc.value.culprit == 3


def test_bad_share_names_the_sender() -> None:
    rounds = [dkg.round1(i, 2, 3, CTX) for i in (1, 2, 3)]
    received = {s.identifier: s.share_for(2) for s, _ in rounds}
    received[3] = (received[3] + 1) % frost.L
    with pytest.raises(dkg.DkgComplaint) as exc:
        dkg.finish(2, 2, [b for _, b in rounds], received, CTX)
    assert exc.value.culprit == 3


def test_structural_errors() -> None:
    rounds = [dkg.round1(i, 2, 3, CTX) for i in (1, 2, 3)]
    b = [x for _, x in rounds]
    shares = {s.identifier: s.share_for(1) for s, _ in rounds}
    with pytest.raises(frost.FrostError, match="share from every participant"):
        dkg.finish(1, 2, b, {1: shares[1], 2: shares[2]}, CTX)
    with pytest.raises(frost.FrostError, match="numbered"):
        dkg.finish(1, 2, [b[0], b[0], b[2]], shares, CTX)
    with pytest.raises(dkg.DkgComplaint, match="number of commitments"):
        dkg.verify_round1(b[0], 3, CTX)
    with pytest.raises(frost.FrostError):
        dkg.round1(1, 1, 3, CTX)
