# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Adversarial regressions for the 2026-09-29 review (ADR-0033)."""

import dataclasses
import hashlib
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from esp.agent.descriptor import AGENT_EVENT_CODE, OPAQUE_DESCRIPTOR_CODE
from esp.codec.errors import WireError
from esp.codec.header import DpLevel, Header
from esp.codec.tlv import Tlv, encode_tlv
from esp.consent.capability import SenderCapability
from esp.consent.revocation import RevocationRegistry
from esp.core.taoss_types import TaossType as T
from esp.crypto.envelope import open_packet, seal_packet
from esp.crypto.primitives import CryptoError, SigningKey
from esp.decoder.budget import DecodeBudget
from esp.privacy.dp import (
    Adjacency,
    DpAuditor,
    DpParams,
    PrivacyBudgetError,
    PrivacyLedger,
    epsilon_rdp,
    rdp_coefficient,
)
from esp.session.endpoint import APPLICATION_CONTROL_CODES, ReceiverHardening
from esp.session.sequence import NonceReuseError, SenderSequencer, SequenceStore
from esp.xcf.capsule import EnvelopeAlg, seal
from esp.xcf.gate import Gate, GateRefused, ReleaseRequest, gated_access, recall, unwrap_release
from tests.integration.test_endpoint import ALL, NOW, descriptor, establish, pair, sender_capability
from tests.integration.test_endpoint_dp import KNO_CTX, SIGMA, dp_pair, latent_only
from tests.unit.frame.test_frame_wire import full_anchor_frame
from tests.unit.test_keys_revocation import OLD, witnessed_lineage
from tests.unit.xcf.test_xcf import MASTER, RECIPIENT, body, cap, lineage, recall_policy, spec
from tests.unit.xcf.test_xcf import NOW as XNOW

pytestmark = [pytest.mark.integration, pytest.mark.security]


def test_sender_refuses_unprotected_dp_descriptor(tmp_path: Path) -> None:
    with pytest.raises(PrivacyBudgetError, match="requires a DP configuration"):
        dp_pair(tmp_path, dp=False)


def test_parallel_ledger_instances_cannot_overspend(tmp_path: Path) -> None:
    cid = uuid.uuid4()
    ledgers = [PrivacyLedger(tmp_path / "budget.json", cid, ceiling=1.0) for _ in range(8)]

    def attempt(ledger: PrivacyLedger) -> bool:
        try:
            ledger.charge(0.01)
        except PrivacyBudgetError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(attempt, ledgers)) == 1
    assert PrivacyLedger(tmp_path / "budget.json", cid, ceiling=1.0).k == 1


@pytest.mark.parametrize("cost", [-1.0, 0.0, float("nan"), float("inf")])
def test_invalid_budget_cost_cannot_decrease_ledger(tmp_path: Path, cost: float) -> None:
    ledger = PrivacyLedger(tmp_path / "budget.json", uuid.uuid4(), ceiling=1.0)
    ledger.charge(0.01)
    with pytest.raises(PrivacyBudgetError):
        ledger.charge(cost)
    assert ledger.k == 1


def test_rotated_key_cannot_issue_a_fresh_grant(tmp_path: Path) -> None:
    lin, _ = witnessed_lineage()
    grant = dataclasses.replace(sender_capability(), issuer_pk=OLD.public_bytes)
    _, r = pair(tmp_path, trusted=frozenset({OLD.public_bytes}))
    r._lineage = lin
    verified = SenderCapability.verify(grant.sign(OLD))
    with pytest.raises(CryptoError, match="not trusted"):
        r._check_issuer(verified)
    r.accept_state.accepted_grants.add(hashlib.sha256(verified.body()).digest())
    r._check_issuer(verified)
    changed = dataclasses.replace(verified, max_segments=verified.max_segments + 1)
    with pytest.raises(CryptoError, match="not trusted"):
        r._check_issuer(changed)


def test_every_affect_descriptor_must_respect_asymmetric_bounds(tmp_path: Path) -> None:
    s, r = pair(tmp_path, sf=6)
    factory = r._capability_factory
    r._capability_factory = lambda h: dataclasses.replace(factory(h), valence_bounds=(0.0, 1.0))
    establish(s, r)
    frame = full_anchor_frame()
    blocks = []
    for original_block in frame.types:
        block = original_block
        if block.type is T.EMO:
            original = block.affect[0]
            block = block.model_copy(
                update={
                    "affect": (
                        original.model_copy(update={"valence": 0.75}),
                        original.model_copy(update={"valence": -0.5}),
                    )
                }
            )
        blocks.append(block)
    frame = frame.model_copy(update={"types": tuple(blocks)})
    result = r.receive(s.send_frame(frame, ALL, now_ns=NOW), now_ns=NOW)
    assert not result.accepted
    assert any("valence" in v for v in result.violations)
    assert r.decoder_invocations == 0


@pytest.mark.parametrize("fields", [{"profile": 2}, {"sf_level": 7}])
def test_authenticated_packet_must_match_session_profile(tmp_path: Path, fields: dict) -> None:
    s, r = pair(tmp_path)
    establish(s, r)
    packet = s.send_frame(full_anchor_frame(), ALL, now_ns=NOW)
    opened = open_packet(
        packet, s._keys, expected_sender=s.session_public_key, max_payload_len=2**20
    )
    forged = seal_packet(
        dataclasses.replace(opened.header, **fields), opened.plaintext, s._keys, s._session_key
    )
    assert not r.receive(forged, now_ns=NOW).accepted
    assert r.receive(packet, now_ns=NOW).accepted  # rejection did not consume sequence state


def test_receiver_payload_limit_binds_sender_and_receiver(tmp_path: Path) -> None:
    s, r = pair(tmp_path, r_desc=descriptor(max_payload_len=100))
    establish(s, r)
    with pytest.raises(WireError, match="negotiated maximum"):
        s.send_frame(full_anchor_frame(), ALL, now_ns=NOW)
    # Bypass the honest sender's preflight to test the receiver independently.
    s._negotiated = dataclasses.replace(s._negotiated, responder=descriptor())
    packet = s.send_frame(full_anchor_frame(), ALL, now_ns=NOW)
    assert Header.decode(packet[:100]).payload_len > 100
    assert not r.receive(packet, now_ns=NOW).accepted


def test_unnegotiated_wire_extensions_abort_establishment(tmp_path: Path) -> None:
    s, r = pair(tmp_path, r_desc=descriptor(registries={}))
    with pytest.raises(WireError, match="registries pinned by both"):
        establish(s, r)


@pytest.mark.parametrize("code", [0x23, 0x81, 0x86, 0x60])
def test_bad_controls_are_rejected_without_crashing_or_committing(
    tmp_path: Path, code: int
) -> None:
    s, r = pair(tmp_path)
    establish(s, r)
    bad = s.send_control(encode_tlv(code, b""), now_ns=NOW)
    assert not r.receive(bad, now_ns=NOW).accepted
    assert r.sos_signals == 0
    assert r.receive(s.sos(now_ns=NOW), now_ns=NOW).accepted
    assert r.sos_signals == 1


def test_controls_apply_atomically(tmp_path: Path) -> None:
    s, r = pair(tmp_path)
    establish(s, r)
    # A valid SOS before a malformed close must not partially apply.
    packet = s.send_control(encode_tlv(0x86, b"\x01") + encode_tlv(0x81, b""), now_ns=NOW)
    assert not r.receive(packet, now_ns=NOW).accepted
    assert r.sos_signals == 0


def test_throttled_dp_packet_can_be_retried_without_double_charge(tmp_path: Path) -> None:
    s, r, ledger = dp_pair(tmp_path)
    r._hardening = ReceiverHardening(decode_budget=DecodeBudget(rate_per_s=1, burst=1))
    assert r.receive(s.send_frame(latent_only(), KNO_CTX, now_ns=NOW), now_ns=NOW).accepted
    packet = s.send_frame(latent_only(), KNO_CTX, now_ns=NOW + 1)
    denied = r.receive(packet, now_ns=NOW + 1)
    assert not denied.accepted
    assert "throttled" in denied.violations[0]
    assert r.receive(packet, now_ns=NOW + 2_000_000_000).accepted
    assert ledger.k == 2
    assert not r.receive(packet, now_ns=NOW + 3_000_000_000).accepted


def test_variable_release_costs_use_cumulative_accounting() -> None:
    auditor, cid, total = DpAuditor(ceiling=100), uuid.uuid4(), 0.0
    for k, types in enumerate(((T.KNO,), (T.KNO, T.CTX), (T.KNO,)), 1):
        clips, sigmas = dict.fromkeys(types, 1.0), dict.fromkeys(types, SIGMA)
        total += rdp_coefficient(clips, sigmas)
        params = DpParams(
            cid, Adjacency.FRAME, 0, clips, sigmas, k, epsilon_rdp(total, 1e-6)[0], 1e-6
        )
        assert (
            auditor.audit(DpLevel.L1_BALANCED_REF, params, frozenset(types)) == params.epsilon_spent
        )


def test_retransmit_cache_is_bounded_and_eviction_never_reuses_nonce(tmp_path: Path) -> None:
    store = SequenceStore(tmp_path / "seq.json", "test")
    store.initialize()
    sequencer = SenderSequencer(store, max_cached_packets=4)
    for _ in range(20):
        seq = sequencer.reserve(b"plain")
        sequencer.record_sent(seq, b"plain", b"sealed" + bytes([seq]))
    assert len(sequencer._sent) == 4
    assert not sequencer._plaintext_digest
    assert sequencer.retransmit(19) == b"sealed\x13"
    with pytest.raises(NonceReuseError):
        sequencer.record_sent(0, b"plain", b"new ciphertext")
    with pytest.raises(NonceReuseError):
        sequencer.retransmit(0)
    assert sequencer.reserve(b"next") == 20


def test_gate_checks_signature_owner_audience_and_recipient_key() -> None:
    gate = Gate()
    gid, secret = gate.new_gate(MASTER.public_bytes)
    capsule, cek = seal(
        spec(),
        body(),
        envelope_alg=EnvelopeAlg.GATED_CEK,
        access_material=gated_access(gid, secret),
    )
    key = X25519PrivateKey.generate()
    grant = cap()

    def request(tlv: Tlv, identity=RECIPIENT):
        return ReleaseRequest.create(
            capsule, tlv, key.public_key(), identity, valid_until_ns=XNOW + 10**12
        )

    def release(tlv: Tlv, proof: ReleaseRequest, recipient=None):
        return gate.release(
            capsule,
            tlv,
            recipient or key.public_key(),
            request=proof,
            now_ns=XNOW,
            revocations=RevocationRegistry(),
        )

    assert unwrap_release(capsule, release(grant, request(grant)), key) == cek
    broken = Tlv(grant.code, grant.value[:-1] + bytes([grant.value[-1] ^ 1]))
    with pytest.raises(CryptoError):
        release(broken, request(broken))
    stranger = SigningKey.generate()
    foreign = dataclasses.replace(
        SenderCapability.verify(grant), issuer_pk=stranger.public_bytes
    ).sign(stranger)
    with pytest.raises(GateRefused, match="registered gate owner"):
        release(foreign, request(foreign))
    with pytest.raises(GateRefused, match="audience"):
        release(grant, request(grant, stranger))
    with pytest.raises(CryptoError):
        release(grant, request(grant), X25519PrivateKey.generate().public_key())
    stale = ReleaseRequest.create(
        capsule, grant, key.public_key(), RECIPIENT, valid_until_ns=XNOW - 1
    )
    with pytest.raises(GateRefused, match="expired"):
        release(grant, stale)
    revoked = RevocationRegistry()
    revoked.revoked_capabilities.add(SenderCapability.verify(grant).capability_id.bytes)
    with pytest.raises(GateRefused, match="revoked"):
        gate.release(
            capsule,
            grant,
            key.public_key(),
            request=request(grant),
            now_ns=XNOW,
            revocations=revoked,
        )


def test_recall_fails_closed_on_missing_ancestor_or_policy() -> None:
    chain = lineage(3)
    store = {c.cid: c for c in chain}
    policy = recall_policy(store)
    for partial in ({chain[-1].cid: chain[-1]}, store):
        selected_policy = policy if len(partial) == 1 else dataclasses.replace(policy, no_replay={})
        with pytest.raises(GateRefused):
            recall(
                partial,
                chain[-1].cid,
                cap(),
                recipient_pk=RECIPIENT.public_bytes,
                revocations=RevocationRegistry(),
                now_ns=XNOW,
                policy=selected_policy,
                epsilon_budget=1.0,
            )


def test_application_control_codes_match_the_agent_profile() -> None:
    assert frozenset({OPAQUE_DESCRIPTOR_CODE, AGENT_EVENT_CODE}) == APPLICATION_CONTROL_CODES
