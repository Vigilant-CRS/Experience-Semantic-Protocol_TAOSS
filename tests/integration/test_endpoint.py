# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Endpoint integration: establishment, consented data flow, quarantine, revocation.

Covers the remaining parts of WP-051 (quarantine before decoding), WP-048
(no descriptor change inside a session) and the core of WP-024.
"""

import contextlib
import dataclasses
import uuid
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from esp.codec.frame_wire import WireOptions
from esp.codec.tlv import encode_tlv
from esp.consent.capability import AudienceMode, ReceiverCapability, Rights, SenderCapability
from esp.consent.revocation import ConsentRevocationReason, Effects, RevocationIntent
from esp.core.provenance import AffectScope
from esp.core.taoss_types import TaossType
from esp.crypto.noise_ik import StaticKeyPair
from esp.crypto.primitives import CryptoError, SigningKey
from esp.frame.model import DisclosurePolicy
from esp.ontology.profiles import BASIC8_ID, basic8_registry
from esp.regulatory.guard import DeploymentContext, Regime, RegulatoryDeclaration
from esp.session.descriptor import NegotiationError, SessionDescriptor
from esp.session.endpoint import ReceiverEndpoint, SenderEndpoint
from esp.session.state import SessionState, SessionStateError, StateMachine
from tests.unit.frame.test_frame_wire import full_anchor_frame

pytestmark = [pytest.mark.integration, pytest.mark.security]
T = TaossType
MASTER = SigningKey.from_seed(b"\x91" * 32)
RECEIVER_ID = SigningKey.from_seed(b"\x92" * 32)
REGISTRY = basic8_registry()
WIRE = WireOptions(addendum=True, anchor_sets={BASIC8_ID: REGISTRY.anchor_set(BASIC8_ID)})
REGISTRIES = {"esp-addendum-v1": b"\xa1" * 32, BASIC8_ID: bytes.fromhex(REGISTRY.digest_hex())}
NOW = 1_000 * 10**9
CAP_ID = uuid.UUID("21212121-2121-4121-8121-212121212121")
DECLARATION = RegulatoryDeclaration(
    regimes=(Regime.EU_AI_ACT, Regime.EU_GDPR),
    intended_use="ESP reference implementation tests (synthetic data)",
    deployment_context=DeploymentContext.OTHER,
    biometric_inputs=False,
    affect_scopes=(AffectScope.CONTENT, AffectScope.SELF_DECLARED),
)


def descriptor(**kw: object) -> SessionDescriptor:
    return SessionDescriptor(**({"profile": 1, "sf_level": 0, "registries": REGISTRIES} | kw))  # type: ignore[arg-type]


def sender_capability(types: int = 0x3F, **kw: object) -> SenderCapability:
    fields: dict[str, object] = {
        "capability_id": CAP_ID,
        "types_allowed": types,
        "rights": Rights(0),
        "max_segments": 100,
        "dp_epsilon_ceiling": 0.0,
        "valid_until_ns": NOW + 3600 * 10**9,
        "audience_mode": AudienceMode.RECIPIENT_PUBKEY,
        "audience_value": RECEIVER_ID.public_bytes,
        "issuer_pk": MASTER.public_bytes,
        "nonce": b"\x07" * 16,
    }
    return SenderCapability(**(fields | kw))  # type: ignore[arg-type]


def receiver_capability_for(types: int = 0x3F):  # type: ignore[no-untyped-def]
    """Factory for a receiver capability accepting ``types`` (valence bounds iff EMO)."""
    n = bin(types).count("1")

    def factory(noise_h: bytes) -> ReceiverCapability:
        return ReceiverCapability(
            accept_types=types,
            max_norm=(1e3,) * n,
            valence_bounds=(-1.0, 1.0) if types & T.EMO.bit else None,
            rate_limit_hz=1000,
            valid_from_ns=0,
            valid_until_ns=NOW + 3600 * 10**9,
            nonce=b"\x08" * 16,
            pk_receiver=RECEIVER_ID.public_bytes,
            noise_h=noise_h,
        )

    return factory


receiver_capability = receiver_capability_for(0x3F)


def pair(
    tmp_path: Path,
    *,
    sf: int = 0,
    receiver_types: int | None = 0x3F,
    cap: SenderCapability | None = None,
    trusted: frozenset[bytes] | None = None,
    r_desc: SessionDescriptor | None = None,
    wire: WireOptions = WIRE,
):  # type: ignore[no-untyped-def]
    """Sender/receiver pair; ``receiver_types=None`` means no receiver capability (default deny)."""
    r_static = StaticKeyPair.generate()
    sender = SenderEndpoint(
        master=MASTER,
        static=StaticKeyPair.generate(),
        responder_static=r_static.public_bytes,
        receiver_identity=RECEIVER_ID.public_bytes,
        descriptor=descriptor(sf_level=sf),
        capability=cap or sender_capability(),
        state_dir=tmp_path,
        wire=wire,
        declaration=DECLARATION,
    )
    receiver = ReceiverEndpoint(
        identity=RECEIVER_ID,
        static=r_static,
        descriptor=r_desc or descriptor(sf_level=sf),
        capability=None if receiver_types is None else receiver_capability_for(receiver_types),
        trusted_issuers=trusted if trusted is not None else frozenset({MASTER.public_bytes}),
        wire=wire,
        declaration=DECLARATION,
    )
    return sender, receiver


def establish(sender: SenderEndpoint, receiver: ReceiverEndpoint) -> None:
    hs2, t1 = receiver.on_handshake1(sender.start())
    sender.on_handshake2(hs2)
    receiver.on_transport2(sender.on_transport1(t1))


ALL = DisclosurePolicy(allowed_types=tuple(TaossType))


def test_establishment_reaches_active_with_matching_transcripts(tmp_path: Path) -> None:
    s, r = pair(tmp_path)
    establish(s, r)
    assert s.state is SessionState.ACTIVE
    assert r.state is SessionState.ACTIVE
    assert s.transcript == r.transcript
    assert s.transcript is not None
    assert list(tmp_path.glob("seq-*.json"))  # sequence state persisted


def test_receiver_consent_masks_emo_within_sf6(tmp_path: Path) -> None:
    s, r = pair(tmp_path, sf=6, receiver_types=0x3B)  # receiver accepts everything except EMO
    establish(s, r)
    result = r.receive(s.send_frame(full_anchor_frame(), ALL, now_ns=NOW), now_ns=NOW)
    assert result.accepted, result.violations
    assert result.frame is not None
    assert result.frame.present_types == (T.KNO, T.INT, T.CTX, T.SEN, T.TEM)
    assert result.frame.masked_types == (T.EMO,)


def test_sf6_with_emo_consent_carries_emo(tmp_path: Path) -> None:
    s, r = pair(tmp_path, sf=6)
    establish(s, r)
    result = r.receive(s.send_frame(full_anchor_frame(), ALL, now_ns=NOW), now_ns=NOW)
    assert result.frame is not None
    assert result.frame.present_types == tuple(TaossType)


def test_profile_requires_consentable_types(tmp_path: Path) -> None:
    s, r = pair(tmp_path, sf=7, receiver_types=0x3B)  # SF7 needs EMO, receiver refuses it
    with pytest.raises(CryptoError, match="SF7 requires"):
        establish(s, r)
    assert r.state is SessionState.CLOSED or s.state is SessionState.CLOSED


def test_sender_refuses_frames_violating_the_profile(tmp_path: Path) -> None:
    from esp.codec.errors import WireError  # noqa: PLC0415

    s, r = pair(tmp_path, sf=2)
    establish(s, r)
    with pytest.raises(WireError, match="required types missing"):
        s.send_frame(
            full_anchor_frame(), DisclosurePolicy(allowed_types=(T.KNO, T.CTX)), now_ns=NOW
        )
    assert r.decoder_invocations == 0


def test_emo_masked_end_to_end(tmp_path: Path) -> None:
    s, r = pair(tmp_path, sf=2)
    establish(s, r)
    packet = s.send_frame(
        full_anchor_frame(), DisclosurePolicy(allowed_types=(T.KNO, T.INT, T.CTX)), now_ns=NOW
    )
    assert packet[8:10] == (T.KNO.bit | T.INT.bit | T.CTX.bit).to_bytes(2, "big")
    assert packet[10:12] == (0x0001 | 0x0002 | 0x0004).to_bytes(
        2, "big"
    )  # EMO_MASKED|NO_REPLAY|NO_STORE
    result = r.receive(packet, now_ns=NOW)
    assert result.accepted
    assert result.frame is not None
    assert result.frame.block(T.EMO) is None
    assert T.EMO in result.frame.masked_types


def test_default_deny_receiver_gets_only_kno_ctx(tmp_path: Path) -> None:
    s, r = pair(tmp_path, sf=1, receiver_types=None)
    establish(s, r)
    result = r.receive(s.send_frame(full_anchor_frame(), ALL, now_ns=NOW), now_ns=NOW)
    assert result.frame is not None
    assert result.frame.present_types == (T.KNO, T.CTX)


def test_rejected_packets_never_reach_the_decoder(tmp_path: Path) -> None:
    s, r = pair(tmp_path, sf=6, cap=sender_capability(types=0x3B))  # sender: everything but EMO
    establish(s, r)
    # A misbehaving sender bypasses its own policy and pushes EMO anyway.
    s._capability = sender_capability(types=0x3F)
    packet = s.send_frame(full_anchor_frame(), ALL, now_ns=NOW)
    result = r.receive(packet, now_ns=NOW)
    assert not result.accepted
    assert any(v.startswith("3:types not permitted") for v in result.violations)
    assert r.decoder_invocations == 0
    s._capability = sender_capability(types=0x3B)
    tampered = bytearray(s.send_frame(full_anchor_frame(), ALL, now_ns=NOW))
    tampered[-70] ^= 1
    assert not r.receive(bytes(tampered), now_ns=NOW).accepted
    assert r.decoder_invocations == 0


def test_data_before_consent_is_rejected(tmp_path: Path) -> None:
    s, r = pair(tmp_path)
    hs2, t1 = r.on_handshake1(s.start())
    s.on_handshake2(hs2)
    t2 = s.on_transport1(t1)  # sender is ACTIVE, receiver not yet
    packet = s.send_frame(full_anchor_frame(), DisclosurePolicy(allowed_types=(T.KNO,)), now_ns=NOW)
    early = r.receive(packet, now_ns=NOW)
    assert not early.accepted
    assert "data before consent" in early.violations[0]
    r.on_transport2(t2)
    assert r.receive(packet, now_ns=NOW).accepted


def test_replayed_packet_rejected(tmp_path: Path) -> None:
    s, r = pair(tmp_path)
    establish(s, r)
    packet = s.send_frame(full_anchor_frame(), DisclosurePolicy(allowed_types=(T.KNO,)), now_ns=NOW)
    assert r.receive(packet, now_ns=NOW).accepted
    again = r.receive(packet, now_ns=NOW)
    assert not again.accepted
    assert "replayed" in again.violations[0]


def test_revocation_stops_future_data(tmp_path: Path) -> None:
    s, r = pair(tmp_path)
    establish(s, r)
    kno = DisclosurePolicy(allowed_types=(T.KNO,))
    assert r.receive(s.send_frame(full_anchor_frame(), kno, now_ns=NOW), now_ns=NOW).accepted
    intent = RevocationIntent(
        CAP_ID,
        uuid.UUID(int=0),
        0,
        ConsentRevocationReason.CONSENT_WITHDRAWN,
        Effects.REVOKE_FUTURE_USE,
        MASTER.public_bytes,
        MASTER.public_bytes,
    ).sign(MASTER)
    assert r.receive(s.send_control(intent.encode(), now_ns=NOW), now_ns=NOW).accepted
    after = r.receive(s.send_frame(full_anchor_frame(), kno, now_ns=NOW), now_ns=NOW)
    assert not after.accepted
    assert "13:capability or timeline revoked" in after.violations


def test_close_ends_the_session(tmp_path: Path) -> None:
    s, r = pair(tmp_path)
    establish(s, r)
    close = s.close(now_ns=NOW)
    assert s.state is SessionState.CLOSED
    assert r.receive(close, now_ns=NOW).accepted
    assert r.state is SessionState.CLOSED
    with pytest.raises(SessionStateError):
        s.send_frame(full_anchor_frame(), ALL, now_ns=NOW)


def test_descriptor_change_inside_a_session_aborts(tmp_path: Path) -> None:
    s, r = pair(tmp_path)
    establish(s, r)
    sneaky = s.send_control(encode_tlv(0x80, descriptor(sf_level=6).encode()), now_ns=NOW)
    with pytest.raises(SessionStateError, match="new handshake"):
        r.receive(sneaky, now_ns=NOW)
    assert r.state is SessionState.CLOSED


def test_untrusted_issuer_and_profile_mismatch_fail_closed(tmp_path: Path) -> None:
    s, r = pair(tmp_path, trusted=frozenset())
    with pytest.raises(CryptoError, match="not trusted"):
        establish(s, r)
    assert r.state is SessionState.CLOSED
    s2, r2 = pair(tmp_path / "b", r_desc=descriptor(sf_level=1))
    (tmp_path / "b").mkdir()
    with pytest.raises(NegotiationError):
        establish(s2, r2)
    assert r2.state is SessionState.CLOSED


def test_audience_mismatch_rejected_per_packet(tmp_path: Path) -> None:
    other = SigningKey.from_seed(b"\x93" * 32)
    s, r = pair(tmp_path, cap=sender_capability(audience_value=other.public_bytes))
    establish(s, r)
    res = r.receive(
        s.send_frame(full_anchor_frame(), DisclosurePolicy(allowed_types=(T.KNO,)), now_ns=NOW),
        now_ns=NOW,
    )
    assert "4:recipient not in audience" in res.violations


# --- WP-024 property: state machine never allows data outside ACTIVE ---------------

EVENTS = list(SessionState)


@settings(max_examples=500)
@given(st.lists(st.sampled_from(EVENTS), max_size=20))
def test_state_machine_never_allows_data_outside_active(events: list[SessionState]) -> None:
    m = StateMachine()
    for target in events:
        with contextlib.suppress(SessionStateError):
            m.advance(target)
        try:
            m.require_data()
        except SessionStateError:
            assert m.state is not SessionState.ACTIVE
        else:
            assert m.state is SessionState.ACTIVE
    history = m.history
    reached_active = SessionState.ACTIVE in history
    if reached_active:
        idx = history.index(SessionState.ACTIVE)
        assert SessionState.CONSENT_ESTABLISHED in history[:idx]
    assert history.count(SessionState.CLOSED) <= 1
    if SessionState.CLOSED in history:
        assert history[-1] is SessionState.CLOSED


def test_locally_widened_capability_does_not_bypass_verification(tmp_path: Path) -> None:
    """A capability widened after signing is not what the receiver verified."""
    s, r = pair(tmp_path, sf=6, cap=sender_capability(types=0x3B))
    establish(s, r)
    s._capability = dataclasses.replace(sender_capability(types=0x3B), types_allowed=0x3F)
    res = r.receive(s.send_frame(full_anchor_frame(), ALL, now_ns=NOW), now_ns=NOW)
    assert not res.accepted  # the receiver enforces the capability it verified (no EMO)
    assert any(v.startswith("3:types not permitted: EMO") for v in res.violations)


def test_compromised_master_key_terminates_live_sessions(tmp_path: Path) -> None:
    s, r = pair(tmp_path)
    establish(s, r)
    assert not r.notify_key_compromised(b"\x00" * 32)  # unrelated key: no effect
    assert r.state is SessionState.ACTIVE
    assert r.notify_key_compromised(MASTER.public_bytes)
    assert r.state is SessionState.CLOSED
    late = r.receive(
        s.send_frame(full_anchor_frame(), DisclosurePolicy(allowed_types=(T.KNO,)), now_ns=NOW),
        now_ns=NOW,
    )
    assert not late.accepted
