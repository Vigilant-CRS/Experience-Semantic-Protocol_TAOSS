# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-066 over real endpoints: MEB profiles are enforced before decoding.

Negative tests craft packets with the sender's own valid session keys
(``_seal``): a malicious or buggy machine cannot get EMO, a missing
``EMO_MASKED`` or a missing ``NO_REPLAY`` past the receiver.
"""

import uuid
from pathlib import Path

import pytest

from esp.codec.errors import WireError
from esp.codec.frame_wire import WireOptions, consent_flags_for, frame_to_payload
from esp.codec.header import ConsentFlags
from esp.consent.capability import AudienceMode, ReceiverCapability, Rights, SenderCapability
from esp.core.taoss_types import TaossType, types_to_bitmap
from esp.crypto.noise_ik import StaticKeyPair
from esp.crypto.primitives import SigningKey
from esp.frame.model import DisclosurePolicy, ExperienceFrame, TypeBlock
from esp.meb.adapter import machine_frame
from esp.meb.handover import HandoverAdapter, simulate
from esp.meb.profiles import SURGICAL, VEHICLE_HANDOVER, DomainProfile
from esp.regulatory.guard import DeploymentContext, Regime, RegulatoryDeclaration
from esp.session.descriptor import SessionDescriptor
from esp.session.endpoint import ReceiverEndpoint, SenderEndpoint
from esp.session.profiles import custom_profile_digest

NO_RIGHTS = Rights(0)
pytestmark = [pytest.mark.integration, pytest.mark.security]
T = TaossType
NOW = 10**18
HOUR = 3600 * 10**9
MACHINE = SigningKey.from_seed(b"\x31" * 32)
DRIVER = SigningKey.from_seed(b"\x32" * 32)
WIRE = WireOptions(addendum=True)
DECLARATION = RegulatoryDeclaration(
    regimes=(Regime.EU_AI_ACT,),
    intended_use="MEB handover simulation (synthetic vehicle, no natural persons' affect)",
    deployment_context=DeploymentContext.SAFETY,
    biometric_inputs=False,
    affect_scopes=(),
)


def pair(
    tmp_path: Path, profile: DomainProfile, *, rights: Rights = NO_RIGHTS
) -> tuple[SenderEndpoint, ReceiverEndpoint]:
    types = profile.types
    desc = SessionDescriptor(
        profile=1,
        sf_level=0,
        registries={
            "esp-addendum-v1": b"\xa1" * 32,
            profile.registry: custom_profile_digest(profile.registry),
        },
    )

    def rc(noise_h: bytes) -> ReceiverCapability:
        return ReceiverCapability(
            accept_types=types_to_bitmap(types),
            max_norm=(2.0,) * len(types),
            valence_bounds=None,
            rate_limit_hz=1000,
            valid_from_ns=0,
            valid_until_ns=NOW + HOUR,
            nonce=b"\x08" * 16,
            pk_receiver=DRIVER.public_bytes,
            noise_h=noise_h,
        )

    r_static = StaticKeyPair.generate()
    sender = SenderEndpoint(
        master=MACHINE,
        static=StaticKeyPair.generate(),
        responder_static=r_static.public_bytes,
        receiver_identity=DRIVER.public_bytes,
        descriptor=desc,
        capability=SenderCapability(
            capability_id=uuid.uuid4(),
            types_allowed=types_to_bitmap(types),
            rights=rights,
            max_segments=100,
            dp_epsilon_ceiling=0.0,
            valid_until_ns=NOW + HOUR,
            audience_mode=AudienceMode.RECIPIENT_PUBKEY,
            audience_value=DRIVER.public_bytes,
            issuer_pk=MACHINE.public_bytes,
            nonce=b"\x07" * 16,
        ),
        state_dir=tmp_path,
        wire=WIRE,
        declaration=DECLARATION,
    )
    receiver = ReceiverEndpoint(
        identity=DRIVER,
        static=r_static,
        descriptor=desc,
        capability=rc,
        trusted_issuers=frozenset({MACHINE.public_bytes}),
        wire=WIRE,
        declaration=DECLARATION,
    )
    hs2, t1 = receiver.on_handshake1(sender.start())
    sender.on_handshake2(hs2)
    receiver.on_transport2(sender.on_transport1(t1))
    return sender, receiver


def handover_frame(seq: int = 1) -> ExperienceFrame:
    sc = simulate(seq)
    return machine_frame(
        HandoverAdapter(),
        sc.sensors,
        sc.actions,
        sc.task,
        profile=VEHICLE_HANDOVER,
        timeline_id=uuid.uuid4(),
        sequence=seq,
        now_ns=NOW,
    )


ALL = DisclosurePolicy(allowed_types=tuple(TaossType))


def test_handover_frame_is_accepted_with_emo_masked(tmp_path: Path) -> None:
    sender, receiver = pair(tmp_path, VEHICLE_HANDOVER)
    packet = sender.send_frame(handover_frame(), ALL, now_ns=NOW)
    result = receiver.receive(packet, now_ns=NOW)
    assert result.accepted, result.violations
    assert result.frame is not None
    assert set(result.frame.present_types) == {T.INT, T.CTX, T.TEM, T.SEN}
    assert T.EMO in result.frame.masked_types
    assert receiver.decoder_invocations == 1


def _crafted(sender: SenderEndpoint, frame: ExperienceFrame, *, clear: int = 0) -> bytes:
    encoded = frame_to_payload(frame, WIRE)
    flags = consent_flags_for(encoded, sender._rights_flags()) & ~clear
    return sender._seal(encoded.types_bitmap, flags, encoded.payload, NOW)


def test_machine_packet_with_emo_bit_is_rejected_before_decoding(tmp_path: Path) -> None:
    sender, receiver = pair(tmp_path, VEHICLE_HANDOVER)
    frame = handover_frame()
    machine_emo = ExperienceFrame.model_validate(
        frame.model_dump()
        | {
            "types": (*frame.types, TypeBlock(type=T.EMO, latent=(1.0,) + (0.0,) * 63)),
            "masked_types": (),
        }
    )
    packet = _crafted(sender, machine_emo)
    result = receiver.receive(packet, now_ns=NOW)
    assert not result.accepted
    assert any("not allowed" in v for v in result.violations)
    assert receiver.decoder_invocations == 0


def test_handover_without_emo_masked_is_rejected(tmp_path: Path) -> None:
    sender, receiver = pair(tmp_path, VEHICLE_HANDOVER)
    packet = _crafted(sender, handover_frame(), clear=int(ConsentFlags.EMO_MASKED))
    result = receiver.receive(packet, now_ns=NOW)
    assert not result.accepted
    assert any("must be explicitly masked" in v for v in result.violations)
    assert receiver.decoder_invocations == 0
    # and the sender refuses to produce such a packet in the first place
    unmasked = handover_frame().model_copy(update={"masked_types": ()})
    with pytest.raises(WireError, match="must be explicitly masked"):
        sender.send_frame(unmasked, ALL, now_ns=NOW)


def test_handover_with_kno_is_rejected(tmp_path: Path) -> None:
    sender, receiver = pair(tmp_path, VEHICLE_HANDOVER)
    frame = handover_frame()
    with_kno = ExperienceFrame.model_validate(
        frame.model_dump()
        | {"types": (TypeBlock(type=T.KNO, latent=(1.0,) + (0.0,) * 239), *frame.types)}
    )
    packet = _crafted(sender, with_kno)
    result = receiver.receive(packet, now_ns=NOW)
    assert not result.accepted
    assert any("not allowed" in v for v in result.violations)
    # the honest sender path withholds KNO: the capability and profile do not allow it
    ok = receiver.receive(sender.send_frame(with_kno, ALL, now_ns=NOW), now_ns=NOW)
    assert ok.accepted
    assert ok.frame is not None
    assert T.KNO not in ok.frame.present_types


def _surgical_frame() -> ExperienceFrame:
    frame = handover_frame()
    blocks = [b for b in frame.types if b.type in {T.INT, T.SEN, T.TEM}]
    blocks.append(TypeBlock(type=T.KNO, latent=(1.0,) + (0.0,) * 239))
    return ExperienceFrame.model_validate(frame.model_dump() | {"types": tuple(blocks)})


def test_surgical_requires_no_replay_on_both_sides(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    sender, receiver = pair(tmp_path / "a", SURGICAL)
    packet = sender.send_frame(_surgical_frame(), ALL, now_ns=NOW)
    ok = receiver.receive(packet, now_ns=NOW)
    assert ok.accepted, ok.violations
    # a capability granting ALLOW_REPLAY would drop NO_REPLAY: the sender refuses to send
    sender2, receiver2 = pair(tmp_path / "b", SURGICAL, rights=Rights.ALLOW_REPLAY)
    with pytest.raises(WireError, match="required consent flags"):
        sender2.send_frame(_surgical_frame(), ALL, now_ns=NOW)
    # a crafted packet without NO_REPLAY is refused by the profile check, not only Accept(9)
    crafted = _crafted(sender2, _surgical_frame(), clear=int(ConsentFlags.NO_REPLAY))
    result = receiver2.receive(crafted, now_ns=NOW)
    assert not result.accepted
    assert any("required consent flags" in v for v in result.violations)
    assert receiver2.decoder_invocations == 0
