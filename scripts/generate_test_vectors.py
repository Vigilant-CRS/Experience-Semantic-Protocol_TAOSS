# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Generate the versioned conformance vectors under ``vectors/`` (plan WP-021).

Usage: uv run python scripts/generate_test_vectors.py [--check]

Vectors are deterministic (fixed inputs, no randomness). ``--check`` fails if
the committed files differ from what the generator produces.
"""

from __future__ import annotations

import json
import struct
import sys
import uuid
from pathlib import Path
from typing import Any

import numpy as np

from esp.codec.header import HEADER_LEN, ConsentFlags, DpLevel, Header, PrivacyFlags, float32
from esp.codec.tlv import LatentEncoding, encode_tlv, encode_typed_latent
from esp.consent.capability import AudienceMode, ReceiverCapability, Rights, SenderCapability
from esp.consent.revocation import (
    ConsentRevocationReason,
    DeletionAttestation,
    DeletionScope,
    Effects,
    RevocationIntent,
    request_digest,
)
from esp.core.taoss_types import TaossType
from esp.crypto.envelope import seal_packet
from esp.crypto.identity import IdentityProof, session_binding
from esp.crypto.keys import DirectionKeys, deterministic_nonce, timeline_tag
from esp.crypto.primitives import SigningKey, blake2b
from esp.privacy.dp import (
    REFERENCE_PROFILES,
    Adjacency,
    DpParams,
    epsilon_rdp,
    rdp_coefficient,
)
from esp.session.descriptor import SessionDescriptor
from esp.session.replay import ReplayError, ReplayWindow

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "vectors"
SUITE_VERSION = "1.0.0"

TIMELINE = uuid.UUID("5f0c6a8e-3b7d-4c4e-9a53-2f6a1d9e8b10")
SENDER = bytes(range(32))
NONCE = bytes.fromhex("000102030405060708090a0b")


def header_fields(h: Header) -> dict[str, Any]:
    return {
        "version_major": h.version_major,
        "version_minor": h.version_minor,
        "profile": h.profile,
        "sf_level": h.sf_level,
        "types_bitmap": h.types_bitmap,
        "consent_flags": h.consent_flags,
        "privacy_flags": h.privacy_flags,
        "capabilities": h.capabilities,
        "timestamp_ns": h.timestamp_ns,
        "timeline_id": str(h.timeline_id),
        "segment_seq": h.segment_seq,
        "dt_ms": h.dt_ms,
        "phase_f32_hex": struct.pack(">f", h.phase).hex(),
        "sender_id": h.sender_id.hex(),
        "payload_len": h.payload_len,
        "nonce": h.nonce.hex(),
    }


def base(**kw: Any) -> Header:  # noqa: ANN401
    fields: dict[str, Any] = {
        "profile": 1,
        "sf_level": 0,
        "types_bitmap": 0x0001,
        "consent_flags": 0,
        "privacy_flags": 0,
        "capabilities": 0,
        "timestamp_ns": 1_727_000_000_000_000_000,
        "timeline_id": TIMELINE,
        "segment_seq": 0,
        "dt_ms": 0,
        "phase": 0.0,
        "sender_id": SENDER,
        "payload_len": 0,
        "nonce": NONCE,
    }
    fields.update(kw)
    return Header(**fields)


def valid_header_vectors() -> list[dict[str, Any]]:
    cases = [
        ("minimal", "SF0, KNO only, empty payload", base()),
        (
            "all_types",
            "SF7, all six TAOSS types, NO_REPLAY|NO_STORE, quantized, timing obfuscation",
            base(
                sf_level=7,
                types_bitmap=0x003F,
                consent_flags=ConsentFlags.NO_REPLAY | ConsentFlags.NO_STORE,
                privacy_flags=PrivacyFlags.QUANTIZED | PrivacyFlags.TIMING_OBF,
                segment_seq=123,
                dt_ms=20,
                phase=float32(0.25),
                payload_len=693 - 180,
            ),
        ),
        (
            "emo_masked",
            "SF6 (all except EMO), EMO intentionally withheld by sender consent",
            base(sf_level=6, types_bitmap=0x003B, consent_flags=ConsentFlags.EMO_MASKED),
        ),
        (
            "dp_private_ref",
            "DP_LEVEL = L1_PRIVATE_REF",
            base(types_bitmap=0x0009, privacy_flags=2, payload_len=600),
        ),
        (
            "max_lengths",
            "maximum field values; capabilities bits 0-11 + CAPS_EXT_PRESENT",
            base(
                profile=0xFF,
                sf_level=7,
                types_bitmap=0x003F,
                capabilities=0x8FFF,
                timestamp_ns=2**64 - 1,
                segment_seq=2**32 - 1,
                dt_ms=2**32 - 1,
                phase=float32(0.99999994),
                payload_len=2**32 - 1,
                version_minor=0xFF,
            ),
        ),
    ]
    return [
        {"name": n, "description": d, "hex": h.encode().hex(), "fields": header_fields(h)}
        for n, d, h in cases
    ]


def _patch(data: bytes, offset: int, value: bytes) -> bytes:
    return data[:offset] + value + data[offset + len(value) :]


def invalid_header_vectors() -> list[dict[str, Any]]:
    ok = base().encode()
    emo = base(types_bitmap=0x0004).encode()
    v1_timeline = uuid.UUID("c232ab00-9414-11ec-b3c8-9f6bdeced846")
    cases = [
        ("bad_magic", _patch(ok, 0, b"ESQ"), "bad magic"),
        ("version_major_2", _patch(ok, 3, b"\x02"), "version_major"),
        ("profile_zero", _patch(ok, 5, b"\x00"), "profile"),
        ("sf_level_8", _patch(ok, 6, b"\x08"), "sf_level"),
        ("invalid_reserved_byte", _patch(ok, 7, b"\x01"), "reserved byte"),
        ("reserved_type_bit", _patch(ok, 8, b"\x00\x41"), "reserved types_bitmap"),
        ("reserved_consent_bit", _patch(ok, 10, b"\x00\x08"), "reserved consent_flags"),
        ("reserved_privacy_bit", _patch(ok, 12, b"\x00\x40"), "reserved privacy_flags"),
        ("reserved_dp_level", _patch(ok, 12, b"\x00\x04"), "DP_LEVEL"),
        ("reserved_capability_bit", _patch(ok, 14, b"\x10\x00"), "capabilities bits 12-14"),
        ("emo_present_and_masked", _patch(emo, 10, b"\x00\x01"), "mask-bit invariant"),
        ("timeline_not_uuid4", _patch(ok, 24, v1_timeline.bytes), "UUIDv4"),
        ("phase_one", _patch(ok, 48, struct.pack(">f", 1.0)), "phase"),
        ("phase_nan", _patch(ok, 48, bytes.fromhex("7fc00000")), "phase"),
        ("phase_negative_zero", _patch(ok, 48, bytes.fromhex("80000000")), "negative"),
        ("truncated", ok[:99], "exactly 100 bytes"),
        ("too_long", ok + b"\x00", "exactly 100 bytes"),
    ]
    return [{"name": n, "hex": b.hex(), "expect_error": e} for n, b, e in cases]


#: Fixed TEM latent (16 coordinates) used by the latent vectors.
TEM_VALUES = [
    0.0,
    0.5,
    -0.5,
    1.0,
    -1.0,
    0.25,
    -0.25,
    0.125,
    2.0,
    -2.0,
    0.1,
    -0.1,
    3.5,
    -3.5,
    0.0,
    0.75,
]


def valid_latent_vectors() -> list[dict[str, Any]]:
    values = np.array(TEM_VALUES)
    out = []
    for enc in LatentEncoding:
        raw = encode_typed_latent(TaossType.TEM, values, enc)
        out.append(
            {
                "name": f"tem_{enc.name.lower()}",
                "type": "TEM",
                "encoding": enc.name,
                "input_values": TEM_VALUES,
                "hex": raw.hex(),
                "body_len": len(raw) - 5,
            }
        )
    return out


def invalid_latent_vectors() -> list[dict[str, Any]]:
    good = encode_typed_latent(TaossType.TEM, np.array(TEM_VALUES), LatentEncoding.INT8_SYM)
    body = bytearray(good[5:])
    minus128 = bytearray(body)
    minus128[8] = 0x80
    flags = bytearray(body)
    flags[1] = 1
    zero_scale = bytearray(body)
    zero_scale[4:8] = bytes(4)
    f32 = encode_typed_latent(TaossType.TEM, np.array(TEM_VALUES))[5:]
    nan = bytearray(f32)
    nan[8:12] = bytes.fromhex("7fc00000")
    scale2 = bytearray(f32)
    scale2[4:8] = bytes.fromhex("40000000")
    cases = [
        ("int8_minus_128", encode_tlv(0x65, bytes(minus128)), "-128"),
        ("nonzero_flags", encode_tlv(0x65, bytes(flags)), "flags"),
        ("int8_zero_scale", encode_tlv(0x65, bytes(zero_scale)), "scale"),
        ("f32_nan", encode_tlv(0x65, bytes(nan)), "NaN"),
        ("f32_scale_not_one", encode_tlv(0x65, bytes(scale2)), "exactly 1.0"),
        ("wrong_dims", encode_tlv(0x65, bytes(body[:2]) + b"\x00\x0f" + bytes(body[4:-1])), "dims"),
        ("body_too_long", encode_tlv(0x65, bytes(body) + b"\x00"), "length mismatch"),
        ("unknown_encoding", encode_tlv(0x65, b"\x03" + bytes(body[1:])), "encoding"),
        ("truncated_subheader", encode_tlv(0x65, bytes(body[:7])), "truncated"),
    ]
    return [{"name": n, "hex": b.hex(), "expect_error": e} for n, b, e in cases]


def crypto_packet_vectors() -> list[dict[str, Any]]:
    """ESP packet with fixed keys; every intermediate value is exposed (ADR-0009/0010)."""
    k_split = bytes(range(32))
    seed = bytes(32)
    keys = DirectionKeys.from_split_key(k_split)
    signer = SigningKey.from_seed(seed)
    seq = 7
    plaintext = b"abc"
    header = base(
        sf_level=2,
        types_bitmap=0x000B,
        consent_flags=ConsentFlags.EMO_MASKED,
        segment_seq=seq,
        dt_ms=40,
        phase=0.5,
        sender_id=signer.public_bytes,
        nonce=deterministic_nonce(keys, TIMELINE, seq),
    )
    packet = seal_packet(header, plaintext, keys, signer)
    return [
        {
            "name": "deterministic_nonce_packet",
            "k_split": k_split.hex(),
            "k_aead": keys.aead.hex(),
            "k_nonce": keys.nonce.hex(),
            "timeline_id": str(TIMELINE),
            "timeline_tag": timeline_tag(keys, TIMELINE).hex(),
            "segment_seq": seq,
            "nonce": header.nonce.hex(),
            "ed25519_seed": seed.hex(),
            "sender_id": signer.public_bytes.hex(),
            "plaintext": plaintext.hex(),
            "packet_hex": packet.hex(),
            "packet_len": len(packet),
        }
    ]


ISSUER = SigningKey.from_seed(b"\x31" * 32)
RECEIVER = SigningKey.from_seed(b"\x32" * 32)
SESSION = SigningKey.from_seed(b"\x33" * 32)
NOISE_H = blake2b(b"conformance-noise-h")
CAP_ID = uuid.UUID("11111111-2222-4333-8444-555555555555")


def session_vectors() -> list[dict[str, Any]]:
    desc = SessionDescriptor(
        profile=1,
        sf_level=6,
        rate_sensor_mhz=250_000,
        rate_latent_mhz=50_000,
        rate_packet_mhz=50_000,
        registries={"esp-addendum-v1": b"\xa1" * 32, "esp-emo-v13-basic8-v1": b"\xdd" * 32},
    )
    return [
        {
            "name": "descriptor_sf6_two_registries",
            "hex": desc.encode().hex(),
            "digest": desc.digest().hex(),
        }
    ]


def capability_vectors() -> list[dict[str, Any]]:
    sender = SenderCapability(
        CAP_ID,
        0x000B,
        Rights.ALLOW_STORE,
        1000,
        8.0,
        2**62,
        AudienceMode.RECIPIENT_PUBKEY,
        RECEIVER.public_bytes,
        ISSUER.public_bytes,
        b"\x00" * 16,
    )
    receiver = ReceiverCapability(
        0x000F,
        (10.0, 10.0, 10.0, 10.0),
        (-0.5, 1.0),
        50,
        0,
        2**62,
        b"\x01" * 16,
        RECEIVER.public_bytes,
        NOISE_H,
    )
    receiver_no_emo = ReceiverCapability(
        0x0009,
        (10.0, 10.0),
        None,
        50,
        0,
        2**62,
        b"\x01" * 16,
        RECEIVER.public_bytes,
        NOISE_H,
    )
    return [
        {
            "name": "sender_capability",
            "issuer_seed": (b"\x31" * 32).hex(),
            "tlv_hex": sender.sign(ISSUER).encode().hex(),
        },
        {
            "name": "receiver_capability_with_emo",
            "receiver_seed": (b"\x32" * 32).hex(),
            "noise_h": NOISE_H.hex(),
            "tlv_hex": receiver.sign(RECEIVER).encode().hex(),
        },
        {
            "name": "receiver_capability_without_emo",
            "receiver_seed": (b"\x32" * 32).hex(),
            "noise_h": NOISE_H.hex(),
            "tlv_hex": receiver_no_emo.sign(RECEIVER).encode().hex(),
        },
    ]


def revocation_vectors() -> list[dict[str, Any]]:
    intent = RevocationIntent(
        CAP_ID,
        uuid.UUID(int=0),
        0,
        ConsentRevocationReason.CONSENT_WITHDRAWN,
        Effects.REVOKE_FUTURE_USE | Effects.REQUEST_DELETE_STORED,
        ISSUER.public_bytes,
        ISSUER.public_bytes,
    ).sign(ISSUER)
    attestation = DeletionAttestation(
        CAP_ID,
        uuid.UUID(int=0),
        DeletionScope.STORED_CAPSULES,
        request_digest(intent),
        bytes(32),
        123,
        RECEIVER.public_bytes,
    ).sign(RECEIVER)
    return [
        {"name": "consent_withdrawn", "tlv_hex": intent.encode().hex()},
        {
            "name": "deletion_attestation",
            "request_tlv_hex": intent.encode().hex(),
            "tlv_hex": attestation.encode().hex(),
        },
    ]


def identity_vectors() -> list[dict[str, Any]]:
    proof = IdentityProof(ISSUER.public_bytes, NOISE_H, 1_727_000_000).encode(
        ISSUER, SESSION.public_bytes
    )
    return [
        {
            "name": "identity_proof",
            "pk_session": SESSION.public_bytes.hex(),
            "noise_h": NOISE_H.hex(),
            "tlv_hex": proof.encode().hex(),
        },
        {
            "name": "session_binding",
            "session_seed": (b"\x33" * 32).hex(),
            "noise_h": NOISE_H.hex(),
            "tlv_hex": session_binding(SESSION, NOISE_H).encode().hex(),
        },
    ]


def replay_vectors() -> list[dict[str, Any]]:
    """Sequences with the expected accept (1) / reject (0) outcome, W_back=1024, W_fwd=128."""
    sequences = [
        [0, 1, 2, 2, 1],
        [127, 128, 255, 383, 511, 639, 767, 895, 1023, 1151, 127, 1151 - 1023, 1151 - 1024],
        [0, 200],
        [5, 3, 4, 3, 133, 134],
    ]
    out = []
    for i, seq in enumerate(sequences):
        w = ReplayWindow(w_back=1024, w_fwd=128)
        expected = []
        for s in seq:
            try:
                w.accept(s)
                expected.append(1)
            except ReplayError:
                expected.append(0)
        out.append(
            {
                "name": f"window_{i}",
                "w_back": 1024,
                "w_fwd": 128,
                "sequence": seq,
                "accept": expected,
            }
        )
    return out


def dp_vectors() -> list[dict[str, Any]]:
    """V13 section 12 reference accounting (L1-BALANCED, C = 1, delta_tot = 1e-6)."""
    sigma = REFERENCE_PROFILES[DpLevel.L1_BALANCED_REF][1]
    five = [TaossType.KNO, TaossType.INT, TaossType.CTX, TaossType.SEN, TaossType.TEM]
    c_type = rdp_coefficient({TaossType.EMO: 1.0}, {TaossType.EMO: sigma})
    c_joint = rdp_coefficient(dict.fromkeys(five, 1.0), dict.fromkeys(five, sigma))
    eps_type, alpha_type = epsilon_rdp(100 * c_type, 1e-6)
    eps_joint, alpha_joint = epsilon_rdp(100 * c_joint, 1e-6)
    sigma32 = float(np.float32(sigma))
    params = DpParams(
        capability_id=CAP_ID,
        adjacency=Adjacency.FRAME,
        segment_window=0,
        clip_norms=dict.fromkeys(five, 1.0),
        sigmas=dict.fromkeys(five, sigma32),
        composition_k=100,
        epsilon_spent=float(np.float32(eps_joint)),
        delta_target=1e-6,
    )
    return [
        {
            "name": "l1_balanced_reference",
            "eps_per_release": 0.5,
            "delta_per_release": 1e-8,
            "sigma": sigma,
            "k": 100,
            "delta_total": 1e-6,
            "per_type": {"eps": eps_type, "alpha": alpha_type},
            "joint_5_types": {"eps": eps_joint, "alpha": alpha_joint},
            "tlv_hex": params.encode().encode().hex(),
            "tlv_body_len": 82,
        },
        {
            "name": "l1_private_reference",
            "eps_per_release": 0.1,
            "delta_per_release": 1e-8,
            "sigma": REFERENCE_PROFILES[DpLevel.L1_PRIVATE_REF][1],
        },
    ]


def xcf_vectors() -> list[dict[str, Any]]:
    from esp.xcf.capsule import CapsuleSpec, EnvelopeAlg, PrivateBody, seal  # noqa: PLC0415
    from esp.xcf.gate import gated_access  # noqa: PLC0415

    out: list[dict[str, Any]] = []
    parent = bytes(32)
    for i, name in enumerate(("genesis_gated_cek", "child_gated_cek")):
        seed = bytes([0x40 + i]) * 32
        inputs = {
            "cek": bytes([0x50 + i]) * 32,
            "nonce": bytes([0x60 + i]) * 12,
            "gate_id": bytes([0x70 + i]) * 16,
            "gate_secret": bytes([0x80 + i]) * 32,
            "wrap_nonce": bytes([0x90 + i]) * 12,
        }
        spec = CapsuleSpec(
            types_bitmap=0x000B,
            encoder_id=uuid.UUID("11111111-1111-4111-8111-111111111111"),
            anchor_set_id=uuid.UUID("22222222-2222-4222-8222-222222222222"),
            created_ns=1_727_000_000_000_000_000 + i,
            packets_count=3,
            dp_eps_spent=0.5,
            dp_delta=float(np.float32(1e-6)),
            parent_cid=parent,
        )
        body = PrivateBody(
            policy_id=uuid.UUID("33333333-3333-4333-8333-333333333333"),
            timeline_id=uuid.UUID("44444444-4444-4444-8444-444444444444"),
            payload=b"typed-latent TLVs",
        )
        capsule, _ = seal(
            spec,
            body,
            envelope_alg=EnvelopeAlg.GATED_CEK,
            access_material=gated_access(
                inputs["gate_id"], inputs["gate_secret"], inputs["wrap_nonce"]
            ),
            capsule_key=SigningKey.from_seed(seed),
            cek=inputs["cek"],
            nonce=inputs["nonce"],
        )
        out.append(
            {
                "name": name,
                "signer_seed": seed.hex(),
                **{k: v.hex() for k, v in inputs.items()},
                "parent_cid": parent.hex(),
                "created_ns": spec.created_ns,
                "policy_id": str(body.policy_id),
                "timeline_id": str(body.timeline_id),
                "payload_hex": body.payload.hex(),
                "header_hex": capsule.raw[:148].hex(),
                "capsule_hex": capsule.raw.hex(),
                "capsule_sig": capsule.raw[-64:].hex(),
                "cid": capsule.cid.hex(),
            }
        )
        parent = capsule.cid
    return out


def hive_vectors() -> list[dict[str, Any]]:
    """Typed-Hive TLVs 0x70-0x73 (ADR-0021), including invalid inputs a parser must reject."""
    from esp.codec.tlv import Tlv  # noqa: PLC0415
    from esp.crypto.signed import sign_tlv  # noqa: PLC0415
    from esp.hive import frost  # noqa: PLC0415
    from esp.hive.episode import contribution_commitment  # noqa: PLC0415
    from esp.hive.membership import identified_proof, identified_ref  # noqa: PLC0415
    from esp.hive.tlv import (  # noqa: PLC0415
        CollectiveIntent,
        ExitPolicy,
        HiveContribution,
        HiveExit,
        HiveGrant,
        MembershipMode,
        Operator,
        PrivacyMode,
        Rule,
    )

    master = SigningKey.from_seed(b"\x70" * 32)
    member = SigningKey.from_seed(b"\x71" * 32)
    episode = uuid.UUID("70707070-7070-4070-8070-707070707070")
    base = SenderCapability(
        uuid.UUID("71717171-7171-4171-8171-717171717171"),
        0x000F,
        Rights(0),
        1000,
        8.0,
        2**62,
        AudienceMode.RECIPIENT_PUBKEY,
        member.public_bytes,
        master.public_bytes,
        b"\x72" * 16,
    )
    grant = HiveGrant(
        capability_id=base.capability_id,
        episode_id=episode,
        hive_types=0x000F,
        emergence_types=0x0001,
        privacy_mode=PrivacyMode.SECAGG_DISTRIBUTED,
        membership_mode=MembershipMode.IDENTIFIED,
        lambda_max=(0.5, 0.0, 0.0, 0.25),
        epsilon_member=(2.0, 0.5, 2.0, 2.0),
        delta_member=float(np.float32(1e-5)),
        op_id=(
            Operator.COVARIANCE_INTERSECTION,
            Operator.SOCIAL_CHOICE,
            Operator.EMO_DP_HISTOGRAM,
            Operator.PROVENANCE_UNION,
        ),
        min_group=5,
        quorum_min=3,
        rule_id=Rule.EXPONENTIAL_MECHANISM,
        exit_policy=ExitPolicy.NEXT_ROUND,
        membership_root=bytes(32),
        valid_until_ns=2**61,
    )
    grant_tlv = grant.sign(master)
    ref = identified_ref(episode, member.public_bytes)
    x = np.array([0.5, -0.25, 0.125, 1.0])
    opening = b"\x73" * 32
    commitment = contribution_commitment(episode, TaossType.KNO, 1, x, opening)
    c0 = HiveContribution(episode, ref, 1, commitment, b"")
    contribution = HiveContribution(episode, ref, 1, commitment, identified_proof(member, c0))
    x0 = HiveExit(episode, ref, b"")
    exit_obj = HiveExit(episode, ref, identified_proof(member, x0))
    # FROST group of the RFC 9591 E.1 vector (3 guardians, threshold 2), fixed nonces.
    group, shares = frost.trusted_dealer_keygen(
        3,
        2,
        int.from_bytes(
            bytes.fromhex("7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304"),
            "little",
        ),
        [
            int.from_bytes(
                bytes.fromhex("178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204"),
                "little",
            )
        ],
    )
    intent = CollectiveIntent(
        episode_id=episode,
        capsule_cid=b"\x74" * 32,
        rule_id=Rule.EXPONENTIAL_MECHANISM,
        epsilon_used=0.5,
        n_contributors=5,
        member_ref_root=b"\x75" * 32,
        group_key_id=frost.group_key_id(group.group_public),
    )
    msg = intent.signing_message()
    signers = [shares[0], shares[2]]
    rounds = [
        frost.commit(s, (bytes([0x76 + i]) * 32, bytes([0x78 + i]) * 32))
        for i, s in enumerate(signers)
    ]
    comms = [c for _, c in rounds]
    z = {
        s.identifier: frost.sign(s, n, msg, comms)
        for s, (n, _) in zip(signers, rounds, strict=True)
    }
    cic_tlv = intent.encode(frost.aggregate(group, comms, msg, z))
    # invalid: a grant widening the base types (SEN not in base 0x000F), validly signed
    wide = HiveGrant(
        **{
            **{f: getattr(grant, f) for f in grant.__dataclass_fields__},
            "hive_types": 0x001F,
            "lambda_max": (*grant.lambda_max, 0.0),
            "epsilon_member": (*grant.epsilon_member, 0.5),
            "op_id": (*grant.op_id, Operator.SEN_COMPOSITION),
        }
    )
    # invalid: EMO lambda_max != 0 (bytes patched, re-signed, so only the rule is violated)
    body = bytearray(grant.body())
    emo_lambda_offset = 39 + 4 * 2  # lambda_max[EMO] is the third per-type float
    body[emo_lambda_offset : emo_lambda_offset + 4] = struct.pack(">f", 0.25)
    emo_mixing = sign_tlv(0x70, bytes(body), master)
    good_c = contribution.encode().encode()
    return [
        {
            "name": "hive_grant",
            "master_seed": (b"\x70" * 32).hex(),
            "base_capability_tlv_hex": base.sign(master).encode().hex(),
            "tlv_hex": grant_tlv.encode().hex(),
        },
        {
            "name": "hive_contribution_identified",
            "member_seed": (b"\x71" * 32).hex(),
            "episode_id": str(episode),
            "member_ref": ref.hex(),
            "type": "KNO",
            "round": 1,
            "state": x.tolist(),
            "opening": opening.hex(),
            "commitment": commitment.hex(),
            "tlv_hex": good_c.hex(),
        },
        {
            "name": "hive_exit_identified",
            "member_seed": (b"\x71" * 32).hex(),
            "tlv_hex": exit_obj.encode().encode().hex(),
        },
        {
            "name": "collective_intent_frost",
            "group_public_key": group.group_public.hex(),
            "signers": [1, 3],
            "signing_message": msg.hex(),
            "tlv_hex": cic_tlv.encode().hex(),
        },
        {
            "name": "grant_widens_base",
            "base_capability_tlv_hex": base.sign(master).encode().hex(),
            "tlv_hex": wide.sign(master).encode().hex(),
            "expect_error": "widens the base capability types",
        },
        {
            "name": "grant_emo_mixing",
            "tlv_hex": emo_mixing.encode().hex(),
            "expect_error": "EMO lambda_max must be 0",
        },
        {
            "name": "contribution_truncated",
            "tlv_hex": Tlv(0x71, good_c[5:-1]).encode().hex(),
            "expect_error": "proof length mismatch",
        },
        {
            "name": "contribution_trailing_byte",
            "tlv_hex": Tlv(0x71, good_c[5:] + b"\x00").encode().hex(),
            "expect_error": "proof length mismatch",
        },
        {
            "name": "collective_intent_short",
            "tlv_hex": Tlv(0x73, cic_tlv.value[:-1]).encode().hex(),
            "expect_error": "malformed COLLECTIVE_INTENT",
        },
    ]


def documents() -> dict[Path, dict[str, Any]]:
    meta = {
        "suite_version": SUITE_VERSION,
        "spec": "ESP V13 Appendix A; ADR-0010, ADR-0017",
        "license": "CC-BY-4.0",
        "header_len": HEADER_LEN,
    }
    return {
        OUT / "wire" / "header_valid.json": meta | {"vectors": valid_header_vectors()},
        OUT / "malformed" / "header_invalid.json": meta | {"vectors": invalid_header_vectors()},
        OUT / "wire" / "latent_valid.json": meta
        | {"spec": "ESP V13 section 8.4", "vectors": valid_latent_vectors()},
        OUT / "malformed" / "latent_invalid.json": meta
        | {"spec": "ESP V13 section 8.4", "vectors": invalid_latent_vectors()},
        OUT / "crypto" / "packet_valid.json": meta
        | {
            "spec": "ESP V13 section 9.2; ADR-0009, ADR-0010",
            "vectors": crypto_packet_vectors(),
        },
        OUT / "session" / "descriptor.json": meta
        | {"spec": "ADR-0012", "vectors": session_vectors()},
        OUT / "consent" / "capabilities.json": meta
        | {"spec": "ESP V13 section 9.7; ADR-0015", "vectors": capability_vectors()},
        OUT / "consent" / "revocation.json": meta
        | {"spec": "ESP V13 section 9.7", "vectors": revocation_vectors()},
        OUT / "identity" / "bindings.json": meta
        | {"spec": "ESP V13 section 9.4; ADR-0013", "vectors": identity_vectors()},
        OUT / "replay" / "windows.json": meta
        | {"spec": "ESP V13 section 9.5; ADR-0016", "vectors": replay_vectors()},
        OUT / "privacy" / "dp_accounting.json": meta
        | {"spec": "ESP V13 section 12; ADR-0018", "vectors": dp_vectors()},
        OUT / "xcf" / "capsules.json": meta
        | {
            "spec": "ESP V13 XCF v1 (148-byte header, CID, capsule_sig); GAP-018",
            "vectors": xcf_vectors(),
        },
        OUT / "hive" / "tlvs.json": meta
        | {
            "spec": "ESP V13 Typed Hive protocol objects 0x70-0x73; ADR-0021; RFC 9591",
            "vectors": hive_vectors(),
        },
    }


def render(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def with_index(docs: dict[Path, dict[str, Any]]) -> dict[Path, dict[str, Any]]:
    """Add vectors/INDEX.json: suite version, file list and BLAKE2b-256 of each file."""
    files = {
        str(path.relative_to(OUT)): blake2b(render(doc).encode()).hex()
        for path, doc in sorted(docs.items())
    }
    index = {"suite_version": SUITE_VERSION, "license": "CC-BY-4.0", "files": files}
    return docs | {OUT / "INDEX.json": index}


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = []
    for path, doc in with_index(documents()).items():
        text = render(doc)
        if check:
            if not path.exists() or path.read_text(encoding="utf-8") != text:
                stale.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
    if stale:
        print(f"stale vectors: {', '.join(stale)}")
        return 1
    print("vectors up to date" if check else "vectors written")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
