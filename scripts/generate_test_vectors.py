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

from esp.codec.header import HEADER_LEN, ConsentFlags, Header, PrivacyFlags, float32
from esp.codec.tlv import LatentEncoding, encode_tlv, encode_typed_latent
from esp.core.taoss_types import TaossType
from esp.crypto.envelope import seal_packet
from esp.crypto.keys import DirectionKeys, deterministic_nonce, timeline_tag
from esp.crypto.primitives import SigningKey

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
    }


def render(doc: dict[str, Any]) -> str:
    return json.dumps(doc, indent=2, sort_keys=True) + "\n"


def main(argv: list[str]) -> int:
    check = "--check" in argv
    stale = []
    for path, doc in documents().items():
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
