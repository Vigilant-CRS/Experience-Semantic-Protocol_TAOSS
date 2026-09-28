# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-021: the versioned conformance vector suite.

Vectors are produced by ``scripts/generate_test_vectors.py`` from our own
codecs, so these tests additionally check the bytes *independently* against
the V13 field layouts (offsets written out by hand from the spec).
"""

import hashlib
import json
import struct
import uuid
from pathlib import Path
from typing import Any

import pytest

from esp.codec.tlv import iter_tlvs
from esp.consent.capability import ReceiverCapability, SenderCapability
from esp.consent.revocation import DeletionAttestation, RevocationIntent
from esp.crypto.identity import IdentityProof, verify_session_binding
from esp.crypto.primitives import ed25519_verify
from esp.session.descriptor import SessionDescriptor
from esp.session.replay import ReplayError, ReplayWindow

pytestmark = pytest.mark.conformance
VECTORS = Path(__file__).resolve().parents[2] / "vectors"


def load(rel: str) -> list[dict[str, Any]]:
    return json.loads((VECTORS / rel).read_text())["vectors"]


def tlv(hex_: str):  # type: ignore[no-untyped-def]
    items = iter_tlvs(bytes.fromhex(hex_))
    assert len(items) == 1
    return items[0]


def test_index_lists_every_file_with_its_digest() -> None:
    index = json.loads((VECTORS / "INDEX.json").read_text())
    assert index["suite_version"] == "1.0.0"
    on_disk = {str(p.relative_to(VECTORS)) for p in VECTORS.rglob("*.json")} - {"INDEX.json"}
    assert set(index["files"]) == on_disk
    for rel, digest in index["files"].items():
        assert hashlib.blake2b((VECTORS / rel).read_bytes(), digest_size=32).hexdigest() == digest


def test_every_vector_file_is_versioned_and_licensed() -> None:
    for path in VECTORS.rglob("*.json"):
        doc = json.loads(path.read_text())
        assert doc["license"] == "CC-BY-4.0", path
        assert doc["suite_version"] == "1.0.0", path


def test_sender_capability_matches_v13_layout() -> None:
    v = next(x for x in load("consent/capabilities.json") if x["name"] == "sender_capability")
    raw = bytes.fromhex(v["tlv_hex"])
    # t u8 | length u32 | version u8 | capability_id[16] | types_allowed u16 | rights u8 |
    # max_segments u64 | dp_epsilon_ceiling f32 | valid_until_ns u64 | audience_mode u8 |
    # audience_value[32] | issuer_pk[32] | nonce[16] | sig[64]
    assert raw[0] == 0x22
    assert struct.unpack(">I", raw[1:5])[0] == len(raw) - 5 == 121 + 64
    assert raw[5] == 1
    assert uuid.UUID(bytes=raw[6:22]) == uuid.UUID("11111111-2222-4333-8444-555555555555")
    assert struct.unpack(">H", raw[22:24])[0] == 0x000B
    assert raw[24] == 0b10  # ALLOW_STORE only
    assert struct.unpack(">Q", raw[25:33])[0] == 1000
    assert struct.unpack(">f", raw[33:37])[0] == 8.0
    assert raw[45] == 0  # audience_mode RECIPIENT_PUBKEY
    issuer = raw[78:110]
    assert len(raw[110:126]) == 16  # nonce
    ed25519_verify(issuer, b"esp/v1/capability" + raw[: len(raw) - 64], raw[-64:])
    assert SenderCapability.verify(tlv(v["tlv_hex"])).issuer_pk == issuer


@pytest.mark.parametrize(
    "name", ["receiver_capability_with_emo", "receiver_capability_without_emo"]
)
def test_receiver_capability_layout_and_optional_valence(name: str) -> None:
    v = next(x for x in load("consent/capabilities.json") if x["name"] == name)
    raw = bytes.fromhex(v["tlv_hex"])
    accept = struct.unpack(">H", raw[6:8])[0]
    n_types = raw[8]
    assert n_types == bin(accept).count("1")
    emo = bool(accept & 0x4)
    expected_body = 4 + 4 * n_types + (8 if emo else 0) + 2 + 8 + 8 + 16 + 32 + 32 + 64
    assert len(raw) - 5 == expected_body
    pk_r = raw[-64 - 64 : -64 - 32]
    ed25519_verify(pk_r, b"esp/v1/receiver-capability" + raw[:-64], raw[-64:])
    cap = ReceiverCapability.verify(tlv(v["tlv_hex"]), noise_h=bytes.fromhex(v["noise_h"]))
    assert (cap.valence_bounds is not None) == emo


def test_revocation_and_attestation_vectors() -> None:
    by_name = {v["name"]: v for v in load("consent/revocation.json")}
    raw = bytes.fromhex(by_name["consent_withdrawn"]["tlv_hex"])
    # version | capability_id[16] | timeline_id[16] | revoke_from_seq u64 | reason u8 | effects u8 |
    # capability_issuer_pk[32] | signer_pk[32] | sig[64]
    assert raw[0] == 0x23
    assert raw[22:38] == bytes(16)  # capability scope
    assert raw[46] == 1  # CONSENT_WITHDRAWN
    assert raw[47] == 0b0011
    signer = raw[80:112]
    ed25519_verify(signer, b"esp/v1/revocation" + raw[:-64], raw[-64:])
    RevocationIntent.verify(tlv(by_name["consent_withdrawn"]["tlv_hex"]))
    att = by_name["deletion_attestation"]
    DeletionAttestation.verify(tlv(att["tlv_hex"]), request=tlv(att["request_tlv_hex"]))


def test_identity_vectors_follow_v13_messages() -> None:
    by_name = {v["name"]: v for v in load("identity/bindings.json")}
    proof = by_name["identity_proof"]
    raw = bytes.fromhex(proof["tlv_hex"])
    pk_m, noise_h, epoch, sig = raw[5:37], raw[37:69], raw[69:77], raw[77:]
    message = b"esp/v1/identity-proof" + bytes.fromhex(proof["pk_session"]) + noise_h + epoch
    ed25519_verify(pk_m, message, sig)  # exactly the V13 section 9.4 message
    IdentityProof.verify(
        tlv(proof["tlv_hex"]),
        pk_session=bytes.fromhex(proof["pk_session"]),
        noise_h=bytes.fromhex(proof["noise_h"]),
    )
    binding = by_name["session_binding"]
    assert verify_session_binding(
        tlv(binding["tlv_hex"]), noise_h=bytes.fromhex(binding["noise_h"])
    )


def test_session_descriptor_vector() -> None:
    v = load("session/descriptor.json")[0]
    desc = SessionDescriptor.decode(bytes.fromhex(v["hex"]))
    assert desc.encode().hex() == v["hex"]
    assert desc.digest().hex() == v["digest"]
    assert desc.sf_level == 6


@pytest.mark.parametrize("vector", load("replay/windows.json"), ids=lambda v: v["name"])
def test_replay_window_vectors(vector: dict[str, Any]) -> None:
    w = ReplayWindow(w_back=vector["w_back"], w_fwd=vector["w_fwd"])
    got = []
    for s in vector["sequence"]:
        try:
            w.accept(s)
            got.append(1)
        except ReplayError:
            got.append(0)
    assert got == vector["accept"]


def test_dp_accounting_vectors_match_v13_text() -> None:
    import math  # noqa: PLC0415

    from esp.codec.tlv import iter_tlvs as _iter  # noqa: PLC0415
    from esp.privacy.dp import DpParams  # noqa: PLC0415

    ref = load("privacy/dp_accounting.json")[0]
    assert math.isclose(ref["sigma"], 24.42, abs_tol=0.01)  # V13: "approx 24.42"
    assert math.isclose(ref["per_type"]["eps"], 4.6, abs_tol=0.05)  # V13: "approx 4.6"
    assert math.isclose(ref["per_type"]["alpha"], 7.4, abs_tol=0.05)  # V13: "alpha approx 7.4"
    assert math.isclose(ref["joint_5_types"]["eps"], 11.3, abs_tol=0.05)  # V13: "approx 11.3"
    assert math.isclose(ref["joint_5_types"]["alpha"], 3.87, abs_tol=0.01)  # V13: "approx 3.87"
    params = DpParams.decode(_iter(bytes.fromhex(ref["tlv_hex"]))[0])
    assert len(bytes.fromhex(ref["tlv_hex"])) - 5 == ref["tlv_body_len"] == 82
    assert params.composition_k == 100
    priv = load("privacy/dp_accounting.json")[1]
    assert math.isclose(priv["sigma"], 122.13, abs_tol=0.01)  # V13: "approx 122.13"
