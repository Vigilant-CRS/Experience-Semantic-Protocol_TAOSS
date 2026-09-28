# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-014 conformance: golden header vectors (V13 Appendix A)."""

import json
import struct
import uuid
from pathlib import Path
from typing import Any

import pytest

from esp.codec.errors import WireError
from esp.codec.header import Header

VECTORS = Path(__file__).resolve().parents[2] / "vectors"
VALID = json.loads((VECTORS / "wire" / "header_valid.json").read_text())["vectors"]
INVALID = json.loads((VECTORS / "malformed" / "header_invalid.json").read_text())["vectors"]

pytestmark = pytest.mark.conformance


def test_required_golden_vectors_exist() -> None:
    names = {v["name"] for v in VALID} | {v["name"] for v in INVALID}
    for required in ("minimal", "all_types", "emo_masked", "invalid_reserved_byte", "max_lengths"):
        assert required in names


@pytest.mark.parametrize("vector", VALID, ids=lambda v: v["name"])
def test_valid_vectors_decode_and_reencode_exactly(vector: dict[str, Any]) -> None:
    raw = bytes.fromhex(vector["hex"])
    assert len(raw) == 100
    h = Header.decode(raw)
    f = vector["fields"]
    assert h.encode() == raw
    assert (h.version_major, h.version_minor, h.profile, h.sf_level) == (
        f["version_major"],
        f["version_minor"],
        f["profile"],
        f["sf_level"],
    )
    assert (h.types_bitmap, h.consent_flags, h.privacy_flags, h.capabilities) == (
        f["types_bitmap"],
        f["consent_flags"],
        f["privacy_flags"],
        f["capabilities"],
    )
    assert (h.timestamp_ns, h.segment_seq, h.dt_ms, h.payload_len) == (
        f["timestamp_ns"],
        f["segment_seq"],
        f["dt_ms"],
        f["payload_len"],
    )
    assert h.timeline_id == uuid.UUID(f["timeline_id"])
    assert struct.pack(">f", h.phase).hex() == f["phase_f32_hex"]
    assert (h.sender_id.hex(), h.nonce.hex()) == (f["sender_id"], f["nonce"])


@pytest.mark.parametrize("vector", INVALID, ids=lambda v: v["name"])
def test_invalid_vectors_rejected(vector: dict[str, Any]) -> None:
    with pytest.raises(WireError, match=vector["expect_error"]):
        Header.decode(bytes.fromhex(vector["hex"]))


def test_semantics_of_emo_masked_vector() -> None:
    h = Header.decode(bytes.fromhex(next(v for v in VALID if v["name"] == "emo_masked")["hex"]))
    assert h.emo_masked
    assert [t.name for t in h.types] == ["KNO", "INT", "CTX", "SEN", "TEM"]
