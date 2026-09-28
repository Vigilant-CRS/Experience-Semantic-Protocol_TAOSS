# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M3 gate: byte-exact ESP v1 (plan section 54, M3 + section 54a additions).

Gate: wire golden vectors, crypto vectors, replay tests, consent tests,
fuzz smoke. Critical test: a single changed header bit causes an
authentication failure. The full evidence runs via ``run_milestone.py M3``,
which executes this file together with the conformance, crypto, replay,
consent and fuzz suites.
"""

import re
import uuid
from pathlib import Path

import pytest

from esp.codec.errors import WireError
from esp.codec.header import Header
from esp.crypto.envelope import open_packet, seal_packet
from esp.crypto.keys import DirectionKeys, deterministic_nonce
from esp.crypto.primitives import CryptoError, SigningKey

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]

M3_WORK_PACKAGES = (
    "WP-014",
    "WP-015",
    "WP-016",
    "WP-017",
    "WP-018",
    "WP-019",
    "WP-020",
    "WP-021",
    "WP-022",
    "WP-048",
    "WP-051",
    "WP-052",
    "WP-054",
    "WP-056",
    "WP-061",
    "WP-065",
)
M3_GAPS = ("GAP-002", "GAP-003", "GAP-005", "GAP-006", "GAP-008", "GAP-009", "GAP-011")


def test_critical_single_header_bit_fails_authentication() -> None:
    keys = DirectionKeys.from_split_key(b"\x44" * 32)
    signer = SigningKey.from_seed(b"\x45" * 32)
    timeline = uuid.UUID("5f0c6a8e-3b7d-4c4e-9a53-2f6a1d9e8b10")
    header = Header(
        profile=1,
        sf_level=7,
        types_bitmap=0x3F,
        consent_flags=0,
        privacy_flags=0,
        capabilities=0,
        timestamp_ns=1,
        timeline_id=timeline,
        segment_seq=9,
        dt_ms=20,
        phase=0.25,
        sender_id=signer.public_bytes,
        payload_len=0,
        nonce=deterministic_nonce(keys, timeline, 9),
    )
    packet = seal_packet(header, b"x" * 64, keys, signer)
    for bit in range(800):
        tampered = bytearray(packet)
        tampered[bit // 8] ^= 1 << (bit % 8)
        with pytest.raises((CryptoError, WireError)):
            open_packet(
                bytes(tampered), keys, expected_sender=signer.public_bytes, max_payload_len=4096
            )


def test_all_m3_work_packages_verified_in_plan() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    for wp in M3_WORK_PACKAGES:
        section = re.search(rf"^## {wp} — .*?\*\*Status:\*\* `([A-Z_]+)`", plan, re.S | re.M)
        assert section is not None, wp
        assert section.group(1) == "VERIFIED", f"{wp} is {section.group(1)}"


def test_m3_gaps_resolved() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    for gap in M3_GAPS:
        row = re.search(rf"^\| {gap} \|.*\| (\w+) \|$", plan, re.M)
        assert row is not None, gap
        assert row.group(1) == "RESOLVED", f"{gap} is {row.group(1)}"
