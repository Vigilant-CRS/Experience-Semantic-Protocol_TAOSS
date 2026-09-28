# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""0x70-0x73 codecs: exact layouts, narrowing-only grants, EMO mixing, strict parsing."""

import dataclasses
import json
import struct
import uuid
from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv, iter_tlvs
from esp.conformance.runner import _hive
from esp.consent.capability import SenderCapability
from esp.consent.revocation import RevocationRegistry
from esp.core.taoss_types import TaossType as T
from esp.core.taoss_types import types_to_bitmap
from esp.crypto.primitives import CryptoError, SigningKey
from esp.crypto.signed import sign_tlv
from esp.hive import frost
from esp.hive.episode import frost_sign_intent
from esp.hive.simulation import NOW, base_capability, grant_for
from esp.hive.tlv import (
    CIC_LEN,
    MAX_PROOF_LEN,
    CollectiveIntent,
    HiveContribution,
    HiveError,
    HiveExit,
    HiveGrant,
    MembershipMode,
    Operator,
    Rule,
    verify_collective_intent,
    verify_grant,
)

pytestmark = pytest.mark.security
ROOT = Path(__file__).resolve().parents[3]
MASTER = SigningKey.from_seed(b"\x51" * 32)
EP = uuid.UUID("51515151-5151-4151-8151-515151515151")


def fresh() -> tuple[SenderCapability, HiveGrant]:
    cap, _ = base_capability(MASTER, b"\x01" * 32)
    return cap, grant_for(cap, EP)


def test_grant_layout_and_roundtrip() -> None:
    cap, g = fresh()
    tlv = g.sign(MASTER)
    n = len(g.types)
    assert len(tlv.value) == 153 + 9 * n
    assert HiveGrant.parse(tlv) == g
    assert verify_grant(tlv, cap, now_ns=NOW) == g
    # canonical ADR-0015 signature input
    body = g.body()
    assert tlv.value[: len(body)] == body


def test_grant_signed_by_other_key_rejected() -> None:
    cap, g = fresh()
    with pytest.raises(CryptoError):
        verify_grant(g.sign(SigningKey.from_seed(b"\x52" * 32)), cap, now_ns=NOW)


def test_widening_grant_rejected() -> None:
    master = SigningKey.from_seed(b"\x53" * 32)
    cap, _ = base_capability(master, b"\x01" * 32)
    narrow = dataclasses.replace(cap, types_allowed=types_to_bitmap((T.KNO, T.CTX)))
    g = grant_for(narrow, EP, types=(T.KNO, T.CTX, T.SEN))
    with pytest.raises(HiveError, match="widens"):
        verify_grant(g.sign(master), narrow, now_ns=NOW)
    ok = grant_for(narrow, EP, types=(T.KNO, T.CTX))
    assert verify_grant(ok.sign(master), narrow, now_ns=NOW).types == (T.KNO, T.CTX)


def test_grant_cannot_outlive_or_outspend_base() -> None:
    cap, g = fresh()
    late = dataclasses.replace(g, valid_until_ns=cap.valid_until_ns + 1)
    with pytest.raises(HiveError, match="outlives"):
        verify_grant(late.sign(MASTER), cap, now_ns=NOW)
    poor = dataclasses.replace(cap, dp_epsilon_ceiling=1.0)
    with pytest.raises(HiveError, match="budget"):
        verify_grant(g.sign(MASTER), poor, now_ns=NOW)
    with pytest.raises(HiveError, match="expired"):
        verify_grant(g.sign(MASTER), cap, now_ns=g.valid_until_ns + 1)
    other = dataclasses.replace(g, capability_id=uuid.uuid4())
    with pytest.raises(HiveError, match="another base"):
        verify_grant(other.sign(MASTER), cap, now_ns=NOW)


def test_revoked_base_capability_invalidates_grant() -> None:
    cap, g = fresh()
    reg = RevocationRegistry()
    reg.revoked_capabilities.add(cap.capability_id.bytes)
    with pytest.raises(HiveError, match="revoked"):
        verify_grant(g.sign(MASTER), cap, now_ns=NOW, revocations=reg)


def test_emo_mixing_nonzero_rejected() -> None:
    _, g = fresh()
    i = g.types.index(T.EMO)
    lam = list(g.lambda_max)
    lam[i] = 0.25
    with pytest.raises(HiveError, match="EMO lambda_max must be 0"):
        dataclasses.replace(g, lambda_max=tuple(lam))
    # also when smuggled in on the wire (validly signed)
    body = bytearray(g.body())
    struct.pack_into(">f", body, 39 + 4 * i, 0.25)
    with pytest.raises(HiveError, match="EMO"):
        HiveGrant.parse(sign_tlv(0x70, bytes(body), MASTER))


def test_emo_centroid_operator_rejected() -> None:
    _, g = fresh()
    ops = list(g.op_id)
    ops[g.types.index(T.EMO)] = Operator.COVARIANCE_INTERSECTION  # a mean-like fusion
    with pytest.raises(HiveError, match="not allowed for EMO"):
        dataclasses.replace(g, op_id=tuple(ops))


@pytest.mark.parametrize(
    ("change", "match"),
    [
        ({"emergence_types": 0}, "emergence_types"),
        ({"emergence_types": T.SEN.bit}, "emergence_types"),
        ({"min_group": 1}, "min_group"),
        ({"quorum_min": 0}, "INT grant"),
        ({"rule_id": Rule.NONE}, "INT grant"),
        ({"delta_member": 1.0}, "delta_member"),
        ({"membership_mode": MembershipMode.ANONYMOUS}, "membership_root"),
        ({"episode_id": uuid.UUID(int=0)}, "non-zero"),
    ],
)
def test_grant_field_rules(change: dict[str, object], match: str) -> None:
    _, g = fresh()
    with pytest.raises((WireError, HiveError), match=match):
        dataclasses.replace(g, **change)


def test_no_int_means_no_quorum() -> None:
    cap, _ = fresh()
    g = grant_for(cap, EP, types=(T.KNO, T.CTX))
    assert (g.quorum_min, g.rule_id) == (0, Rule.NONE)
    with pytest.raises(WireError, match="without INT"):
        dataclasses.replace(g, quorum_min=3)


def test_grant_parse_rejects_bad_lengths() -> None:
    _, g = fresh()
    raw = g.sign(MASTER).value
    for bad in (raw[:-1], raw + b"\x00", raw[:10]):
        with pytest.raises(WireError):
            HiveGrant.parse(Tlv(0x70, bad))
    wrong_n = bytearray(raw)
    wrong_n[36] ^= 1  # n_types no longer popcount(hive_types)
    with pytest.raises(WireError, match="n_types"):
        HiveGrant.parse(Tlv(0x70, bytes(wrong_n)))


def test_contribution_and_exit_layouts() -> None:
    c = HiveContribution(EP, b"\x02" * 32, 7, b"\x03" * 32, b"proof")
    raw = c.encode().value
    assert len(raw) == 92 + 5
    assert raw[:16] == EP.bytes
    assert raw[16:48] == b"\x02" * 32
    assert struct.unpack(">Q", raw[48:56]) == (7,)
    assert struct.unpack(">I", raw[88:92]) == (5,)
    assert HiveContribution.decode(c.encode()) == c
    x = HiveExit(EP, b"\x02" * 32, b"pp")
    assert len(x.encode().value) == 52 + 2
    assert HiveExit.decode(x.encode()) == x


@settings(max_examples=200, deadline=None)
@given(st.binary(max_size=200))
def test_contribution_parser_total(data: bytes) -> None:
    for code, cls in ((0x71, HiveContribution), (0x72, HiveExit)):
        try:
            obj = cls.decode(Tlv(code, data))  # type: ignore[attr-defined]
        except WireError:
            continue
        assert obj.encode().value == data  # accepted inputs are canonical


def test_proof_bounds() -> None:
    with pytest.raises(WireError, match="profile maximum"):
        HiveContribution(EP, b"\x02" * 32, 1, b"\x03" * 32, b"x" * (MAX_PROOF_LEN + 1))
    head = EP.bytes + b"\x02" * 32 + struct.pack(">Q", 1) + b"\x03" * 32
    overflow = head + struct.pack(">I", 2**32 - 1) + b"abc"
    with pytest.raises(WireError, match="proof length"):
        HiveContribution.decode(Tlv(0x71, overflow))


def test_collective_intent_frost_verifies_as_ed25519() -> None:
    group, shares = frost.trusted_dealer_keygen(5, 3)
    cic = CollectiveIntent(
        EP,
        b"\x04" * 32,
        Rule.MAJORITY_BINARY,
        0.0,
        5,
        b"\x05" * 32,
        frost.group_key_id(group.group_public),
    )
    tlv = frost_sign_intent(cic, group, shares[1:4])
    assert len(tlv.value) == CIC_LEN == 169
    assert verify_collective_intent(tlv, group.group_public) == cic
    other, _ = frost.trusted_dealer_keygen(5, 3)
    with pytest.raises(HiveError, match="group_key_id"):
        verify_collective_intent(tlv, other.group_public)
    bad = bytearray(tlv.value)
    bad[20] ^= 1
    with pytest.raises(CryptoError):
        verify_collective_intent(Tlv(0x73, bytes(bad)), group.group_public)


def test_collective_intent_needs_rule() -> None:
    with pytest.raises(WireError, match="rule"):
        CollectiveIntent(EP, b"\x04" * 32, Rule.NONE, 0.0, 5, b"\x05" * 32, b"\x06" * 16)


def test_golden_vectors_are_reproduced() -> None:
    doc = json.loads((ROOT / "vectors" / "hive" / "tlvs.json").read_text())
    assert doc["license"] == "CC-BY-4.0"
    names = {v["name"] for v in doc["vectors"]}
    assert {
        "hive_grant",
        "hive_contribution_identified",
        "hive_exit_identified",
        "collective_intent_frost",
    } <= names
    for v in doc["vectors"]:
        _hive(v)  # valid ones verify, invalid ones are refused for the stated reason
    grant = next(v for v in doc["vectors"] if v["name"] == "hive_grant")
    (tlv,) = iter_tlvs(bytes.fromhex(grant["tlv_hex"]))
    assert tlv.code == 0x70
