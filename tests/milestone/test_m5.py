# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M5 gate: BCI-free post-linguistic demo with two independent processes.

Sender and receiver run as separate OS processes over QUIC. The test only
reads their logs (receiver events, sender packet capture) and checks the
gate sequence: connect, negotiate, consent, share KNO+INT+CTX, mask EMO,
wire-inspect, EMO absent, add EMO consent, EMO present, revoke EMO, future
EMO rejected.
"""

import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]
#: Every wire object that carries EMO content (ADR-0011, ADR-0014 in this demo).
EMO_CODES = {"0x62", "0x92", "0x93", "0x50"}


def _jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.fixture(scope="module")
def run(
    tmp_path_factory: pytest.TempPathFactory,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    d = tmp_path_factory.mktemp("m5")
    cmd = [sys.executable, "-m", "esp.demo"]
    env = os.environ | {"PYTHONPATH": str(ROOT / "src")}
    subprocess.run([*cmd, "init", str(d / "keys")], check=True, env=env, timeout=60)
    events = d / "recv.jsonl"
    receiver = subprocess.Popen(
        [*cmd, "receive", str(d / "keys"), "--port", "0", "--events", str(events)], env=env
    )
    try:
        deadline = time.monotonic() + 30
        while not (events.exists() and events.read_text(encoding="utf-8").strip()):
            assert time.monotonic() < deadline, "receiver did not start"
            time.sleep(0.1)
        port = _jsonl(events)[0]["port"]
        subprocess.run(
            [
                *cmd,
                "send",
                str(d / "keys"),
                "--port",
                str(port),
                "--capture",
                str(d / "send.jsonl"),
            ],
            check=True,
            env=env,
            timeout=120,
        )
        assert receiver.wait(timeout=60) == 0
    finally:
        if receiver.poll() is None:
            receiver.kill()
    for secret in (
        d / "keys" / "sender" / "master.seed",
        d / "keys" / "receiver" / "identity.seed",
    ):
        assert secret.stat().st_mode & 0o077 == 0  # private keys are owner-only
    return _jsonl(events), _jsonl(d / "send.jsonl")


def packets(
    events: list[dict[str, Any]], session: int, channel: str = "STATE"
) -> list[dict[str, Any]]:
    return [
        e
        for e in events
        if e["event"] == "packet" and e["session"] == session and e["channel"] == channel
    ]


def captured(capture: list[dict[str, Any]], step: str) -> list[dict[str, Any]]:
    return [c for c in capture if c["event"] == "captured" and c["step"] == step]


def test_m5_work_package_verified() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    m = re.search(r"^## WP-025 — .*?\*\*Status:\*\* `([A-Z_]+)`", plan, re.S | re.M)
    assert m is not None
    assert m.group(1) == "VERIFIED"


def test_steps_1_to_3_connect_negotiate_consent(run: tuple[list, list]) -> None:
    events, capture = run
    active = [e["session"] for e in events if e["event"] == "session_active"]
    assert active == [1, 2, 4]  # session 3 used a revoked capability
    assert [c["session"] for c in capture if c["event"] == "session_active"] == [1, 2, 3, 4]


def test_steps_4_to_7_share_mask_inspect_emo_absent(run: tuple[list, list]) -> None:
    events, capture = run
    (p,) = packets(events, 1)
    assert p["accepted"]
    assert p["frame"]["present_types"] == ["KNO", "INT", "CTX"]
    assert p["frame"]["masked_types"] == ["EMO"]
    assert p["frame"]["bindings"] == []  # the EMO->KNO binding cannot outlive masked EMO
    assert p["frame"]["affect_descriptors"] == 0
    # wire inspection: header (cleartext) and the decrypted payload's TLV codes
    (wire,) = captured(capture, "share_without_emo_consent")
    assert "EMO" not in wire["header"]["types"]
    assert wire["header"]["emo_masked"] is True
    assert not EMO_CODES & set(p["plaintext_tlv_codes"])  # EMO really removed, not hidden
    assert p["frame"]["provenance"]["encoder_id"].startswith("esp-demo-projection")


def test_steps_8_9_emo_consent_makes_emo_appear(run: tuple[list, list]) -> None:
    events, _ = run
    with_binding, binding_masked = packets(events, 2)
    for p in (with_binding, binding_masked):
        assert p["accepted"]
        assert p["frame"]["present_types"] == ["KNO", "INT", "EMO", "CTX"]
        assert {"0x62", "0x92", "0x50"} <= set(p["plaintext_tlv_codes"])
        assert p["frame"]["emo_anchor_coordinates"] == 8
    assert with_binding["frame"]["bindings"] == [
        {"relation": "elicited_by", "source": "EMO", "target": "KNO"}
    ]
    assert binding_masked["frame"]["bindings"] == []  # binding masked separately
    assert "0x90" not in binding_masked["plaintext_tlv_codes"]


def test_steps_10_11_revoke_emo_then_future_emo_rejected(run: tuple[list, list]) -> None:
    events, capture = run
    (revocation,) = packets(events, 2, "CONTROL")
    assert revocation["accepted"]
    assert revocation["control"] == ["0x23"]
    refused = [c for c in capture if c["event"] == "send_refused"]
    assert [c["step"] for c in refused] == ["emo_after_revoke"]  # sender stops itself
    # reusing the revoked capability: the receiver refuses the session, nothing is decoded
    (s3,) = [e for e in events if e["event"] == "session_refused"]
    assert s3["session"] == 3
    assert "revoked" in s3["reason"]
    assert captured(capture, "revoked_capability_reused")  # it really was attempted
    assert packets(events, 3) == []
    # afterwards the EMO-free capability is still valid and EMO stays masked
    (p,) = packets(events, 4)
    assert p["accepted"]
    assert p["frame"]["masked_types"] == ["EMO"]
    assert not EMO_CODES & set(p["plaintext_tlv_codes"])
    ends = {e["session"]: e["decoder_invocations"] for e in events if e["event"] == "session_end"}
    assert ends == {1: 1, 2: 2, 4: 1}  # decoder ran only for accepted frames


def test_decoder_transparency_panel(run: tuple[list, list]) -> None:
    """WP-059: absence is reported as intentional masking, never decoded as zero."""
    events, _ = run
    (s1,) = packets(events, 1)
    panel = s1["decoded"]["transparency"]
    assert s1["decoded"]["outputs"]["demo-emotion-label@1"] == {"text": "<EMO absent>"}
    assert panel["decoders"][0]["absent_graceful"] == [{"intentional": True, "type": "EMO"}]
    assert "EMO" in panel["cannot_reconstruct"]
    emo_on = packets(events, 2)[0]
    assert emo_on["decoded"]["outputs"]["demo-emotion-label@1"] == {"text": "fear"}
    assert "EMO" not in emo_on["decoded"]["transparency"]["cannot_reconstruct"]
