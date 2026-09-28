# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-082: interactive consent inspector (logic + HTTP smoke test)."""

import itertools
import json
import threading
import urllib.request
from typing import Any

import pytest

from esp.demo.inspector import SOURCE_URL
from esp.demo.ui import make_server, run_exchange

BASE: dict[str, Any] = {
    "emotions": {"fear": 4},
    "valence": 2,
    "arousal": 4,
    "avoid": 5,
    "context": "work",
    "knowledge": "k1",
    "share_binding": True,
    "receiver_types": ["KNO", "INT", "EMO", "CTX"],
}


def test_emo_appears_only_with_both_consents() -> None:
    for s_emo, r_emo in itertools.product([False, True], repeat=2):
        req = BASE | {
            "sender_types": ["KNO", "INT", "CTX"] + (["EMO"] if s_emo else []),
            "receiver_types": ["KNO", "INT", "CTX"] + (["EMO"] if r_emo else []),
        }
        out = run_exchange(req)
        assert out["ok"], out
        assert out["emo_in_plaintext"] == (s_emo and r_emo)
        assert ("EMO" in out["wire"]["header"]["types"]) == (s_emo and r_emo)
        frame = out["frame"]
        assert ("EMO" in frame["masked_types"]) != (s_emo and r_emo)
        panel = out["decoded"]["transparency"]
        assert ("EMO" in panel["cannot_reconstruct"]) != (s_emo and r_emo)


def test_binding_switch_is_separate() -> None:
    both = BASE | {"sender_types": ["KNO", "INT", "EMO", "CTX"]}
    assert run_exchange(both)["frame"]["bindings"]
    assert run_exchange(both | {"share_binding": False})["frame"]["bindings"] == []


def test_unconsentable_profile_and_bad_input_are_reported_not_raised() -> None:
    no_kno = run_exchange(BASE | {"sender_types": ["INT", "CTX"]})
    assert no_kno["ok"] is False
    assert no_kno["stage"] == "establishment"
    assert "KNO" in no_kno["error"]
    for bad in (
        {"valence": 9},
        {"emotions": {"schadenfreude": 3}},
        {"sender_types": ["XYZ"]},
        {"context": "x" * 100},
        {"valence": True},
    ):
        out = run_exchange(BASE | {"sender_types": ["KNO"]} | bad)
        assert out == out | {"ok": False, "stage": "input"}


@pytest.fixture
def server():  # type: ignore[no-untyped-def]
    srv = make_server(0)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def test_http_page_and_run_endpoint(server: str) -> None:
    with urllib.request.urlopen(server + "/", timeout=10) as r:
        page = r.read().decode()
        assert r.headers["Content-Security-Policy"].startswith("default-src 'self'")
    assert SOURCE_URL in page
    assert 'name="s" value="EMO"' in page
    body = json.dumps(BASE | {"sender_types": ["KNO", "INT", "CTX"]}).encode()
    req = urllib.request.Request(
        server + "/run", data=body, headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        out = json.loads(r.read())
    assert out["ok"]
    assert out["emo_in_plaintext"] is False
    bad = urllib.request.Request(server + "/run", data=b"[1,2]")
    with pytest.raises(urllib.error.HTTPError) as err:
        urllib.request.urlopen(bad, timeout=10)
    assert err.value.code == 400
    err.value.close()  # release the socket held by the error response
