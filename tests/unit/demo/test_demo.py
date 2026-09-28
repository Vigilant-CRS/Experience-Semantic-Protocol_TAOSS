# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-025 / WP-082: demo frame composer and wire inspector."""

import uuid

import numpy as np
import pytest

from esp.core.taoss_types import TaossType
from esp.demo.compose import ENCODER_ID, DemoState, compose_frame
from esp.demo.inspector import SOURCE_URL, render
from esp.session.profiles import CUSTOM_PROFILES, custom_profile_digest

T = TaossType
TL = uuid.UUID("11111111-1111-4111-8111-111111111111")
STATE = DemoState(
    emotions={"fear": 5},
    valence=1,
    readiness={"avoid": 4},
    context=("work",),
    knowledge=("topic_a",),
)


def test_composer_is_deterministic_and_structured() -> None:
    a = compose_frame(STATE, timeline_id=TL, sequence=3, now_ns=10**18)
    b = compose_frame(STATE, timeline_id=TL, sequence=3, now_ns=10**18)
    assert a == b
    assert a.present_types == (T.KNO, T.INT, T.EMO, T.CTX)
    assert a.provenance.encoder_id == ENCODER_ID
    emo = a.block(T.EMO)
    assert emo is not None
    assert emo.latent is not None
    assert np.isclose(np.linalg.norm(emo.latent), 1.0)
    fear = {c.anchor_id: c.similarity for c in emo.anchors}["esp:emo:fear:v1"]
    assert fear == 1.0  # rating 5 on 1..5
    assert len(a.bindings) == 1


def test_different_inputs_give_different_latents() -> None:
    a = compose_frame(STATE, timeline_id=TL, sequence=1, now_ns=1)
    calm = DemoState(emotions={"joy": 4}, valence=5, context=("home",), knowledge=("topic_b",))
    b = compose_frame(calm, timeline_id=TL, sequence=1, now_ns=1)
    for t in (T.KNO, T.EMO, T.CTX):
        ba, bb = a.block(t), b.block(t)
        assert ba is not None
        assert bb is not None
        assert ba.latent != bb.latent


def test_unknown_emotion_label_is_refused() -> None:
    with pytest.raises(ValueError, match="basic-8"):
        compose_frame(
            DemoState(emotions={"schadenfreude": 3}), timeline_id=TL, sequence=1, now_ns=1
        )


def test_no_binding_without_knowledge() -> None:
    frame = compose_frame(DemoState(emotions={"fear": 2}), timeline_id=TL, sequence=1, now_ns=1)
    assert frame.bindings == ()


def test_demo_profile_digest_pins_the_definition() -> None:
    assert CUSTOM_PROFILES["esp-typeset-demo-v1"].required == frozenset({T.KNO, T.INT, T.CTX})
    assert custom_profile_digest("esp-typeset-demo-v1") != custom_profile_digest(
        "esp-typeset-meb-handover-v1"
    )


def test_inspector_escapes_log_content_and_carries_source_link() -> None:
    evil = "<script>alert(1)</script>"
    events = [
        {"event": "session_start", "session": 1},
        {"event": "session_refused", "session": 1, "reason": evil},
        {
            "event": "packet",
            "session": 1,
            "channel": "STATE",
            "accepted": False,
            "violations": [evil],
            "wire_header": {"types": ["KNO", "EMO"], "emo_masked": False, "segment_seq": 0},
            "plaintext_tlv_codes": ["0x60", "0x62"],
            "frame": None,
        },
    ]
    page = render(events, [])
    assert "<script>" not in page
    assert "&lt;script&gt;" in page
    assert SOURCE_URL in page
    assert "LATENT EMO" in page
    assert '<span class="chip emo">yes</span>' in page  # EMO flagged when present
