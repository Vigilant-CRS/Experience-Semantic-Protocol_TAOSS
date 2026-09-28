# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M13 gate: machine and agent governance (WP-066, WP-067).

- machines cannot authorize EMO (negative tests);
- M2H defaults are intersected with the receiver capability;
- two agents exchange INT/CTX/KNO over ESP with an event audit;
- the handover simulator runs with the ``MEB-HANDOVER`` profile.

Details in ``tests/unit/meb``, ``tests/unit/agent``,
``tests/integration/test_meb_endpoint.py`` and
``tests/integration/test_agent_profile.py``.
"""

import uuid

import pytest

from esp.agent.demo import run_agent_demo
from esp.consent.capability import ReceiverPolicy
from esp.core.taoss_types import TaossType
from esp.meb.adapter import machine_frame
from esp.meb.handover import HandoverAdapter, simulate
from esp.meb.profiles import (
    DOMAIN_PROFILES,
    VEHICLE_HANDOVER,
    MebError,
    check_machine_types,
    m2h_types,
)

pytestmark = pytest.mark.milestone
T = TaossType


def test_machines_cannot_authorize_emo() -> None:
    with pytest.raises(MebError):
        check_machine_types({T.INT, T.EMO})
    for profile in DOMAIN_PROFILES.values():
        assert T.EMO not in profile.types
        assert profile.type_set.must_mask == {T.EMO}


def test_m2h_defaults_intersect_receiver_capability() -> None:
    assert m2h_types(None) == {T.KNO, T.CTX}
    assert m2h_types(ReceiverPolicy.default_deny()) == {T.KNO, T.CTX}


def test_handover_simulator_with_meb_handover_profile() -> None:
    sc = simulate(42)
    frame = machine_frame(
        HandoverAdapter(),
        sc.sensors,
        sc.actions,
        sc.task,
        profile=VEHICLE_HANDOVER,
        timeline_id=uuid.uuid4(),
        sequence=1,
        now_ns=1,
    )
    assert set(frame.present_types) == {T.INT, T.CTX, T.TEM, T.SEN}
    assert frame.masked_types == (T.EMO,)


def test_two_agents_exchange_over_esp_with_event_audit() -> None:
    r = run_agent_demo()
    assert r.audit.passed, r.audit.problems
    assert r.reports[0]["taoss_types"] == ["KNO", "INT", "CTX"]
    assert r.reports[1]["consent_guarantees"] is None  # opaque is never TAOSS
    assert r.refused  # INT without capability is refused
