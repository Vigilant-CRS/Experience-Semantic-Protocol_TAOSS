# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-066: machine adapter contract and the vehicle handover simulator."""

import uuid
from collections.abc import Mapping

import numpy as np
import pytest

from esp.core.taoss_types import L1_DIMS, TaossType
from esp.meb.adapter import machine_frame, validate_output
from esp.meb.handover import ADAPTER_ID, HandoverAdapter, simulate, summary_features
from esp.meb.profiles import SURGICAL, VEHICLE_HANDOVER, MebError

pytestmark = pytest.mark.security
T = TaossType
TL = uuid.UUID("11111111-1111-4111-8111-111111111111")


def test_simulator_is_deterministic_and_physical() -> None:
    a, b = simulate(7), simulate(7)
    for x, y in ((a.sensors, b.sensors), (a.actions, b.actions), (a.task, b.task)):
        np.testing.assert_array_equal(x, y)
    assert not np.array_equal(simulate(8).sensors, a.sensors)
    hazard, cruise = simulate(3, steps=80), simulate(3, steps=80, hazard=False)
    assert hazard.time_to_collision_s() < cruise.time_to_collision_s()
    assert np.all(np.diff(hazard.sensors[:, 1]) <= 0)  # distance to the hazard shrinks
    assert np.all(hazard.sensors[:, 0] >= 0)  # speed never negative
    with pytest.raises(ValueError, match="two steps"):
        simulate(1, steps=1)


def test_handover_adapter_output_contract() -> None:
    sc = simulate(1)
    out = HandoverAdapter().encode(sc.sensors, sc.actions, sc.task)
    assert set(out) == {T.INT, T.CTX, T.TEM, T.SEN}
    latents = validate_output(HandoverAdapter(), out)
    for t, v in latents.items():
        assert len(v) == L1_DIMS[t]
        assert np.isclose(np.linalg.norm(v), 1.0)
    # urgency grows as time to collision shrinks
    early = summary_features(sc.sensors[:5], sc.actions[:5], sc.task[:5])[T.SEN][0]
    late = summary_features(sc.sensors, sc.actions, sc.task)[T.SEN][0]
    assert late > early
    with pytest.raises(ValueError, match="sensors"):
        HandoverAdapter().encode(sc.sensors[:, :3], sc.actions, sc.task)
    with pytest.raises(ValueError, match="aligned"):
        HandoverAdapter().encode(sc.sensors, sc.actions[:-1], sc.task)


def test_machine_frame_masks_emo_and_omits_kno() -> None:
    sc = simulate(2)
    frame = machine_frame(
        HandoverAdapter(),
        sc.sensors,
        sc.actions,
        sc.task,
        profile=VEHICLE_HANDOVER,
        timeline_id=TL,
        sequence=1,
        now_ns=5,
    )
    assert set(frame.present_types) == {T.INT, T.CTX, T.TEM, T.SEN}
    assert frame.masked_types == (T.EMO,)
    assert T.KNO not in frame.present_types
    assert frame.provenance.encoder_id == ADAPTER_ID
    VEHICLE_HANDOVER.type_set.check(frozenset(frame.present_types), frozenset(frame.masked_types))


def test_machine_frame_requires_the_profile_types() -> None:
    sc = simulate(2)
    with pytest.raises(MebError, match="requires"):
        machine_frame(
            HandoverAdapter(),
            sc.sensors,
            sc.actions,
            sc.task,
            profile=SURGICAL,  # needs KNO, which the handover adapter never produces
            timeline_id=TL,
            sequence=1,
            now_ns=5,
        )


class _Adapter:
    adapter_id = "test-adapter@1.0.0"

    def __init__(self, types: frozenset[TaossType], out: Mapping[TaossType, np.ndarray]):
        self.types = types
        self._out = out

    def encode(self, sensors: np.ndarray, actions: np.ndarray, task: np.ndarray):  # type: ignore[no-untyped-def]
        return self._out


def _unit(t: TaossType) -> np.ndarray:
    v = np.zeros(L1_DIMS[t])
    v[0] = 1.0
    return v


def test_adapter_contract_violations() -> None:
    good = {T.INT: _unit(T.INT), T.CTX: _unit(T.CTX)}
    validate_output(_Adapter(frozenset(good), good), good)
    with pytest.raises(MebError, match="never author EMO"):  # declares EMO
        validate_output(_Adapter(frozenset({T.INT, T.EMO}), good), good)
    emo = good | {T.EMO: _unit(T.EMO)}
    with pytest.raises(MebError, match="never author EMO"):  # produces EMO undeclared
        validate_output(_Adapter(frozenset(good), emo), emo)
    extra = good | {T.SEN: _unit(T.SEN)}
    with pytest.raises(MebError, match="declares"):  # silently extra type
        validate_output(_Adapter(frozenset(good), extra), extra)
    bad = {T.INT: np.zeros(3), T.CTX: _unit(T.CTX)}
    with pytest.raises(MebError, match="shape"):
        validate_output(_Adapter(frozenset(good), bad), bad)
    nan = {T.INT: np.full(L1_DIMS[T.INT], np.nan), T.CTX: _unit(T.CTX)}
    with pytest.raises(MebError, match="finite"):
        validate_output(_Adapter(frozenset(good), nan), nan)
