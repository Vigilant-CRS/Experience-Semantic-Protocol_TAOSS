# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Deterministic vehicle-to-driver handover simulator and reference adapter (WP-066).

A synthetic automated vehicle approaches a hazard and must hand control back to
the driver. Everything is seeded and runs without hardware:

- ``S`` (sensors): speed [m/s], distance to hazard [m], road friction, sensor
  confidence, lateral offset [m], traffic density;
- ``U`` (actions): steering [rad], brake [0..1];
- ``M`` (task model): planned lane change [0/1], time to handover [s], route progress.

:class:`HandoverAdapter` is a *reference* ``g_mach``. Summary features go
through fixed, documented random projections (``esp-meb-handover-sim``). This is a
placeholder with the right output contract, **not** a trained machine encoder.
It emits the ``MEB-HANDOVER`` type set {INT, CTX, TEM, SEN}: no KNO, never EMO.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

import numpy as np
from numpy.typing import NDArray

from esp.core.taoss_types import L1_DIMS, TaossType

F64 = NDArray[np.float64]
ADAPTER_ID: Final = "esp-meb-handover-sim@0.1.0"
DT_S: Final = 0.1
SENSOR_CHANNELS: Final = (
    "speed",
    "distance",
    "friction",
    "confidence",
    "lateral_offset",
    "traffic",
)
ACTION_CHANNELS: Final = ("steering", "brake")
TASK_CHANNELS: Final = ("lane_change", "time_to_handover", "route_progress")


@dataclass(frozen=True, slots=True)
class HandoverScenario:
    sensors: F64
    actions: F64
    task: F64

    @property
    def steps(self) -> int:
        return int(self.sensors.shape[0])

    def time_to_collision_s(self) -> float:
        """Distance / speed at the last step (inf when stopped)."""
        speed, dist = self.sensors[-1, 0], self.sensors[-1, 1]
        return float(dist / speed) if speed > 1e-6 else float("inf")


def simulate(seed: int, *, steps: int = 50, hazard: bool = True) -> HandoverScenario:
    """One reproducible approach. ``hazard=False`` gives an uneventful cruise."""
    if steps < 2:
        msg = "a scenario needs at least two steps"
        raise ValueError(msg)
    rng = np.random.default_rng(seed)
    speed0 = rng.uniform(20.0, 33.0)
    dist0 = rng.uniform(120.0, 250.0) if hazard else 1e4
    friction = rng.uniform(0.35, 0.95)
    traffic = rng.uniform(0.0, 1.0)
    lane_change = float(hazard and rng.random() < 0.5)
    brake = np.clip(
        np.linspace(0.0, 0.6 if hazard else 0.0, steps) + rng.normal(0, 0.02, steps), 0, 1
    )
    speed = np.maximum(speed0 - np.cumsum(brake * 6.0 * friction * DT_S), 0.0)
    dist = np.maximum(dist0 - np.cumsum(speed * DT_S), 0.0)
    confidence = np.clip(0.95 - (0.4 if hazard else 0.0) * np.linspace(0, 1, steps), 0, 1)
    confidence = np.clip(confidence + rng.normal(0, 0.01, steps), 0, 1)
    lateral = np.cumsum(rng.normal(0, 0.02, steps)) + lane_change * np.linspace(0, 3.5, steps)
    steering = np.gradient(lateral) * 0.5
    ttc = np.where(speed > 1e-6, dist / np.maximum(speed, 1e-6), 1e3)
    time_to_handover = np.clip(ttc - 4.0, 0.0, 60.0)
    progress = np.linspace(0.0, 1.0, steps) * rng.uniform(0.2, 1.0)
    sensors = np.stack(
        [speed, dist, np.full(steps, friction), confidence, lateral, np.full(steps, traffic)], 1
    )
    actions = np.stack([steering, brake], axis=1)
    task = np.stack([np.full(steps, lane_change), time_to_handover, progress], axis=1)
    return HandoverScenario(sensors, actions, task)


def _projection(t: TaossType, n_in: int) -> F64:
    seed = int.from_bytes(
        hashlib.blake2b(f"{ADAPTER_ID}/{t.name}".encode(), digest_size=8).digest()
    )
    return np.random.default_rng(seed).normal(0.0, 1.0, size=(L1_DIMS[t], n_in))


def summary_features(sensors: F64, actions: F64, task: F64) -> dict[TaossType, F64]:
    """Interpretable per-type summaries before projection (used by decoders and tests)."""
    speed, dist, friction, conf, lateral, traffic = sensors[-1]
    ttc = dist / speed if speed > 1e-6 else 1e3
    urgency = 1.0 / (1.0 + max(ttc, 0.0))
    return {
        TaossType.INT: np.array(
            [task[-1, 0], float(np.mean(actions[:, 0])), float(actions[-1, 1]), lateral / 3.5]
        ),
        TaossType.CTX: np.array([speed / 40.0, min(dist, 300.0) / 300.0, friction, traffic]),
        TaossType.TEM: np.array([min(task[-1, 1], 60.0) / 60.0, sensors.shape[0] * DT_S / 10.0]),
        TaossType.SEN: np.array([urgency, conf, 1.0 - conf]),
    }


class HandoverAdapter:
    """Reference ``g_mach`` for the MEB-HANDOVER profile."""

    adapter_id = ADAPTER_ID
    types: frozenset[TaossType] = frozenset(
        {TaossType.INT, TaossType.CTX, TaossType.TEM, TaossType.SEN}
    )

    def encode(self, sensors: F64, actions: F64, task: F64) -> Mapping[TaossType, F64]:
        if sensors.ndim != 2 or sensors.shape[1] != len(SENSOR_CHANNELS):
            msg = f"sensors must have shape (T, {len(SENSOR_CHANNELS)})"
            raise ValueError(msg)
        if actions.shape != (sensors.shape[0], len(ACTION_CHANNELS)) or task.shape != (
            sensors.shape[0],
            len(TASK_CHANNELS),
        ):
            msg = "actions and task model must be aligned with the sensor stream"
            raise ValueError(msg)
        out: dict[TaossType, F64] = {}
        for t, f in summary_features(sensors, actions, task).items():
            z = np.tanh(_projection(t, f.size) @ f)
            out[t] = z / max(float(np.linalg.norm(z)), 1e-12)
        return out
