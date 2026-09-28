# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M2 gate: deterministic simulation (plan section 54, M2).

1. 1,000 synthetic episodes.
2. Identical seeds produce byte-/value-identical ground truth.
3. OracleEstimator reproduces the targets.
4. Clock-drift and dropout fixtures work.
"""

import numpy as np
import pytest

from esp.estimators.base import EstimationContext
from esp.estimators.oracle import OracleEstimator
from esp.evidence.claim import ClaimType
from esp.simulation.engine import simulate
from esp.simulation.spec import EpisodeSpec

pytestmark = pytest.mark.milestone

N_EPISODES = 1_000
PREFIX = {
    ClaimType.EMOTION_CATEGORY: "emotion.",
    ClaimType.ACTION_READINESS: "readiness.",
    ClaimType.CONTEXT: "context.",
}


def random_spec(i: int) -> EpisodeSpec:
    rng = np.random.default_rng(i)
    n_keys = int(rng.integers(1, 4))
    times = [
        0.0,
        *sorted(float(x) for x in rng.choice(np.arange(1, 20) / 10, n_keys - 1, replace=False)),
    ]
    keyframes = [
        {
            "t_s": t,
            "emotion": {"fear": float(rng.random()), "joy": float(rng.random())},
            "readiness": {"avoid": float(rng.random())},
            "valence": float(rng.uniform(-1, 1)),
        }
        for t in times
    ]
    return EpisodeSpec.from_data(
        {
            "name": f"m2-{i}",
            "seed": i,
            "duration_s": 2.0,
            "frame_rate_hz": 5.0,
            "keyframes": keyframes,
            "streams": [
                {
                    "modality": "ecg",
                    "channel": "heart_rate",
                    "unit": "bpm",
                    "rate_hz": 10.0,
                    "base": 70.0,
                    "terms": [{"quantity": "emotion.fear", "gain": 30.0}],
                    "noise_sd": 1.0,
                    "dropout_prob": float(rng.uniform(0, 0.3)),
                    "device_id": "sim-ecg",
                    "clock": {
                        "domain": "sim:ecg",
                        "drift_ppm": float(rng.uniform(-200, 200)),
                        "offset_ns": int(rng.integers(0, 10**7)),
                    },
                }
            ],
        }
    )


def test_m2_thousand_episodes_deterministic_and_oracle_exact() -> None:
    dropouts = 0
    for i in range(N_EPISODES):
        spec = random_spec(i)
        a, b = simulate(spec), simulate(spec)
        assert a.ground_truth_bytes() == b.ground_truth_bytes()
        assert a.observation_bytes() == b.observation_bytes()
        oracle = OracleEstimator(a)
        for point in a.ground_truth:
            claims = oracle.estimate((), EstimationContext(at_ns=point.t_ns)).claims
            got = {
                (
                    c.claim
                    if c.claim_type is ClaimType.AFFECT_DIMENSION
                    else PREFIX[c.claim_type] + c.claim
                ): c.value
                for c in claims
            }
            assert got == dict(point.values)
        for o in a.observations:
            drift = spec.streams[0].clock.drift_ppm
            offset = spec.streams[0].clock.offset_ns
            assert (
                o.timestamp.source_ns
                == round(o.timestamp.monotonic_ns * (1 + drift * 1e-6)) + offset
            )
            dropouts += o.quality.dropout
    assert dropouts > 0
