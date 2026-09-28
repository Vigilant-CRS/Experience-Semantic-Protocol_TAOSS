# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-012 acceptance tests: deterministic seed, reproducible episode, oracle target."""

import math
from pathlib import Path

import pytest
from pydantic import ValidationError

from esp.observation.model import check_stream_ordering
from esp.simulation.engine import ground_truth_at, simulate
from esp.simulation.spec import EpisodeSpec, load_episode_yaml

EXAMPLE = (
    Path(__file__).resolve().parents[3]
    / "examples"
    / "synthetic_sender_receiver"
    / "fear_at_work.yaml"
)


def spec(**overrides: object) -> EpisodeSpec:
    base = load_episode_yaml(EXAMPLE)
    return EpisodeSpec.from_data(base.model_dump(mode="json") | overrides)


def test_example_loads() -> None:
    s = load_episode_yaml(EXAMPLE)
    assert s.name == "fear-at-work"
    assert len(s.streams) == 2


def test_same_seed_is_byte_identical() -> None:
    a, b = simulate(spec()), simulate(spec())
    assert a.ground_truth_bytes() == b.ground_truth_bytes()
    assert a.observation_bytes() == b.observation_bytes()
    assert (a.episode_id, a.timeline_id) == (b.episode_id, b.timeline_id)


def test_different_seed_changes_noise_not_truth_values() -> None:
    a, b = simulate(spec()), simulate(spec(seed=43))
    assert [p.values for p in a.ground_truth] == [p.values for p in b.ground_truth]
    assert a.observation_bytes() != b.observation_bytes()


def test_adding_a_stream_does_not_change_existing_streams() -> None:
    one = spec()
    only_first = EpisodeSpec.from_data(
        one.model_dump(mode="json") | {"streams": [one.streams[0].model_dump(mode="json")]}
    )
    a = [o for o in simulate(one).observations if o.channel == "heart_rate"]
    b = list(simulate(only_first).observations)
    assert [o.canonical_json() for o in a] == [o.canonical_json() for o in b]


def test_interpolation_is_exact_at_keyframes_and_linear_between() -> None:
    s = spec()
    assert ground_truth_at(s.keyframes, 0.0)["emotion.fear"] == 0.2
    assert ground_truth_at(s.keyframes, 5.0)["emotion.fear"] == 0.8
    assert math.isclose(ground_truth_at(s.keyframes, 2.5)["emotion.fear"], 0.5)
    assert ground_truth_at(s.keyframes, 9.9)["emotion.fear"] == 0.5  # held after last


def test_observations_are_valid_synthetic_and_ordered() -> None:
    ep = simulate(spec())
    assert all(o.device.synthetic for o in ep.observations)
    assert check_stream_ordering(ep.observations) == []
    assert len([o for o in ep.observations if o.channel == "heart_rate"]) == 40
    assert len([o for o in ep.observations if o.channel == "scl"]) == 80


def test_dropout_fixture() -> None:
    ep = simulate(spec(streams=[spec().streams[0].model_dump(mode="json") | {"dropout_prob": 0.5}]))
    dropped = [o for o in ep.observations if o.quality.dropout]
    assert 5 < len(dropped) < 35
    assert all(o.value is None for o in dropped)


def test_clock_drift_fixture() -> None:
    ep = simulate(
        spec(
            streams=[
                spec().streams[1].model_dump(mode="json")
                | {"clock": {"domain": "sim:eda", "drift_ppm": 100.0, "offset_ns": 5000}}
            ]
        )
    )
    last = ep.observations[-1].timestamp
    expected = round(last.monotonic_ns * (1 + 100e-6)) + 5000
    assert last.source_ns == expected
    assert last.source_ns - last.monotonic_ns > 900_000  # ~1 ms drift after ~10 s


def test_spec_validation() -> None:
    with pytest.raises(ValidationError, match="first keyframe"):
        spec(keyframes=[{"t_s": 1.0, "emotion": {"fear": 0.1}}])
    with pytest.raises(ValidationError, match="same quantities"):
        spec(
            keyframes=[
                {"t_s": 0.0, "emotion": {"fear": 0.1}},
                {"t_s": 1.0, "emotion": {"joy": 0.1}},
            ]
        )
    with pytest.raises(ValidationError, match="unknown quantity"):
        spec(keyframes=[{"t_s": 0.0, "emotion": {"joy": 0.1}}])
    with pytest.raises(ValidationError):
        spec(seed=-1)
    with pytest.raises(ValueError, match="exactly one top-level key"):
        load_episode_yaml("foo: 1\n")
