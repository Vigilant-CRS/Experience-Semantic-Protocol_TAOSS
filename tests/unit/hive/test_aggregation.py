# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Secure aggregation + distributed noise, EMO histogram, fusion and social choice."""

import math

import numpy as np
import pytest

from esp.hive.aggregation import (
    AffectDistribution,
    MemberInput,
    RoundAborted,
    SecAggMember,
    covariance_intersection,
    emo_histogram,
    exponential_mechanism,
    from_fixed,
    inverse_variance,
    majority_binary,
    masked_sum,
    rdp_epsilon,
    secure_round,
    to_fixed,
)
from esp.hive.tlv import HiveError

pytestmark = pytest.mark.security


def test_masks_cancel_exactly_and_hide_inputs() -> None:
    rng = np.random.default_rng(0)
    xs = [rng.normal(size=6) for _ in range(5)]
    members = {i: SecAggMember(i) for i in range(5)}
    pubs = {i: m.public for i, m in members.items()}
    masked = {i: members[i].mask(to_fixed(xs[i]), pubs, b"r1") for i in range(5)}
    total = from_fixed(masked_sum(masked, list(members)))
    assert np.allclose(total, sum(xs), atol=1e-5)
    # a single masked vector reveals nothing obvious about its input
    single = from_fixed(masked[0])
    assert not np.allclose(single, xs[0], atol=1.0)
    # a different round id gives different masks
    again = members[0].mask(to_fixed(xs[0]), pubs, b"r2")
    assert not np.array_equal(again, masked[0])


def test_missing_member_aborts_the_round() -> None:
    members = {i: SecAggMember(i) for i in range(4)}
    pubs = {i: m.public for i, m in members.items()}
    masked = {i: members[i].mask(to_fixed(np.ones(3)), pubs, b"r") for i in range(3)}
    with pytest.raises(RoundAborted, match="did not complete"):
        masked_sum(masked, list(members))


def _inputs(n: int, honest: int) -> list[MemberInput]:
    rng = np.random.default_rng(1)
    return [MemberInput(i, rng.normal(size=4) * 0.3, adds_noise=i < honest) for i in range(n)]


def test_round_aborts_below_honest_threshold() -> None:
    kw = {"clip_norm": 1.0, "sigma": 8.0, "delta": 1e-5, "round_id": b"x", "min_group": 5}
    rng = np.random.default_rng(2)
    rel = secure_round(_inputs(6, 4), honest_min=4, rng=rng, **kw)  # type: ignore[arg-type]
    assert rel.honest == 4
    assert rel.n == 6
    with pytest.raises(RoundAborted, match="qualifying noise"):
        secure_round(_inputs(6, 3), honest_min=4, rng=rng, **kw)  # type: ignore[arg-type]
    with pytest.raises(RoundAborted, match="minimum group"):
        secure_round(_inputs(4, 4), honest_min=4, rng=rng, **kw)  # type: ignore[arg-type]
    with pytest.raises(RoundAborted):
        secure_round(_inputs(6, 6), honest_min=4, rng=rng, completed=[0, 1, 2, 3, 4], **kw)  # type: ignore[arg-type]


def test_distributed_noise_variance_and_clipping() -> None:
    """Released-mean noise variance is sigma^2/(n·h) per coordinate (V13 proposition)."""
    n, h, sigma = 6, 4, 2.0
    zeros = [MemberInput(i, np.zeros(1)) for i in range(n)]
    rng = np.random.default_rng(3)
    draws = [
        secure_round(
            zeros,
            clip_norm=1.0,
            sigma=sigma,
            honest_min=h,
            delta=1e-5,
            rng=rng,
            round_id=b"v",
            min_group=5,
        ).mean[0]
        for _ in range(3000)
    ]
    expected = sigma**2 / (n * h)
    assert abs(np.var(draws) / expected - 1.0) < 0.1
    big = [MemberInput(i, np.array([100.0, 0.0]), adds_noise=True) for i in range(n)]
    rel = secure_round(
        big,
        clip_norm=1.0,
        sigma=1e-6,
        honest_min=h,
        delta=1e-5,
        rng=rng,
        round_id=b"c",
        min_group=5,
    )
    assert np.allclose(rel.mean, [1.0, 0.0], atol=1e-4)  # clipped to C before aggregation


def test_rdp_accounting() -> None:
    eps = rdp_epsilon(1.0, 12.0, 1e-5)
    c = 4.0 / (2 * 144.0)
    closed = c + 2 * math.sqrt(c * math.log(1e5))
    assert closed <= eps <= closed * 1.05  # grid accountant >= closed form
    assert rdp_epsilon(1.0, 24.0, 1e-5) < eps


def test_emo_is_a_distribution_never_a_centroid() -> None:
    anchors = ("joy", "fear", "anger")
    rng = np.random.default_rng(4)
    coords = [np.array([1.0, 0, 0])] * 3 + [np.array([0, 0, 1.0])] * 3  # bimodal
    d = emo_histogram(coords, anchors, epsilon=50.0, min_group=5, rng=rng)
    assert isinstance(d, AffectDistribution)
    assert not any(hasattr(d, a) for a in ("mean", "centroid", "valence"))
    shares = d.shares()
    assert shares[1] < 0.2 < shares[0]  # the empty middle mode stays empty
    with pytest.raises(RoundAborted, match="at least 5"):
        emo_histogram(coords[:4], anchors, epsilon=1.0, min_group=5, rng=rng)
    with pytest.raises(HiveError):
        emo_histogram(coords, anchors, epsilon=0.0, min_group=5, rng=rng)


def test_covariance_intersection_is_conservative_under_copying() -> None:
    """Echo overconfidence: n copies of one estimate must not shrink the covariance."""
    m, c = np.array([1.0, 2.0]), np.eye(2) * 0.5
    iv_mean, iv_cov = inverse_variance([m] * 5, [c] * 5)
    ci_mean, ci_cov = covariance_intersection([m] * 5, [c] * 5)
    assert np.allclose(iv_cov, c / 5)  # overconfident: claims a 5x gain from copies
    assert np.allclose(ci_cov, c, atol=1e-6)  # CI: no gain from identical evidence
    assert np.allclose(ci_mean, m)
    assert np.allclose(iv_mean, m)
    # with genuinely complementary evidence CI still improves on each input
    a, b = np.diag([0.1, 10.0]), np.diag([10.0, 0.1])
    _, fused = covariance_intersection([m, m], [a, b])
    assert np.trace(fused) < min(np.trace(a), np.trace(b))


def test_social_choice() -> None:
    assert majority_binary([True, True, False])
    assert not majority_binary([True, False])  # tie keeps the status quo
    rng = np.random.default_rng(5)
    picks = [
        exponential_mechanism({"a": 10.0, "b": 0.0}, epsilon=2.0, sensitivity=1.0, rng=rng)
        for _ in range(500)
    ]
    frac_a = picks.count("a") / len(picks)
    p_a = 1 / (1 + math.exp(-2.0 * 10 / 2))
    assert abs(frac_a - p_a) < 0.02
    flat = [
        exponential_mechanism({"a": 10.0, "b": 0.0}, epsilon=0.01, sensitivity=1.0, rng=rng)
        for _ in range(2000)
    ]
    assert 0.4 < flat.count("a") / len(flat) < 0.6  # tiny epsilon: nearly uniform
    with pytest.raises(HiveError):
        exponential_mechanism({"a": 1.0}, epsilon=0.0, sensitivity=1.0, rng=rng)
