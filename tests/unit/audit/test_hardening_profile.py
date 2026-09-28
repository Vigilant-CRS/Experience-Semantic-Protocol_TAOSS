# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GAP-015: ``esp-covert-hardening-v1`` profile, pattern checks, calibration and stream guard."""

import dataclasses
import json
from pathlib import Path

import numpy as np
import pytest

from esp.audit.hardening_calibration import CalibrationConfig, run, sub_step_recovery
from esp.audit.hardening_profile import (
    CovertHardeningProfile,
    StreamGuard,
    calibrate,
    check_stream,
    default_profile,
    int8_codes,
    randomized_quantize_sigma,
    tem_pattern_violations,
)

pytestmark = pytest.mark.security
ROOT = Path(__file__).resolve().parents[3]
RUN, PERIOD = 8, 4


def honest(n: int = 400, seed: int = 0) -> np.ndarray:
    rng = np.random.default_rng(seed)
    x = rng.normal(size=(n, 4))
    for t in range(1, n):
        x[t] = 0.9 * x[t - 1] + np.sqrt(1 - 0.81) * x[t]
    return x


def flags(codes: np.ndarray) -> dict[str, np.ndarray]:
    return tem_pattern_violations(codes, max_period=PERIOD, run=RUN)


# --- pattern checks -------------------------------------------------------------------------------


def test_honest_smooth_stream_has_no_forbidden_pattern() -> None:
    f = flags(int8_codes(honest()))
    assert not any(v.any() for v in f.values())


def test_all_zero_frame_flagged() -> None:
    codes = int8_codes(honest(20))
    codes[5] = 0
    assert flags(codes)["all_zero"].tolist() == [i == 5 for i in range(20)]


@pytest.mark.parametrize("period", [2, 3, 4])
def test_repeating_phase_flagged_for_every_period(period: int) -> None:
    codes = int8_codes(honest(60))
    cycle = codes[10 : 10 + period].copy()
    codes[10:40] = np.tile(cycle, (30 // period + 1, 1))[:30]
    f = flags(codes)["repeating_phase"]
    assert f[20:40].all()
    assert not f[:10].any()


def test_short_repetition_below_run_is_allowed() -> None:
    codes = int8_codes(honest(60))
    codes[10:15] = np.tile(codes[10:12], (3, 1))[:5]  # period 2 for 5 frames only
    assert not flags(codes)["repeating_phase"].any()


def test_constant_tem_is_allowed_as_a_paused_stream() -> None:
    codes = np.tile(int8_codes(honest(1)), (50, 1))
    f = flags(codes)
    assert not f["repeating_phase"].any()
    assert not f["structured_offset"].any()


def test_structured_offset_flagged() -> None:
    codes = int8_codes(honest(60))
    codes[20:35] = codes[20] + np.arange(15)[:, None] * np.array([0, 1, -1, 2])
    f = flags(codes)["structured_offset"]
    assert f[22:35].all()
    assert not f[:20].any()


# --- profile ------------------------------------------------------------------------


def test_default_profile_is_frozen_and_roundtrips() -> None:
    p = default_profile()
    assert p.name == "esp-covert-hardening-v1"
    assert CovertHardeningProfile.from_json(p.to_json()) == p
    report = json.loads((ROOT / "artifacts/research/hardening_calibration.json").read_text())
    assert report["profile_digest"] == p.digest()
    assert p.sigma_steps == report["sub_step"]["chosen_sigma_steps"]
    assert "EXPERIMENTAL" in p.provenance["status"]


def test_profile_validation() -> None:
    p = default_profile()
    with pytest.raises(ValueError, match="lo < hi"):
        dataclasses.replace(p, tem_hi=p.tem_lo)
    with pytest.raises(ValueError, match="sparsity band"):
        dataclasses.replace(p, sparsity_bands={"KNO": (0.5, 0.2)})
    with pytest.raises(ValueError, match="max_period"):
        dataclasses.replace(p, max_period=1)


def test_calibrated_bands_accept_honest_and_reject_excursions() -> None:
    calib, ev = honest(2000, 1), honest(2000, 2)
    p = calibrate({"TEM": calib}, sigma_steps=0.5)
    assert check_stream(p, {"TEM": ev}).flagged().mean() < 0.01
    ev[100, 0] = p.tem_hi[0] + 1.0
    assert check_stream(p, {"TEM": ev}).tem_band[100]


def test_sparsity_band_catches_gating_modulation() -> None:
    kno = np.random.default_rng(3).normal(size=(500, 12))
    p = calibrate({"TEM": honest(500), "KNO": kno}, sigma_steps=0.5)
    kno[50:60, :6] = 0.0
    rep = check_stream(p, {"TEM": honest(500), "KNO": kno})
    assert rep.sparsity["KNO"][50:60].all()
    assert rep.sparsity["KNO"].sum() == 10


# --- randomized quantization ----------------------------------------------------------------------


def test_randomized_quantization_destroys_sub_step_parity_code() -> None:
    tem = honest(3000)
    rng = np.random.default_rng(0)
    assert sub_step_recovery(tem, 0.0, rng) == 1.0  # deterministic rounding leaks every bit
    assert abs(sub_step_recovery(tem, default_profile().sigma_steps, rng) - 0.5) < 0.06


def test_randomized_quantization_stays_on_the_int8_grid() -> None:
    x = honest(50)
    q = randomized_quantize_sigma(x, 0.5, np.random.default_rng(1))
    s = np.max(np.abs(x), axis=1, keepdims=True) / 127.0
    assert np.allclose(q / s, np.rint(q / s))


# --- stream guard -------------------------------------------------------------------------


def test_stream_guard_admits_honest_and_refuses_phase_code() -> None:
    p = default_profile()
    guard = StreamGuard(p)
    stream = honest(40) * 0.5
    assert all(guard.admit({"TEM": f}) == [] for f in stream)
    a, b = stream[-2], stream[-1]
    refused = [guard.admit({"TEM": a if i % 2 else b}) for i in range(RUN + 4)]
    assert any("pattern:repeating_phase" in r for r in refused)


def test_stream_guard_refuses_out_of_band_frame() -> None:
    p = default_profile()
    frame = np.zeros(4) + np.asarray(p.tem_hi) + 1.0
    assert "tem_band" in StreamGuard(p).admit({"TEM": frame})


# --- the experiment itself ------------------------------------------------------------------------


def test_small_calibration_run_detects_every_covert_sender() -> None:
    profile, report = run(CalibrationConfig(n=1500, steps=40, seed=3))
    for rho, fpr in report["honest_false_positives"].items():
        assert fpr["frame_fpr"] < 0.02, rho
    for kind, det in report["covert_detection"].items():
        assert det["detected_bit1_windows"] > 0.9, kind
    assert profile.sigma_steps == report["sub_step"]["chosen_sigma_steps"]


@pytest.mark.slow
def test_full_calibration_reproduces_the_frozen_profile() -> None:
    profile, _ = run(CalibrationConfig())
    frozen = default_profile()
    assert np.allclose(profile.tem_lo, frozen.tem_lo, atol=1e-5)
    assert np.allclose(profile.tem_hi, frozen.tem_hi, atol=1e-5)
    assert profile.sigma_steps == frozen.sigma_steps
