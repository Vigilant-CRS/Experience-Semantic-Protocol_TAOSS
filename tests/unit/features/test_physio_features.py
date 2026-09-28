# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-028: physiological features on fixtures with known properties (and one real dataset)."""

from pathlib import Path

import numpy as np
import pytest

from esp.features.physio import (
    eda_features,
    eeg_band_powers,
    find_peaks,
    heart_rate,
    pupil_gaze_features,
    respiration_rate,
    windows,
)
from esp.observation.model import DeviceMetadata, Modality

FS = 250.0
DATA = Path(__file__).resolve().parents[3] / "data" / "external"


def by_name(features: list) -> dict:  # type: ignore[type-arg]
    return {f.name: f for f in features}


def ecg(rr_s: list[float], fs: float = FS, noise: float = 0.02, seed: int = 0) -> np.ndarray:
    """Gaussian R waves (10 ms) plus small T waves at the given RR intervals."""
    beats = np.cumsum([0.5, *rr_s])
    t = np.arange(0, beats[-1] + 1.0, 1 / fs)
    x = np.zeros_like(t)
    for b in beats:
        x += np.exp(-((t - b) ** 2) / (2 * 0.01**2)) + 0.25 * np.exp(
            -((t - b - 0.25) ** 2) / (2 * 0.04**2)
        )
    return x + np.random.default_rng(seed).normal(0, noise, t.size)


def test_heart_rate_and_hrv_from_ecg_match_known_intervals() -> None:
    rr = [0.8, 0.86] * 20  # alternating: successive differences 60 ms
    f = by_name(heart_rate(ecg(rr), FS, 0))
    assert f["hr"].value == pytest.approx(60 / 0.83, abs=1.0)
    assert f["hrv_rmssd"].value == pytest.approx(60.0, abs=4.0)
    assert f["hrv_sdnn"].value == pytest.approx(np.std(np.array(rr) * 1000, ddof=1), abs=4.0)
    assert f["hrv_pnn50"].value == pytest.approx(100.0)
    assert f["hr"].unit == "bpm"
    assert f["hr"].quality == 1.0


def test_heart_rate_from_ppg() -> None:
    t = np.arange(0, 60, 1 / 64)
    ppg = np.sin(2 * np.pi * 1.25 * t) ** 3 + 0.2 * np.sin(2 * np.pi * 0.1 * t)  # 75 bpm + drift
    f = by_name(heart_rate(ppg, 64.0, 0, source=Modality.PPG))
    assert f["hr"].value == pytest.approx(75.0, abs=1.5)


def test_flat_signal_is_reported_implausible_not_invented() -> None:
    f = by_name(heart_rate(np.zeros(5000), FS, 0))
    assert np.isnan(f["hr"].value)
    assert f["hr"].quality == 0.0
    obs = f["hr"].to_observation(DeviceMetadata(device_id="d1", kind="t"), "test")
    assert obs.value is None
    assert obs.quality.dropout


def test_dropouts_reduce_quality_but_not_the_estimate() -> None:
    x = ecg([0.8] * 40)
    x[1000:1500] = np.nan  # 2 s dropout
    f = by_name(heart_rate(x, FS, 0))
    assert f["hr"].value == pytest.approx(75.0, abs=1.5)
    assert 0.9 < f["hr"].quality < 1.0


def test_eda_tonic_level_and_responses() -> None:
    fs = 4.0
    t = np.arange(0, 120, 1 / fs)
    eda = 2.0 + 0.002 * t  # slowly rising tonic level
    for onset in (20, 55, 90):  # three SCRs: fast rise, slow recovery
        dt_ = np.clip(t - onset, 0, None)
        eda += 0.2 * (1 - np.exp(-dt_ / 1.0)) * np.exp(-dt_ / 5.0) * (t >= onset)
    f = by_name(eda_features(eda, fs, 0))
    assert f["eda_scr_count"].value == 3
    assert f["eda_scl"].value == pytest.approx(2.12, abs=0.1)
    assert f["eda_scr_rate"].value == pytest.approx(1.5)
    assert f["eda_scl"].unit == "uS"


def test_respiration_rate() -> None:
    fs = 25.0
    t = np.arange(0, 120, 1 / fs)
    resp = np.sin(2 * np.pi * 0.25 * t) + 0.1 * np.random.default_rng(3).normal(size=t.size)
    f = respiration_rate(resp, fs, 0)
    assert f.value == pytest.approx(15.0, abs=0.5)
    assert f.unit == "breaths_per_min"
    assert f.quality > 0.5


def test_pupil_and_gaze() -> None:
    fs = 60.0
    n = 600
    pupil = np.linspace(3.0, 4.0, n)
    gaze = np.zeros((n, 2))
    gaze[200:, 0] = 10.0  # saccade 1
    gaze[400:, 1] = 8.0  # saccade 2
    f = by_name(pupil_gaze_features(pupil, gaze, fs, 0))
    assert f["pupil_mean"].value == pytest.approx(3.5, abs=1e-6)
    assert f["pupil_change"].value == pytest.approx(0.75, abs=0.01)
    assert f["saccade_count"].value == 2
    assert f["fixation_ratio"].value > 0.99


def test_eeg_band_powers_find_alpha() -> None:
    t = np.arange(0, 20, 1 / 160)
    eeg = 20 * np.sin(2 * np.pi * 10 * t) + np.random.default_rng(5).normal(0, 1, t.size)
    f = by_name(eeg_band_powers(eeg, 160.0, 0))
    assert f["eeg_alpha_rel"].value > 0.9
    assert f["eeg_alpha_power"].value == pytest.approx(200.0, rel=0.1)  # sine power A^2/2
    assert sum(
        f[f"eeg_{b}_rel"].value for b in ("delta", "theta", "alpha", "beta", "gamma")
    ) == pytest.approx(1.0)


def test_peak_finder_and_windows() -> None:
    x = np.array([0, 1, 0, 3, 0, 0, 2, 0], dtype=float)
    assert find_peaks(x, min_distance=3, threshold=0.5).tolist() == [3, 6]
    assert windows(100, 10.0, 5.0, 2.5) == [(0, 50), (25, 75), (50, 100)]


def test_features_are_deterministic() -> None:
    x = ecg([0.8, 0.9, 0.85] * 10, seed=9)
    assert heart_rate(x, FS, 0) == heart_rate(x, FS, 0)


@pytest.mark.dataset
@pytest.mark.skipif(
    not (DATA / "physionet-wearable-stress-s01").exists(), reason="run fetch_datasets.py"
)
def test_bvp_heart_rate_agrees_with_the_device_on_real_data() -> None:
    from esp.adapters.physio.files import read_empatica  # noqa: PLC0415

    rec = read_empatica(DATA / "physionet-wearable-stress-s01")
    bvp, hr_dev = rec.block("bvp"), rec.block("hr")
    diffs = []
    for k in range(6):  # six 60-s windows in the calm baseline phase
        lo = 60 * 64 * (1 + k)
        seg = bvp.values[lo : lo + 60 * 64, 0]
        start, end = int(bvp.timestamps_ns[lo]), int(bvp.timestamps_ns[lo + 60 * 64 - 1])
        ours = by_name(heart_rate(seg, 64.0, start, source=Modality.PPG))["hr"].value
        m = (hr_dev.timestamps_ns >= start) & (hr_dev.timestamps_ns <= end)
        diffs.append(ours - float(np.median(hr_dev.values[m, 0])))
    assert float(np.median(np.abs(diffs))) < 8.0  # agrees with Empatica's own HR (bpm)
