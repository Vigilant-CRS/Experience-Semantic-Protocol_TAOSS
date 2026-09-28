# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Physiological feature layer (WP-028). Features only — no emotion recognition.

Pure numpy, deterministic, documented algorithms:

- heart rate from ECG (derivative-squared energy, adaptive threshold,
  250 ms refractory period) or from PPG/BVP (detrended peak detection);
- heart-rate variability from RR intervals: SDNN, RMSSD, pNN50;
- electrodermal features: tonic level (SCL) and phasic responses (SCR count);
- respiration rate (dominant frequency in 0.1-0.7 Hz);
- pupil/gaze: mean pupil diameter and change, fixation ratio (I-VT);
- optional EEG spectral band powers (Welch, absolute and relative).

Each feature carries its unit, window, the number of samples used and a
quality in [0, 1] (share of valid samples, plausibility). Implausible
results are reported with quality 0 instead of being silently clipped.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

from esp.core.clock import ClockStamp
from esp.observation.model import DeviceMetadata, Modality, Observation, SignalQuality

F64 = NDArray[np.float64]

EEG_BANDS: dict[str, tuple[float, float]] = {
    "delta": (1.0, 4.0),
    "theta": (4.0, 8.0),
    "alpha": (8.0, 13.0),
    "beta": (13.0, 30.0),
    "gamma": (30.0, 45.0),
}


@dataclass(frozen=True, slots=True)
class FeatureValue:
    name: str
    value: float
    unit: str
    modality: Modality
    window_start_ns: int
    window_end_ns: int
    n_samples: int
    quality: float

    def to_observation(
        self, device: DeviceMetadata, clock_domain: str, sequence: int = 0
    ) -> Observation:
        """A derived feature as a neutral observation (e.g. for the rule-based estimator)."""
        stamp = ClockStamp(
            source_ns=self.window_end_ns,
            monotonic_ns=self.window_end_ns,
            clock_domain=clock_domain,
            sequence=sequence,
        )
        usable = np.isfinite(self.value) and self.quality > 0.0
        return Observation(
            id=uuid.uuid4(),
            modality=self.modality,
            channel=self.name,
            value=float(self.value) if usable else None,
            unit=self.unit,
            device=device,
            timestamp=stamp,
            quality=SignalQuality(signal_quality=self.quality, dropout=not usable),
        )


# --- helpers ------------------------------------------------------------------------------------


def _valid_share(x: F64) -> float:
    return float(np.mean(np.isfinite(x))) if x.size else 0.0


def _fill(x: F64) -> F64:
    """Linear interpolation over NaN dropouts (for filters), keeping length."""
    x = np.asarray(x, dtype=np.float64)
    bad = ~np.isfinite(x)
    if not bad.any():
        return x
    if bad.all():
        return np.zeros_like(x)
    idx = np.arange(x.size)
    out = x.copy()
    out[bad] = np.interp(idx[bad], idx[~bad], x[~bad])
    return out


def moving_average(x: F64, n: int) -> F64:
    if n <= 1:
        return np.asarray(x, dtype=np.float64)
    kernel = np.ones(n) / n
    pad = np.pad(x, (n // 2, n - 1 - n // 2), mode="edge")
    return np.convolve(pad, kernel, mode="valid")


def find_peaks(x: F64, *, min_distance: int, threshold: float) -> NDArray[np.int64]:
    """Local maxima above ``threshold``, greedily keeping the highest within ``min_distance``."""
    if x.size < 3:
        return np.array([], dtype=np.int64)
    cand = np.nonzero((x[1:-1] > x[:-2]) & (x[1:-1] >= x[2:]) & (x[1:-1] > threshold))[0] + 1
    order = cand[np.argsort(-x[cand], kind="stable")]
    taken = np.zeros(x.size, dtype=bool)
    keep = []
    for i in order:
        lo, hi = max(0, i - min_distance + 1), min(x.size, i + min_distance)
        if not taken[lo:hi].any():
            keep.append(i)
            taken[i] = True
    return np.array(sorted(keep), dtype=np.int64)


def welch_psd(x: F64, fs: float, *, segment_s: float = 2.0) -> tuple[F64, F64]:
    """Welch PSD with Hann windows and 50 % overlap (one-sided, density scaling)."""
    x = _fill(np.asarray(x, dtype=np.float64))
    n = min(x.size, max(8, round(segment_s * fs)))
    step = max(1, n // 2)
    win = np.hanning(n)
    scale = fs * np.sum(win**2)
    segs = [x[s : s + n] - np.mean(x[s : s + n]) for s in range(0, x.size - n + 1, step)]
    spectra = [np.abs(np.fft.rfft(s * win)) ** 2 / scale for s in segs]
    psd = np.mean(spectra, axis=0)
    psd[1:-1] *= 2.0
    return np.fft.rfftfreq(n, 1.0 / fs), psd


def _band(freqs: F64, psd: F64, lo: float, hi: float) -> float:
    m = (freqs >= lo) & (freqs < hi)
    return float(np.trapezoid(psd[m], freqs[m])) if m.sum() > 1 else 0.0


# --- cardiac ------------------------------------------------------------------------------------


def r_peaks(ecg: F64, fs: float) -> NDArray[np.int64]:
    """R-peak indices: derivative, squaring, 150 ms integration, adaptive threshold."""
    x = _fill(ecg)
    energy = moving_average(np.gradient(x) ** 2, max(1, round(0.15 * fs)))
    threshold = 0.3 * np.percentile(energy, 99)
    cand = find_peaks(energy, min_distance=round(0.25 * fs), threshold=threshold)
    # refine to the local ECG maximum within +-75 ms
    w = max(1, round(0.075 * fs))
    refined = [
        int(c - w + np.argmax(x[max(0, c - w) : c + w + 1])) if c >= w else int(c) for c in cand
    ]
    return np.unique(np.array(refined, dtype=np.int64))


def ppg_peaks(ppg: F64, fs: float) -> NDArray[np.int64]:
    x = _fill(ppg)
    detrended = moving_average(x, max(1, round(0.1 * fs))) - moving_average(
        x, max(1, round(1.5 * fs))
    )
    threshold = float(np.percentile(detrended, 60))
    return find_peaks(detrended, min_distance=round(0.33 * fs), threshold=threshold)


def rr_intervals_s(peaks: NDArray[np.int64], fs: float) -> F64:
    rr = np.diff(peaks) / fs
    return rr[(rr > 0.3) & (rr < 2.0)]  # 30-200 bpm plausibility


def heart_rate(
    signal: F64, fs: float, t0_ns: int, *, source: Modality = Modality.ECG
) -> list[FeatureValue]:
    peaks = r_peaks(signal, fs) if source is Modality.ECG else ppg_peaks(signal, fs)
    rr = rr_intervals_s(peaks, fs)
    end = t0_ns + round(signal.size / fs * 1e9)
    share = _valid_share(signal)
    plausible = rr.size >= 2
    hr = 60.0 / float(np.median(rr)) if plausible else float("nan")
    q = share if plausible else 0.0
    out = [FeatureValue("hr", hr, "bpm", source, t0_ns, end, int(signal.size), q)]
    out += hrv(rr, source, t0_ns, end, share)
    return out


def hrv(rr_s: F64, source: Modality, t0_ns: int, end_ns: int, share: float) -> list[FeatureValue]:
    ok = rr_s.size >= 3
    rr_ms = rr_s * 1000.0
    d = np.diff(rr_ms)
    q = share if ok else 0.0
    nan = float("nan")
    return [
        FeatureValue(
            "hrv_sdnn",
            float(np.std(rr_ms, ddof=1)) if ok else nan,
            "ms",
            source,
            t0_ns,
            end_ns,
            int(rr_s.size),
            q,
        ),
        FeatureValue(
            "hrv_rmssd",
            float(np.sqrt(np.mean(d**2))) if ok else nan,
            "ms",
            source,
            t0_ns,
            end_ns,
            int(rr_s.size),
            q,
        ),
        FeatureValue(
            "hrv_pnn50",
            float(np.mean(np.abs(d) > 50.0) * 100) if ok else nan,
            "percent",
            source,
            t0_ns,
            end_ns,
            int(rr_s.size),
            q,
        ),
    ]


# --- electrodermal ------------------------------------------------------------------------------


def eda_features(
    eda_us: F64, fs: float, t0_ns: int, *, scr_threshold_us: float = 0.01
) -> list[FeatureValue]:
    """Tonic SCL (4 s moving median proxy) and SCR count (phasic rises above threshold)."""
    x = _fill(eda_us)
    end = t0_ns + round(x.size / fs * 1e9)
    share = _valid_share(eda_us)
    smooth = moving_average(x, max(1, round(0.25 * fs)))
    tonic = moving_average(smooth, max(1, round(4.0 * fs)))
    phasic = smooth - tonic
    peaks = find_peaks(phasic, min_distance=max(1, round(1.0 * fs)), threshold=scr_threshold_us)
    minutes = x.size / fs / 60.0
    plausible = bool(np.all(x[np.isfinite(eda_us)] >= 0)) and x.size > 0
    q = share if plausible else 0.0
    return [
        FeatureValue(
            "eda_scl", float(np.median(tonic)), "uS", Modality.EDA, t0_ns, end, int(x.size), q
        ),
        FeatureValue(
            "eda_scr_count", float(peaks.size), "count", Modality.EDA, t0_ns, end, int(x.size), q
        ),
        FeatureValue(
            "eda_scr_rate",
            float(peaks.size / minutes) if minutes > 0 else 0.0,
            "count",
            Modality.EDA,
            t0_ns,
            end,
            int(x.size),
            q,
        ),
    ]


# --- respiration --------------------------------------------------------------------------------


def respiration_rate(resp: F64, fs: float, t0_ns: int) -> FeatureValue:
    freqs, psd = welch_psd(resp, fs, segment_s=min(32.0, resp.size / fs))
    m = (freqs >= 0.1) & (freqs <= 0.7)
    end = t0_ns + round(resp.size / fs * 1e9)
    if m.sum() < 2:
        return FeatureValue(
            "resp_rate",
            float("nan"),
            "breaths_per_min",
            Modality.RESPIRATION,
            t0_ns,
            end,
            int(resp.size),
            0.0,
        )
    f = float(freqs[m][np.argmax(psd[m])])
    peakiness = float(np.max(psd[m]) / (np.sum(psd[m]) + 1e-12))
    return FeatureValue(
        "resp_rate",
        f * 60.0,
        "breaths_per_min",
        Modality.RESPIRATION,
        t0_ns,
        end,
        int(resp.size),
        _valid_share(resp) * min(1.0, 3 * peakiness),
    )


# --- pupil / gaze -------------------------------------------------------------------------------


def pupil_gaze_features(
    pupil_mm: F64, gaze_deg: F64, fs: float, t0_ns: int, *, saccade_deg_s: float = 30.0
) -> list[FeatureValue]:
    """Mean pupil, pupil change (last - first quarter), fixation ratio (I-VT), saccade count."""
    end = t0_ns + round(pupil_mm.size / fs * 1e9)
    p = pupil_mm[np.isfinite(pupil_mm)]
    q_pupil = _valid_share(pupil_mm)
    quarter = max(1, p.size // 4)
    g = np.asarray(gaze_deg, dtype=np.float64).reshape(pupil_mm.size, 2)
    speed = np.linalg.norm(np.diff(_fill_2d(g), axis=0), axis=1) * fs
    moving = speed > saccade_deg_s
    onsets = int(np.sum(moving[1:] & ~moving[:-1]) + (moving[0] if moving.size else 0))
    nan = float("nan")
    return [
        FeatureValue(
            "pupil_mean",
            float(np.mean(p)) if p.size else nan,
            "mm",
            Modality.EYE,
            t0_ns,
            end,
            int(p.size),
            q_pupil,
        ),
        FeatureValue(
            "pupil_change",
            float(np.mean(p[-quarter:]) - np.mean(p[:quarter])) if p.size else nan,
            "mm",
            Modality.EYE,
            t0_ns,
            end,
            int(p.size),
            q_pupil,
        ),
        FeatureValue(
            "fixation_ratio",
            float(np.mean(~moving)) if moving.size else nan,
            "1",
            Modality.EYE,
            t0_ns,
            end,
            int(speed.size),
            _valid_share(g[:, 0]),
        ),
        FeatureValue(
            "saccade_count",
            float(onsets),
            "count",
            Modality.EYE,
            t0_ns,
            end,
            int(speed.size),
            _valid_share(g[:, 0]),
        ),
    ]


def _fill_2d(g: F64) -> F64:
    return np.stack([_fill(g[:, 0]), _fill(g[:, 1])], axis=1)


# --- EEG ----------------------------------------------------------------------------------------


def eeg_band_powers(
    eeg_uv: F64, fs: float, t0_ns: int, bands: dict[str, tuple[float, float]] | None = None
) -> list[FeatureValue]:
    """Absolute band power (uV^2 -> reported as ``1`` power units) and relative power."""
    bands = bands or EEG_BANDS
    freqs, psd = welch_psd(eeg_uv, fs)
    end = t0_ns + round(eeg_uv.size / fs * 1e9)
    powers = {k: _band(freqs, psd, lo, min(hi, fs / 2)) for k, (lo, hi) in bands.items()}
    total = sum(powers.values())
    q = _valid_share(eeg_uv)
    out = []
    for k, v in powers.items():
        out.append(
            FeatureValue(f"eeg_{k}_power", v, "1", Modality.EEG, t0_ns, end, int(eeg_uv.size), q)
        )
        out.append(
            FeatureValue(
                f"eeg_{k}_rel",
                v / total if total > 0 else float("nan"),
                "1",
                Modality.EEG,
                t0_ns,
                end,
                int(eeg_uv.size),
                q if total > 0 else 0.0,
            )
        )
    return out


def windows(n: int, fs: float, window_s: float, step_s: float) -> Sequence[tuple[int, int]]:
    """Sample index windows ``[start, stop)`` for sliding feature extraction."""
    w, s = round(window_s * fs), max(1, round(step_s * fs))
    return [(i, i + w) for i in range(0, max(0, n - w) + 1, s)] if n >= w else []
