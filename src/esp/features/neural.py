# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Neutral spike features from raw broadband recordings (M18).

``threshold_crossing_counts`` turns a raw broadband block (e.g. Neuropixels at 30 kHz) into
binned threshold-crossing counts, the standard intracortical BCI feature:

1. causal 2nd-order Butterworth high-pass (default 300 Hz, bilinear transform);
2. per-channel noise estimate sigma = median(|x|) / 0.6745 (robust RMS; Quiroga et al. 2004);
3. a crossing is a sample where the filtered signal falls below ``-k*sigma`` (default k = 4.5)
   while the previous sample was not below it (falling edge, so one spike counts once);
4. crossings are counted in fixed bins (default 20 ms) on the block's own clock.

The output is neutral (counts per channel and bin, modality ``SPIKE_COUNTS``) and declares
its processing chain, so a receiver knows exactly how the counts were made. Nothing here
interprets the activity.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np
from numpy.typing import NDArray

from esp.adapters.neural.model import ProcessingStep
from esp.adapters.physio.stream import ChannelSpec, SampleBlock
from esp.observation.model import Modality

F64 = NDArray[np.float64]


def highpass(x: F64, rate_hz: float, cutoff_hz: float = 300.0) -> F64:
    """Causal 2nd-order Butterworth high-pass along axis 0.

    The state starts at the first sample's DC level, so a recording's offset does not
    produce a start-up transient (which would otherwise look like spikes)."""
    if not 0 < cutoff_hz < rate_hz / 2:
        msg = "cutoff must lie between 0 and the Nyquist frequency"
        raise ValueError(msg)
    k = math.tan(math.pi * cutoff_hz / rate_hz)
    q = math.sqrt(2.0) / 2.0  # Butterworth
    norm = 1.0 / (1.0 + k / q + k * k)
    b0, b1, b2 = norm, -2.0 * norm, norm
    a1, a2 = 2.0 * (k * k - 1.0) * norm, (1.0 - k / q + k * k) * norm
    x = np.asarray(x, dtype=np.float64)
    y = np.empty_like(x)
    x1 = x2 = x[0] if x.shape[0] else np.zeros(x.shape[1:])
    y1 = y2 = np.zeros(x.shape[1:])
    for t in range(x.shape[0]):
        xt = x[t]
        yt = b0 * xt + b1 * x1 + b2 * x2 - a1 * y1 - a2 * y2
        y[t] = yt
        x2, x1, y2, y1 = x1, xt, y1, yt
    return y


def robust_sigma(x: F64) -> F64:
    """Per-channel noise level median(|x|)/0.6745 (insensitive to the spikes themselves)."""
    out: F64 = np.median(np.abs(x), axis=0) / 0.6745
    return out


def crossings(x: F64, sigma: F64, k: float = 4.5) -> NDArray[np.bool_]:
    """Falling-edge crossings of ``-k·sigma``: below now, not below one sample earlier."""
    below = x < -k * sigma
    prev = np.vstack([np.zeros((1, x.shape[1]), dtype=bool), below[:-1]])
    out: NDArray[np.bool_] = below & ~prev
    return out


@dataclass(frozen=True, slots=True)
class CrossingResult:
    block: SampleBlock
    processing: tuple[ProcessingStep, ...]
    sigma: F64


def threshold_crossing_counts(
    raw: SampleBlock,
    *,
    k: float = 4.5,
    bin_s: float = 0.02,
    cutoff_hz: float = 300.0,
) -> CrossingResult:
    """Binned threshold-crossing counts of one raw block (only complete bins are emitted)."""
    rate = raw.nominal_rate_hz
    if rate is None or rate <= 0:
        msg = "a regular raw block with a nominal rate is required"
        raise ValueError(msg)
    per_bin = round(bin_s * rate)
    if per_bin < 1 or not math.isclose(per_bin, bin_s * rate, rel_tol=1e-9):
        msg = "the bin width must be a whole number of samples"
        raise ValueError(msg)
    n_bins = raw.n_samples // per_bin
    if n_bins < 1:
        msg = "block shorter than one bin"
        raise ValueError(msg)
    filtered = highpass(raw.values, rate, cutoff_hz)
    sigma = robust_sigma(filtered)
    hits = crossings(filtered, sigma, k)[: n_bins * per_bin]
    counts = hits.reshape(n_bins, per_bin, -1).sum(axis=1).astype(np.float64)
    ts = raw.timestamps_ns[per_bin - 1 : n_bins * per_bin : per_bin].astype(np.int64)  # bin ends
    channels = tuple(
        ChannelSpec(f"{c.name}.tc", Modality.SPIKE_COUNTS, "count") for c in raw.channels
    )
    block = SampleBlock(
        stream=f"{raw.stream}.crossings",
        channels=channels,
        timestamps_ns=ts,
        values=counts,
        device=raw.device,
        clock_domain=raw.clock_domain,
        nominal_rate_hz=1.0 / bin_s,
    )
    processing = (
        ProcessingStep(
            "highpass", (("order", "2"), ("cutoff_hz", repr(cutoff_hz)), ("causal", "true"))
        ),
        ProcessingStep(
            "threshold_crossing", (("k_sigma", repr(-k)), ("sigma", "median_abs_0.6745"))
        ),
        ProcessingStep("binning", (("width_s", repr(bin_s)),)),
    )
    return CrossingResult(block, processing, sigma)
