# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Threshold-crossing counts and full-rate raw broadband replay (M18, WP-088).

The synthetic tests always run. The real-data tests stream a 1 s x 3 channel slice of a
human Neuropixels recording (DANDI:000397, Paulk et al. 2022, CC0) by HTTP range requests
and run only with ``ESP_NETWORK_TESTS=1``.
"""

from __future__ import annotations

import json
import os
import tracemalloc
import urllib.request

import numpy as np
import pytest

from esp.adapters.neural.model import NeuralProfile, ReplayDeclaration
from esp.adapters.physio.stream import ChannelSpec, SampleBlock
from esp.features.neural import crossings, highpass, robust_sigma, threshold_crossing_counts
from esp.observation.model import DeviceMetadata, Modality

RATE = 30_000.0
DEV = DeviceMetadata(device_id="sim-broadband", kind="neural", sampling_rate_hz=RATE)


def _block(values: np.ndarray, rate: float = RATE) -> SampleBlock:
    n, c = values.shape
    ts = np.round(np.arange(n) * (1e9 / rate)).astype(np.int64)
    return SampleBlock(
        stream="raw",
        channels=tuple(ChannelSpec(f"ch{i}", Modality.BROADBAND, "uV") for i in range(c)),
        timestamps_ns=ts,
        values=values.astype(np.float64),
        device=DEV,
        clock_domain="sim",
        nominal_rate_hz=rate,
    )


def test_highpass_removes_offset_and_slow_waves_but_keeps_spike_band() -> None:
    t = np.arange(int(RATE)) / RATE
    dc = np.full((t.size, 1), 5000.0)
    assert np.abs(highpass(dc, RATE)).max() < 1e-6  # no start-up transient from the offset
    slow = 5000.0 + 100.0 * np.sin(2 * np.pi * 10 * t)[:, None]
    fast = 10.0 * np.sin(2 * np.pi * 1000 * t)[:, None]
    tail = slice(int(RATE) // 2, None)
    assert np.abs(highpass(slow, RATE)[tail]).max() < 0.5  # 10 Hz: about -60 dB
    assert np.abs(highpass(fast, RATE)[tail]).max() == pytest.approx(10.0, rel=0.02)
    with pytest.raises(ValueError, match="Nyquist"):
        highpass(dc, RATE, cutoff_hz=RATE)


def test_injected_spikes_are_counted_once_each_in_the_right_bin() -> None:
    rng = np.random.default_rng(7)
    x = rng.normal(0.0, 10.0, size=(int(RATE), 2)) + 3000.0
    per_bin = int(0.02 * RATE)
    want = np.zeros((50, 2))
    for b, c, n in [(0, 0, 1), (3, 0, 2), (3, 1, 1), (17, 1, 3), (49, 0, 1)]:
        for j in range(n):
            at = b * per_bin + 100 + 150 * j
            x[at : at + 6, c] -= 200.0  # a 0.2 ms negative deflection, many samples below
            want[b, c] += 1
    r = threshold_crossing_counts(_block(x))
    assert r.block.values.shape == (50, 2)
    np.testing.assert_array_equal(r.block.values, want)
    assert r.sigma == pytest.approx([10.0, 10.0], rel=0.1)  # spikes do not inflate sigma


def test_only_falling_edges_below_the_negative_threshold_count() -> None:
    sigma = np.array([10.0])
    x = np.zeros((12, 1))
    x[1:3, 0] = 200.0  # positive excursion: never a crossing
    x[4:8, 0] = -50.0  # four samples below -45: one crossing, at its first sample
    x[9, 0] = -44.0  # just above the threshold
    hits = crossings(x, sigma)
    assert hits[:, 0].nonzero()[0].tolist() == [4]


def test_output_is_neutral_binned_and_declares_its_chain() -> None:
    x = np.random.default_rng(0).normal(size=(3000, 2))
    r = threshold_crossing_counts(_block(x))
    b = r.block
    assert [c.name for c in b.channels] == ["ch0.tc", "ch1.tc"]
    assert {c.modality for c in b.channels} == {Modality.SPIKE_COUNTS}
    assert {c.unit for c in b.channels} == {"count"}
    assert b.nominal_rate_hz == pytest.approx(50.0)
    per_bin = 600
    np.testing.assert_array_equal(b.timestamps_ns, _block(x).timestamps_ns[per_bin - 1 :: per_bin])
    assert [s.kind for s in r.processing] == ["highpass", "threshold_crossing", "binning"]
    assert dict(r.processing[1].parameters)["k_sigma"] == "-4.5"
    assert dict(r.processing[2].parameters)["width_s"] == "0.02"


def test_bin_width_and_length_are_validated() -> None:
    x = np.zeros((1000, 1))
    with pytest.raises(ValueError, match="whole number"):
        threshold_crossing_counts(_block(x, rate=1000.5))
    with pytest.raises(ValueError, match="shorter than one bin"):
        threshold_crossing_counts(_block(x[:100]))


def test_robust_sigma_matches_gaussian_rms() -> None:
    x = np.random.default_rng(3).normal(0.0, 7.0, size=(200_000, 1))
    assert robust_sigma(x)[0] == pytest.approx(7.0, rel=0.01)


# --- real human Neuropixels raw broadband (streamed) ----------------------------------------------

DANDISET = "000397"
ASSET = "c6b42439-de35-4619-b406-b1c45e935ba0"  # sub-Pt03, 6.29 GB, never downloaded whole
SHA256 = "3a14c00935dac21ae2b61fa2bf0bd0f9d98cfe19206c6baffa4da1d6d1f53e04"
SERIES = "ElectricalSeriesRaw"
DECL = ReplayDeclaration(
    dataset_id=f"DANDI:{DANDISET}",
    version="draft",
    license="CC0-1.0",
    consent_basis=(
        "intraoperative recordings with participant consent and IRB approval as documented in "
        "Paulk et al., Nat Neurosci 25, 252-263 (2022) and https://dandiarchive.org/dandiset/000397"
    ),
    url=f"https://dandiarchive.org/dandiset/{DANDISET}",
    citation="Paulk et al. (2022) doi:10.1038/s41593-021-00997-0",
)
network = pytest.mark.skipif(
    os.environ.get("ESP_NETWORK_TESTS") != "1", reason="set ESP_NETWORK_TESTS=1"
)


@pytest.fixture(scope="module")
def remote():  # type: ignore[no-untyped-def]
    from esp.adapters.neural.nwb import NwbFile, dandi_asset_url  # noqa: PLC0415

    with NwbFile(dandi_asset_url(ASSET), dandiset=DANDISET) as f:
        yield f


@network
def test_streamed_asset_is_the_pinned_one() -> None:
    url = f"https://api.dandiarchive.org/api/dandisets/{DANDISET}/versions/draft/assets/{ASSET}/"
    with urllib.request.urlopen(url, timeout=60) as r:
        meta = json.load(r)
    assert meta["digest"]["dandi:sha2-256"] == SHA256
    assert meta["contentSize"] > 6_000_000_000
    species = {w.get("species", {}).get("name") for w in meta.get("wasAttributedTo", [])}
    assert species == {"Homo sapiens - Human"}


@network
def test_full_rate_raw_broadband_replays_lazily_under_l4_replay(remote) -> None:  # type: ignore[no-untyped-def]
    from esp.adapters.neural.nwb import electrical_series_adapter  # noqa: PLC0415
    from esp.conformance.neural import check_adapter_contract  # noqa: PLC0415

    es = remote.series(SERIES)
    assert es.data.shape[1] == 384
    assert float(es.rate) == pytest.approx(30_000.0)
    cols = [0, 1, 2]
    a = electrical_series_adapter(
        remote, SERIES, modality=Modality.BROADBAND, channels=cols, replay=DECL
    )
    info = a.info
    assert info.profile is NeuralProfile.L4_REPLAY
    assert info.descriptor is not None
    assert info.descriptor.sampling_rate_hz == pytest.approx(30_000.0)
    assert len(info.descriptor.electrodes) == 3
    report = check_adapter_contract(a, reads=3, max_samples=10_000)
    assert report.ok, report.violations

    b = electrical_series_adapter(
        remote, SERIES, modality=Modality.BROADBAND, channels=cols, replay=DECL
    )
    b.start()
    tracemalloc.start()
    blocks = [blk for _ in range(6) if (blk := b.read(5_000)) is not None]
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    assert peak < 32 * 1024 * 1024  # never the 13.5 GB series, only one window at a time
    got = np.vstack([blk.values for blk in blocks])
    assert got.shape == (30_000, 3)
    want = np.asarray(es.data[:30_000, 0:3], dtype=np.float64) * float(es.conversion) * 1e6
    np.testing.assert_allclose(got, want, rtol=0, atol=1e-9)

    ts = np.concatenate([blk.timestamps_ns for blk in blocks])
    assert (np.diff(ts) > 0).all()
    assert np.median(np.diff(ts)) == pytest.approx(1e9 / 30_000, abs=1)

    one = SampleBlock(
        stream=blocks[0].stream,
        channels=blocks[0].channels,
        timestamps_ns=ts,
        values=got,
        device=blocks[0].device,
        clock_domain=blocks[0].clock_domain,
        nominal_rate_hz=30_000.0,
    )
    tc = threshold_crossing_counts(one)
    assert tc.block.values.shape == (50, 3)
    counts = tc.block.values
    assert np.isfinite(counts).all()
    assert (counts >= 0).all()
    assert (counts.sum(axis=0) < 500).all()  # under 500 crossings/s per channel
    assert (tc.sigma > 0).all()
