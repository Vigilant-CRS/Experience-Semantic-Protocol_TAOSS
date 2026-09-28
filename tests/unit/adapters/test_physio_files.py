# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M6: recorded-data readers, stream analysis and deterministic replay."""

import calendar
import datetime as dt
from pathlib import Path

import numpy as np
import pytest

from esp.adapters.physio.files import (
    RecordingFormatError,
    read_brainvision,
    read_edf,
    read_empatica,
    read_wfdb,
    read_xdf,
)
from esp.adapters.physio.stream import (
    ChannelSpec,
    SampleBlock,
    analyze,
    concat,
    normalize_channel,
    normalize_unit,
    regular_timestamps,
    replay_chunks,
)
from esp.observation.model import DeviceMetadata, Modality

ROOT = Path(__file__).resolve().parents[3]
DATA = ROOT / "data" / "external"
needs_data = pytest.mark.skipif(
    not (DATA / "physionet-eegmmidb-s001").exists(), reason="run scripts/fetch_datasets.py"
)


# --- synthetic EDF / BDF writer (test oracle with known values) -----------------------------


def write_edf(
    path: Path,
    signals: list[np.ndarray],
    rates: list[int],
    *,
    bdf: bool = False,
    n_records_field: int | None = None,
    annotations: list[tuple[float, str]] = (),
) -> None:
    """Minimal EDF(+)/BDF writer: 1-second records, physical range = digital range * 0.5."""
    width = 3 if bdf else 2
    dig_max = (1 << 23) - 1 if bdf else 32767
    labels = [f"Sig{i}" for i in range(len(signals))]
    spr = list(rates)
    ann_spr = 0
    if annotations:
        labels.append("EDF Annotations")
        ann_spr = 60
        spr.append(ann_spr)
    ns = len(labels)
    n_rec = len(signals[0]) // rates[0]

    def f(v: object, n: int) -> bytes:
        return str(v).ljust(n)[:n].encode()

    head = (b"\xffBIOSEMI" if bdf else f(0, 8)) + f("X", 80) + f("Y", 80) + f("20.02.13", 8)
    head += f("17.55.19", 8) + f(256 * (ns + 1), 8) + f("24BIT" if bdf else "EDF+C", 44)
    head += f(n_rec if n_records_field is None else n_records_field, 8) + f(1, 8) + f(ns, 4)
    cols = {
        16: labels,
        80: [""] * ns,
        8: ["uV"] * len(signals) + ([""] if annotations else []),
    }
    head += b"".join(f(x, 16) for x in cols[16]) + b"".join(f(x, 80) for x in cols[80])
    head += b"".join(f(x, 8) for x in cols[8])
    head += b"".join(f(-dig_max * 0.5, 8) for _ in range(ns))
    head += b"".join(f(dig_max * 0.5, 8) for _ in range(ns))
    head += b"".join(f(-dig_max, 8) for _ in range(ns))
    head += b"".join(f(dig_max, 8) for _ in range(ns))
    head += f("", 80) * ns + b"".join(f(x, 8) for x in spr) + f("", 32) * ns
    body = b""
    for r in range(n_rec):
        for sig, rate in zip(signals, rates, strict=True):
            chunk = np.round(sig[r * rate : (r + 1) * rate] * 2).astype(np.int64)
            body += b"".join(int(x).to_bytes(width, "little", signed=True) for x in chunk)
        if annotations:
            tal = f"+{r}\x14\x14\x00".encode()
            for onset, text in annotations:
                if r <= onset < r + 1:
                    tal += f"+{onset}\x14{text}\x14\x00".encode()
            body += tal.ljust(ann_spr * width, b"\x00")
    path.write_bytes(head + body)


T0 = calendar.timegm(dt.datetime(2013, 2, 20, 17, 55, 19).timetuple()) * 10**9


@pytest.mark.parametrize("bdf", [False, True])
def test_edf_bdf_reader_recovers_known_values(tmp_path: Path, bdf: bool) -> None:
    t = np.arange(4 * 100) / 100
    a = np.round(200 * np.sin(2 * np.pi * 3 * t)) / 2  # resolution 0.5 (see writer)
    b = np.round(np.linspace(-100, 100, 4 * 10)) / 2
    p = tmp_path / ("x.bdf" if bdf else "x.edf")
    write_edf(p, [a, b], [100, 10], bdf=bdf, annotations=[(1.5, "T1"), (3.25, "T2")])
    rec = read_edf(p)
    fast, slow = rec.blocks
    assert fast.nominal_rate_hz == 100.0
    assert slow.nominal_rate_hz == 10.0  # different rates -> separate blocks
    np.testing.assert_allclose(fast.channel("sig0"), a, atol=1e-3)
    np.testing.assert_allclose(slow.channel("sig1"), b, atol=1e-3)
    assert fast.channels[0].unit == "uV"
    assert int(fast.timestamps_ns[0]) == T0
    assert int(fast.timestamps_ns[100]) == T0 + 10**9
    (ev,) = rec.events
    assert ev.labels == ("T1", "T2")
    assert ev.timestamps_ns == (T0 + 1_500_000_000, T0 + 3_250_000_000)


def test_unclosed_recording_infers_record_count(tmp_path: Path) -> None:
    p = tmp_path / "open.bdf"
    write_edf(p, [np.zeros(300)], [100], bdf=True, n_records_field=-1)
    assert read_edf(p).blocks[0].n_samples == 300


def test_malformed_edf_is_refused(tmp_path: Path) -> None:
    p = tmp_path / "bad.edf"
    p.write_bytes(b"garbage" * 10)
    with pytest.raises(RecordingFormatError):
        read_edf(p)
    good = tmp_path / "trunc.edf"
    write_edf(good, [np.zeros(300)], [100])
    good.write_bytes(good.read_bytes()[:-50])
    with pytest.raises(RecordingFormatError, match="shorter"):
        read_edf(good)


def test_units_and_channel_names_are_normalized() -> None:
    assert normalize_unit("µV") == "uV"
    assert normalize_unit("NU") == "1"
    assert normalize_unit("%") == "percent"
    with pytest.raises(ValueError, match="unknown unit"):
        normalize_unit("furlongs")
    assert normalize_channel("Fc5.") == "fc5"
    assert normalize_channel("  EEG Fp1-Ref ") == "eeg_fp1-ref"


def test_empatica_reader_with_synthetic_csv(tmp_path: Path) -> None:
    (tmp_path / "EDA.csv").write_text("1361382919.000000\n4.000000\n0.1\n0.2\n0.3\n")
    (tmp_path / "ACC.csv").write_text("1361382919, 1361382919, 1361382919\n32, 32, 32\n64,0,-64\n")
    (tmp_path / "tags.csv").write_text("1361382920.5\n")
    rec = read_empatica(tmp_path)
    eda = rec.block("eda")
    assert eda.channels[0].unit == "uS"
    assert int(eda.timestamps_ns[1]) == 1361382919 * 10**9 + 250_000_000
    np.testing.assert_allclose(rec.block("acc").values[0], [1.0, 0.0, -1.0])  # 1/64 g
    assert rec.events[0].timestamps_ns == (1361382920_500_000_000,)


# --- analysis and replay ----------------------------------------------------------------------


def block(ts: np.ndarray, values: np.ndarray, rate: float | None = 100.0) -> SampleBlock:
    return SampleBlock(
        stream="s",
        channels=(ChannelSpec("x", Modality.ECG, "mV"),),
        timestamps_ns=ts.astype(np.int64),
        values=values.reshape(-1, 1).astype(np.float64),
        device=DeviceMetadata(device_id="dev-1", kind="test", synthetic=True),
        clock_domain="test",
        nominal_rate_hz=rate,
    )


def test_analysis_detects_gaps_dropouts_and_non_monotonic_time() -> None:
    ts = regular_timestamps(0, 1000, 100.0)
    ts = np.delete(ts, np.s_[100:105])  # 5 dropped samples in one gap
    ts[-1] = ts[-2]  # a repeated timestamp (at the end: no following interval)
    values = np.ones(ts.size)
    values[[10, 20]] = np.nan  # flagged dropouts
    r = analyze(block(ts, values))
    assert (r.gaps, r.dropped_estimate, r.non_monotonic, r.dropout_samples) == (1, 5, 1, 2)


def test_regular_grid_has_no_float_drift() -> None:
    ts = regular_timestamps(0, 30 * 60 * 250 + 1, 250.0)  # 30 minutes at 250 Hz
    assert int(ts[-1]) == 30 * 60 * 10**9
    assert np.all(np.diff(ts) == 4_000_000)


def test_replay_is_deterministic_and_lossless() -> None:
    rng = np.random.default_rng(1)
    b = block(regular_timestamps(0, 1234, 100.0), rng.normal(size=1234))
    chunks = list(replay_chunks(b, 100))
    assert len(chunks) == 13
    assert concat(chunks).digest() == b.digest()
    assert [c.digest() for c in replay_chunks(b, 100)] == [c.digest() for c in chunks]


def test_observations_are_neutral_and_flag_dropouts() -> None:
    b = block(regular_timestamps(0, 3, 100.0), np.array([1.0, np.nan, 2.0]))
    obs = list(b.observations())
    assert [o.value for o in obs] == [1.0, None, 2.0]
    assert obs[1].quality.dropout
    assert {o.modality for o in obs} == {Modality.ECG}


def test_invalid_blocks_are_refused() -> None:
    with pytest.raises(ValueError, match="infinite"):
        block(regular_timestamps(0, 2, 100.0), np.array([1.0, np.inf]))
    with pytest.raises(ValueError, match="one timestamp per sample"):
        block(regular_timestamps(0, 3, 100.0), np.array([1.0, 2.0]))


# --- real open datasets (skipped without data/external) ----------------------------------------


@pytest.mark.dataset
@needs_data
def test_eegmmidb_edf_matches_pyedflib_reference() -> None:
    import pyedflib  # noqa: PLC0415

    path = DATA / "physionet-eegmmidb-s001" / "S001R04.edf"
    rec = read_edf(path)
    (b,) = rec.blocks
    assert b.nominal_rate_hz == 160.0
    assert len(b.channels) == 64
    ref = pyedflib.EdfReader(str(path))
    try:
        for i in (0, 17, 63):
            np.testing.assert_allclose(b.values[:, i], ref.readSignal(i), atol=1e-6)
        onsets, _, texts = ref.readAnnotations()
    finally:
        ref.close()
    (ev,) = rec.events
    assert list(ev.labels) == list(texts)
    t0 = int(b.timestamps_ns[0])
    np.testing.assert_allclose([(t - t0) / 1e9 for t in ev.timestamps_ns], onsets, atol=1e-6)
    r = analyze(b)
    assert (r.non_monotonic, r.gaps, r.dropout_samples) == (0, 0, 0)


@pytest.mark.dataset
@needs_data
def test_mne_bdf_with_unclosed_header_and_brainvision() -> None:
    bdf = read_edf(DATA / "mne-test-files" / "test.bdf")
    assert bdf.blocks[0].nominal_rate_hz == 2048.0
    assert bdf.blocks[0].n_samples > 0
    with pytest.raises(ValueError, match="unknown unit"):
        read_brainvision(DATA / "mne-test-files" / "test.vhdr")  # refuse by default
    bv = read_brainvision(DATA / "mne-test-files" / "test.vhdr", unknown_units="dimensionless")
    assert any("unknown unit 'BS'" in n for n in bv.notes)
    (b,) = bv.blocks
    assert b.nominal_rate_hz == 1000.0
    assert len(b.channels) == 32
    assert b.channels[0].unit == "uV"
    assert bv.events[0].labels


@pytest.mark.dataset
@needs_data
def test_wearable_stress_and_wfdb_recordings() -> None:
    e4 = read_empatica(DATA / "physionet-wearable-stress-s01")
    assert e4.block("bvp").nominal_rate_hz == 64.0
    assert e4.block("eda").channels[0].unit == "uS"
    assert len(e4.events[0].timestamps_ns) == 13
    w = read_wfdb(DATA / "physionet-noneeg-subject1" / "Subject1_AccTempEDA")
    names = [c.name for c in w.blocks[0].channels]
    assert names == ["ax", "ay", "az", "temp", "eda"]
    temp = w.blocks[0].channel("temp")
    assert 25.0 < float(np.nanmedian(temp)) < 40.0  # plausible skin temperature in degC


@pytest.mark.dataset
@needs_data
def test_xdf_recordings() -> None:
    minimal = read_xdf(DATA / "xdf-example-files" / "minimal.xdf")
    (eeg,) = minimal.blocks
    assert eeg.values.shape == (9, 3)
    assert minimal.events[0].labels[1:3] == ("Hello", "World")
    resets = read_xdf(DATA / "xdf-example-files" / "clock_resets.xdf")
    biosemi = resets.block("biosemi")
    assert biosemi.values.shape[1] == 8
    assert analyze(biosemi).non_monotonic == 0  # after pyxdf clock synchronization
