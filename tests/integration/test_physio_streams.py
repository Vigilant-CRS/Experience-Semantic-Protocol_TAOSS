# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-026 BrainFlow (synthetic, playback, streaming) and WP-027 LSL (3 parallel streams)."""

import time
import uuid
from pathlib import Path

import numpy as np
import pytest
from brainflow.board_shim import BoardIds
from pylsl import local_clock

from esp.adapters.physio.brainflow_adapter import (
    BrainFlowSource,
    dropped_from_counter,
    playback_params,
    record_to_file,
    streaming_params,
)
from esp.adapters.physio.files import read_xdf
from esp.adapters.physio.lsl_adapter import (
    MarkerInlet,
    MarkerOutlet,
    ReplayOutlet,
    SignalInlet,
    SignalOutlet,
    corrected,
    discover,
    unix_to_lsl_offset_s,
)
from esp.adapters.physio.stream import ChannelSpec, SampleBlock, analyze, concat
from esp.observation.model import DeviceMetadata, Modality

pytestmark = pytest.mark.integration
DATA = Path(__file__).resolve().parents[2] / "data" / "external"


def run_brainflow(src: BrainFlowSource, seconds: float) -> tuple[SampleBlock, np.ndarray]:
    src.start()
    blocks, raws = [], []
    try:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            time.sleep(0.2)
            b, raw = src.poll_with_raw()
            if b is not None:
                blocks.append(b)
                raws.append(raw)
    finally:
        src.stop()
    return concat(blocks), np.concatenate(raws, axis=1)


# --- BrainFlow --------------------------------------------------------------------------------


def test_counter_based_drop_detection_handles_wraparound() -> None:
    assert dropped_from_counter(np.array([253.0, 254, 255, 0, 1])) == 0
    assert dropped_from_counter(np.array([250.0, 255, 3])) == 4 + 3


def test_phase_a_synthetic_board() -> None:
    src = BrainFlowSource()
    src_block, _ = run_brainflow(src, 3.0)
    r = analyze(src_block)
    assert r.non_monotonic == 0
    assert src.dropped == 0
    assert 240 < r.effective_rate_hz < 260  # nominal 250 Hz
    kinds = {c.modality for c in src_block.channels}
    assert {Modality.EEG, Modality.MOTION, Modality.EDA, Modality.PPG} <= kinds
    assert next(c for c in src_block.channels if c.name == "eeg1").unit == "uV"
    lag_s = time.time() - src_block.timestamps_ns[-1] / 1e9
    assert 0 <= lag_s < 2.0  # unix timestamps, no clock confusion


def test_phase_b_playback_is_deterministic(tmp_path: Path) -> None:
    _, raw = run_brainflow(BrainFlowSource(), 2.0)
    f = tmp_path / "session.csv"
    record_to_file(raw, f)
    replays = []
    for _ in range(2):
        pb = BrainFlowSource(
            BoardIds.PLAYBACK_FILE_BOARD, playback_params(f), layout_board=BoardIds.SYNTHETIC_BOARD
        )
        block, _ = run_brainflow(pb, 2.5)
        replays.append(block.values[: raw.shape[1]])
    np.testing.assert_array_equal(replays[0], replays[1])  # identical across replays
    eeg_rows = raw[1:17].T[: replays[0].shape[0]]
    np.testing.assert_allclose(replays[0][:, :16], eeg_rows, atol=1e-6)  # file precision


def test_phase_c_streaming_board() -> None:
    port = 6700 + uuid.uuid4().int % 200
    master = BrainFlowSource()
    master.start()
    master.add_streamer(f"streaming_board://225.1.1.1:{port}")
    try:
        rx = BrainFlowSource(
            BoardIds.STREAMING_BOARD,
            streaming_params(port=port),
            layout_board=BoardIds.SYNTHETIC_BOARD,
        )
        block, _ = run_brainflow(rx, 3.0)
    finally:
        master.stop()
    if block.n_samples == 0:  # pragma: no cover - environment without multicast
        pytest.skip("no multicast on this host")
    assert analyze(block).non_monotonic == 0
    assert rx.dropped <= block.n_samples * 0.01


def test_markers_are_captured() -> None:
    src = BrainFlowSource()
    src.start()
    try:
        time.sleep(0.5)
        src.insert_marker(7.0)
        time.sleep(0.5)
        src.poll()
    finally:
        src.stop()
    assert [v for _, v in src.markers] == [7.0]


# --- LSL: three parallel streams ------------------------------------------------------------------


ECG = (ChannelSpec("ecg", Modality.ECG, "mV"),)


def ecg_signal(n: int, rate: float) -> np.ndarray:
    t = np.arange(n) / rate
    return (np.sin(2 * np.pi * 1.2 * t) ** 63).reshape(-1, 1)  # sharp peaks at 72 bpm


def test_three_parallel_streams_ordering_clock_dropout() -> None:
    tag = uuid.uuid4().hex[:8]
    bf = BrainFlowSource()
    eeg_specs = tuple(c for c in bf.layout.channels if c.modality is Modality.EEG)
    eeg_out = SignalOutlet(f"eeg-{tag}", "EEG", eeg_specs, bf.layout.rate_hz, f"eeg-{tag}")
    ecg_out = SignalOutlet(f"ecg-{tag}", "ECG", ECG, 250.0, f"ecg-{tag}")
    mk_out = MarkerOutlet(f"mk-{tag}", f"mk-{tag}")
    (eeg_s,) = discover("name", f"eeg-{tag}")
    (ecg_s,) = discover("name", f"ecg-{tag}")
    (mk_s,) = discover("name", f"mk-{tag}")
    eeg_in, ecg_in, mk_in = (
        SignalInlet(eeg_s, eeg_specs),
        SignalInlet(ecg_s, ECG),
        MarkerInlet(mk_s),
    )
    for inlet in (eeg_in, ecg_in, mk_in):
        inlet.open()
    offset = unix_to_lsl_offset_s()
    ecg = ecg_signal(1000, 250.0)
    t0 = local_clock()
    ecg_ts = t0 + np.arange(1000) / 250.0
    keep = np.ones(1000, dtype=bool)
    keep[400:425] = False  # a 25-sample dropout in the sender
    got: dict[str, list[SampleBlock]] = {"eeg": [], "ecg": []}
    labels_sent = []
    bf.start()
    try:
        ecg_out.push(ecg[keep], ecg_ts[keep])
        for k in range(3):
            labels_sent.append(f"event-{k}")
            mk_out.push(labels_sent[-1])
            time.sleep(0.5)
            b = bf.poll()
            if b is not None:
                eeg_idx = [i for i, c in enumerate(b.channels) if c.modality is Modality.EEG]
                eeg_out.push(b.values[:, eeg_idx], b.timestamps_ns / 1e9 + offset)
            for name, inlet in (("eeg", eeg_in), ("ecg", ecg_in)):
                blk = inlet.pull(timeout=0.2)
                if blk is not None:
                    got[name].append(blk)
        time.sleep(0.5)
        for name, inlet in (("eeg", eeg_in), ("ecg", ecg_in)):
            while (blk := inlet.pull(timeout=0.2)) is not None:
                got[name].append(blk)
        markers = mk_in.pull(timeout=1.0)
        corr = ecg_in.update_clock()
    finally:
        bf.stop()
        for closable in (eeg_in, ecg_in, mk_in, eeg_out, ecg_out, mk_out):
            closable.close()
    eeg, ecg_rx = concat(got["eeg"]), concat(got["ecg"])
    assert analyze(eeg).non_monotonic == 0
    rep = analyze(ecg_rx)
    assert rep.non_monotonic == 0
    assert (rep.gaps, rep.dropped_estimate) == (1, 25)  # the sender-side dropout is visible
    np.testing.assert_allclose(ecg_rx.values, ecg[keep], atol=1e-6)  # float32 transport
    assert list(markers.labels) == labels_sent  # ordered
    assert abs(corr) < 0.01  # same host: clock correction ~ 0
    shifted = corrected(ecg_rx, corr)
    assert shifted.clock_domain == "lsl-local"
    assert ecg_in.clock.latest() == corr


def test_lsl_replay_reproduces_a_recording() -> None:
    tag = uuid.uuid4().hex[:8]
    n = 500
    values = ecg_signal(n, 250.0)
    values[100] = np.nan  # a dropout in the recording
    rec = SampleBlock(
        stream="ecg",
        channels=ECG,
        timestamps_ns=(np.arange(n) * 4_000_000).astype(np.int64),
        values=values,
        device=DeviceMetadata(device_id="rec-1", kind="replay"),
        clock_domain="file",
        nominal_rate_hz=250.0,
    )
    replay = ReplayOutlet(rec, f"rp-{tag}", "ECG", f"rp-{tag}")
    (s,) = discover("name", f"rp-{tag}")
    inlet = SignalInlet(s, ECG)
    inlet.open()
    time.sleep(0.2)
    pushed = replay.run(speed=10.0)
    blocks = []
    time.sleep(0.3)
    while (b := inlet.pull(timeout=0.3)) is not None:
        blocks.append(b)
    inlet.close()
    replay.outlet.close()
    out = concat(blocks)
    assert pushed == out.n_samples == n - 1  # the dropout stays missing, not zero
    np.testing.assert_allclose(out.values[:, 0], np.delete(values[:, 0], 100), atol=1e-6)
    rel = (out.timestamps_ns - out.timestamps_ns[0]) / 1e9
    expected = np.delete(np.arange(n) * 0.004, 100) / 10.0
    np.testing.assert_allclose(rel, expected, atol=1e-6)  # original relative timing, 10x


@pytest.mark.dataset
@pytest.mark.skipif(not (DATA / "xdf-example-files").exists(), reason="run fetch_datasets.py")
def test_xdf_recording_replays_through_lsl() -> None:
    biosemi = read_xdf(DATA / "xdf-example-files" / "clock_resets.xdf").block("biosemi")
    head = SampleBlock(
        stream=biosemi.stream,
        channels=biosemi.channels,
        timestamps_ns=np.array(biosemi.timestamps_ns[:300]),
        values=np.array(biosemi.values[:300]),
        device=biosemi.device,
        clock_domain=biosemi.clock_domain,
        nominal_rate_hz=biosemi.nominal_rate_hz,
    )
    tag = uuid.uuid4().hex[:8]
    replay = ReplayOutlet(head, f"x-{tag}", "EEG", f"x-{tag}")
    (s,) = discover("name", f"x-{tag}")
    inlet = SignalInlet(s, head.channels)
    inlet.open()
    time.sleep(0.2)
    replay.run(speed=20.0)
    time.sleep(0.3)
    blocks = []
    while (b := inlet.pull(timeout=0.3)) is not None:
        blocks.append(b)
    inlet.close()
    replay.outlet.close()
    out = concat(blocks)
    np.testing.assert_allclose(out.values, head.values, rtol=1e-6, atol=1e-3)
