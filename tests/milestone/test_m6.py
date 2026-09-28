# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M6 gate: physiology-ready without real hardware.

BrainFlow synthetic board -> LSL outlet -> LSL inlet, plus an LSL event
stream, with sliding-window features, for ``ESP_SOAK_SECONDS`` (the gate run
uses 1800 s = 30 minutes; the regular suite 20 s). Measured: dropped samples,
clock error, memory, CPU, timestamp monotonicity. Replay must be reproducible.
"""

import json
import os
import re
import resource
import time
import uuid
from pathlib import Path

import numpy as np
import pytest
from brainflow.board_shim import BoardIds

from esp.adapters.physio.brainflow_adapter import (
    BrainFlowSource,
    playback_params,
    record_to_file,
)
from esp.adapters.physio.lsl_adapter import (
    MarkerInlet,
    MarkerOutlet,
    SignalInlet,
    SignalOutlet,
    discover,
    unix_to_lsl_offset_s,
)
from esp.adapters.physio.stream import analyze
from esp.features.physio import eeg_band_powers
from esp.observation.model import Modality
from tests.integration.test_physio_streams import run_brainflow

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]
SOAK_S = float(os.environ.get("ESP_SOAK_SECONDS", "20"))


def rss_mb() -> float:
    with open("/proc/self/status", encoding="ascii") as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) / 1024
    return float(resource.getrusage(resource.RUSAGE_SELF).ru_maxrss) / 1024  # pragma: no cover


def test_m6_work_packages_verified() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    for wp in ("WP-026", "WP-027", "WP-028", "WP-029"):
        m = re.search(rf"^## {wp} — .*?\*\*Status:\*\* `([A-Z_]+)`", plan, re.S | re.M)
        assert m is not None
        assert m.group(1) == "VERIFIED", wp


def test_m6_soak_brainflow_lsl_events() -> None:
    tag = uuid.uuid4().hex[:8]
    bf = BrainFlowSource()
    eeg_idx = [i for i, c in enumerate(bf.layout.channels) if c.modality is Modality.EEG]
    specs = tuple(bf.layout.channels[i] for i in eeg_idx)
    out = SignalOutlet(f"soak-eeg-{tag}", "EEG", specs, bf.layout.rate_hz, f"soak-eeg-{tag}")
    markers = MarkerOutlet(f"soak-mk-{tag}", f"soak-mk-{tag}")
    (eeg_s,) = discover("name", f"soak-eeg-{tag}")
    (mk_s,) = discover("name", f"soak-mk-{tag}")
    eeg_in, mk_in = SignalInlet(eeg_s, specs), MarkerInlet(mk_s)
    eeg_in.open()
    mk_in.open()
    offset = unix_to_lsl_offset_s()
    received = sent = gaps = non_mono = sent_markers = feature_windows = 0
    got_markers: list[str] = []
    last_ts: int | None = None
    lags: list[float] = []
    corrections: list[float] = []
    window: list[np.ndarray] = []
    rss: list[float] = []
    cpu0, wall0 = time.process_time(), time.monotonic()
    next_marker = next_probe = wall0
    bf.start()
    try:
        while time.monotonic() - wall0 < SOAK_S:
            time.sleep(0.1)
            now = time.monotonic()
            b = bf.poll()
            if b is not None:
                lags.append(time.time() - b.timestamps_ns[-1] / 1e9)
                out.push(b.values[:, eeg_idx], b.timestamps_ns / 1e9 + offset)
                sent += b.n_samples
            if now >= next_marker:
                markers.push(f"m{sent_markers}")
                sent_markers += 1
                next_marker += 1.0
            while (blk := eeg_in.pull(timeout=0.0)) is not None:
                r = analyze(blk)
                received += blk.n_samples
                gaps += r.gaps
                non_mono += r.non_monotonic
                if last_ts is not None:
                    step = int(blk.timestamps_ns[0]) - last_ts
                    non_mono += step <= 0
                    gaps += step > 1.5 * 1e9 / bf.layout.rate_hz
                last_ts = int(blk.timestamps_ns[-1])
                window.append(blk.values[:, 0])
            if sum(w.size for w in window) >= 10 * bf.layout.rate_hz:  # 10-s feature windows
                eeg_band_powers(np.concatenate(window), bf.layout.rate_hz, 0)
                feature_windows += 1
                window.clear()
            got_markers += list(mk_in.pull().labels)
            if now >= next_probe:
                corrections.append(eeg_in.update_clock(timeout=1.0))
                rss.append(rss_mb())
                next_probe += max(1.0, SOAK_S / 60)
    finally:
        bf.stop()
    time.sleep(0.5)
    while (blk := eeg_in.pull(timeout=0.2)) is not None:
        received += blk.n_samples
    got_markers += list(mk_in.pull(timeout=0.5).labels)
    for closable in (eeg_in, mk_in, out, markers):
        closable.close()
    wall = time.monotonic() - wall0
    cpu = (time.process_time() - cpu0) / wall
    warm = rss[max(1, len(rss) // 10)] if len(rss) > 1 else rss[0]
    metrics = {
        "duration_s": round(wall, 1),
        "samples_received": received,
        "brainflow_dropped": bf.dropped,
        "samples_sent_to_lsl": sent,
        "lsl_lost": sent - received,
        "timestamp_gaps_over_1_5_periods": gaps,
        "non_monotonic": non_mono,
        "clock_correction_max_ms": round(1000 * max(abs(c) for c in corrections), 3),
        "brainflow_lag_p99_ms": round(1000 * float(np.percentile(lags, 99)), 1),
        "rss_start_mb": round(rss[0], 1),
        "rss_growth_after_warmup_mb": round(max(rss) - warm, 1),
        "cpu_fraction_of_one_core": round(cpu, 3),
        "markers_sent": sent_markers,
        "markers_received": len(got_markers),
        "feature_windows": feature_windows,
    }
    report_dir = os.environ.get("ESP_REPORT_DIR")
    if report_dir:
        Path(report_dir, "M6-metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
    assert bf.dropped == 0, metrics
    assert sent == received, metrics  # LSL loses nothing; timestamp jitter gaps are reported
    assert non_mono == 0, metrics
    assert received >= 0.95 * SOAK_S * bf.layout.rate_hz, metrics
    assert metrics["clock_correction_max_ms"] < 5.0, metrics
    assert metrics["brainflow_lag_p99_ms"] < 1000, metrics
    assert metrics["rss_growth_after_warmup_mb"] < 64, metrics
    assert cpu < 0.9, metrics
    assert got_markers == [f"m{i}" for i in range(sent_markers)], metrics  # all, in order
    assert feature_windows >= int(SOAK_S // 10) - 1, metrics


def test_m6_replay_is_reproducible(tmp_path: Path) -> None:
    _, raw = run_brainflow(BrainFlowSource(), 2.0)
    f = tmp_path / "s.csv"
    record_to_file(raw, f)
    digests = []
    for _ in range(2):
        pb = BrainFlowSource(
            BoardIds.PLAYBACK_FILE_BOARD, playback_params(f), layout_board=BoardIds.SYNTHETIC_BOARD
        )
        block, _ = run_brainflow(pb, 2.5)
        digests.append(hash(block.values[: raw.shape[1]].tobytes()))
    assert digests[0] == digests[1]
