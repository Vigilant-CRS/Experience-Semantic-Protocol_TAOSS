# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M4 gate: ESP over QUIC and impaired networks (plan section 54, M4).

Network emulator grid: 0-200 ms latency, 0-10 % loss, 0-50 ms jitter
(jitter reorders). Required: control semantics preserved, no revoked data
accepted, session state consistent. ``run_milestone.py M4`` sets
``ESP_REPORT_DIR`` and embeds the per-condition metrics in the report.
"""

import asyncio
import itertools
import json
import math
import os
import re
from collections.abc import Iterator
from pathlib import Path

import pytest

from esp.transport.base import Channel
from esp.transport.memory import FaultProfile
from tests.integration.test_transport import (
    run_session,
    test_panic_and_sos_arrive_under_loss_and_stop_data,
)

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]
GRID = [
    FaultProfile(latency_s=lat, jitter_s=jit, loss=loss, seed=100 + i)
    for i, (lat, jit, loss) in enumerate(itertools.product((0.0, 0.2), (0.0, 0.05), (0.0, 0.1)))
]
METRICS: dict[str, dict[str, float | None]] = {}


@pytest.fixture(scope="module", autouse=True)
def _write_metrics() -> Iterator[None]:
    yield
    out = os.environ.get("ESP_REPORT_DIR")
    if out and METRICS:
        Path(out, "M4-metrics.json").write_text(
            json.dumps(METRICS, indent=2, sort_keys=True, allow_nan=False) + "\n",
            encoding="utf-8",
        )


def test_m4_work_packages_verified() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    for wp in ("WP-023", "WP-024", "WP-062", "WP-063", "WP-064"):
        m = re.search(rf"^## {wp} — .*?\*\*Status:\*\* `([A-Z_]+)`", plan, re.S | re.M)
        assert m is not None
        assert m.group(1) == "VERIFIED", wp


def label(p: FaultProfile) -> str:
    return (
        f"lat{int(p.latency_s * 1000)}ms-jit{int(p.jitter_s * 1000)}ms-loss{int(p.loss * 100)}pct"
    )


@pytest.mark.parametrize("profile", GRID, ids=label)
@pytest.mark.parametrize("channel", [Channel.STATE, Channel.DATAGRAM])
def test_m4_network_grid(tmp_path: Path, profile: FaultProfile, channel: Channel) -> None:
    pump, sent = asyncio.run(run_session(tmp_path, profile, channel=channel))
    d = pump.metrics.deliveries
    revoked_at = next(
        i for i, x in enumerate(d) if x.channel is Channel.CONTROL and x.result.control
    )
    assert all(not x.result.accepted for x in d[revoked_at + 1 :])  # no revoked data accepted
    assert all(x.result.frame is None for x in d if not x.result.accepted)  # quarantine held
    if channel is Channel.STATE:
        assert pump.metrics.accepted_frames == sent  # control/state semantics preserved
    report = pump.report(frames_sent=sent)
    METRICS[f"{channel.name}/{label(profile)}"] = {
        k: None if math.isnan(v) else round(v, 3) for k, v in report.items()
    }


def test_m4_panic_closes_the_session_under_loss(tmp_path: Path) -> None:
    """PANIC and SOS on CONTROL under 10 % loss; the receiver ends CLOSED (asserted inside)."""
    test_panic_and_sos_arrive_under_loss_and_stop_data(tmp_path)
