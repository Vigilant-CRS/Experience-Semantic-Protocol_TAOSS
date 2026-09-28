# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-043: performance and rate benchmarks (smoke-sized)."""

import pytest

from esp.codec.tlv import LatentEncoding
from esp.perf import RATES_HZ, bench_profile, network_latency

pytestmark = pytest.mark.integration


@pytest.mark.parametrize("sf", [0, 7])
@pytest.mark.parametrize("encoding", [LatentEncoding.F32_BE, LatentEncoding.INT8_SYM])
def test_wire_size_matches_v13_and_50hz_is_sustainable(sf: int, encoding: LatentEncoding) -> None:
    r = bench_profile(sf, encoding, n=40)
    assert r["wire_bytes_per_frame"] == r["v13_bytes_per_release"]  # V13 rate arithmetic holds
    assert set(r["kbit_s"]) == {f"{hz}Hz" for hz in RATES_HZ}
    assert r["total_send_receive"]["p99_ms"] < 20.0  # 50 Hz budget per frame, generous
    assert r["max_sustainable_hz"] >= max(RATES_HZ)
    assert r["peak_memory_kib"] < 16 * 1024
    for part in ("encode", "open_verify_decrypt", "decode", "total_send_receive"):
        assert r[part]["p50_ms"] > 0


def test_network_latency_over_memory_link() -> None:
    r = network_latency(n=20, latency_s=0.01)
    assert r["frames"] == 20
    assert 10.0 <= r["p50_ms"] < 100.0
