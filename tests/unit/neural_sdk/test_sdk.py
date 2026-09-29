# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-090: neural vendor SDK — contract surface, base classes, JSON lines, Rust mirror."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest
from numpy.typing import NDArray

from esp.adapters.neural import SimulatedNeuralAdapter, band_features
from esp.adapters.neural import interface as neural_interface
from esp.adapters.neural import model as neural_model
from esp.core.taoss_types import L1_DIMS, TaossType
from esp.neural_sdk import (
    CONTRACT_VERSION,
    AdapterStateError,
    BlockAdapter,
    NeuralAdapter,
    NeuralDecoder,
    NeuralFeatures,
    TypedDecoderBase,
    check_adapter_contract,
    check_decoder_contract,
    decode_boundary,
    describe_contract,
    regular_timestamps,
)
from esp.neural_sdk.example import example_adapter, example_decoder
from esp.neural_sdk.jsonl import (
    JsonLinesAdapter,
    block_to_json,
    dump_adapter,
    info_from_json,
    info_to_json,
)
from esp.observation.units import UNITS

pytestmark = pytest.mark.security
ROOT = Path(__file__).resolve().parents[3]
RUST = (ROOT / "rust" / "esp-rs" / "src" / "neural.rs").read_text(encoding="utf-8")


def _rust_list(name: str) -> set[str]:
    m = re.search(rf"const {name}: &\[&str\] = &\[(.*?)\];", RUST, re.S)
    assert m is not None, name
    return set(re.findall(r'"([^"]*)"', m.group(1)))


# --- contract surface -----------------------------------------------------------------------------


def test_contract_is_versioned_and_described() -> None:
    d = describe_contract()
    assert d["contract_version"] == CONTRACT_VERSION == "1.0.0"
    assert set(d["units"]) == set(UNITS)
    assert set(d["modalities"]["invasive_replay_only"]) == {m.value for m in neural_model.INVASIVE}
    assert d["profiles"] == ["L3-LIVE", "L4-REPLAY", "L4-LIVE"]


def test_rust_mirror_uses_the_same_contract_constants() -> None:
    """Drift guard: the Rust checker must use exactly the Python sets and words."""
    assert f'CONTRACT_VERSION: &str = "{CONTRACT_VERSION}"' in RUST
    assert _rust_list("UNITS") == set(UNITS)
    assert _rust_list("NON_INVASIVE") == {m.value for m in neural_model.NON_INVASIVE}
    assert _rust_list("INVASIVE") == {m.value for m in neural_model.INVASIVE}
    assert _rust_list("AUXILIARY") == {m.value for m in neural_model.AUXILIARY}
    assert _rust_list("OPEN_LICENSES") == set(neural_model.OPEN_LICENSES)
    words = re.search(r"\((emo\|[^)]*)\)", neural_interface._INTERPRETIVE.pattern)
    assert words is not None
    assert _rust_list("INTERPRETIVE") == set(words.group(1).split("|"))


def test_example_vendor_adapter_and_decoder_pass() -> None:
    a = example_adapter()
    assert isinstance(a, NeuralAdapter)
    report = check_adapter_contract(a)
    assert report.ok, report.violations
    assert a.info.replay is not None  # invasive ECoG only as a declared recording
    a.start()
    block = a.read(512)
    a.stop()
    assert block is not None
    f = band_features(block)
    dec = example_decoder(len(f.names))
    assert isinstance(dec, NeuralDecoder)
    assert check_decoder_contract(dec, f).ok
    out = decode_boundary(dec, f, frozenset({TaossType.INT, TaossType.EMO}))
    assert set(out) == {TaossType.INT}  # EMO neither declared nor ever produced


# --- base classes ---------------------------------------------------------------------------------


class _Scripted(BlockAdapter):
    def __init__(self, chunks: list[tuple[NDArray[np.int64], NDArray[np.float64]]]) -> None:
        super().__init__(SimulatedNeuralAdapter(0, n_channels=2).info)
        self.chunks = chunks

    def acquire(self, max_samples: int) -> tuple[NDArray[np.int64], NDArray[np.float64]] | None:
        return self.chunks.pop(0) if self.chunks else None


def _chunk(start: int, n: int = 4) -> tuple[NDArray[np.int64], NDArray[np.float64]]:
    return regular_timestamps(start, n, 256.0), np.zeros((n, 2))


def test_block_adapter_builds_declared_blocks() -> None:
    a = _Scripted([_chunk(0), _chunk(10**9)])
    report = check_adapter_contract(a)
    assert report.ok
    assert report.blocks == 2


def test_block_adapter_refuses_reads_before_start() -> None:
    with pytest.raises(AdapterStateError, match="not started"):
        _Scripted([_chunk(0)]).read(8)


@pytest.mark.parametrize(
    ("chunks", "match"),
    [
        ([_chunk(10**9), _chunk(0)], "increase"),
        ([(np.array([0, 5, 5, 9], dtype=np.int64), np.zeros((4, 2)))], "increase"),
        ([(np.array([0.0, 1.0]), np.zeros((2, 2)))], "int64"),
        ([_chunk(0, n=9)], "max_samples"),
    ],
)
def test_block_adapter_never_repairs_a_broken_clock(
    chunks: list[tuple[NDArray[np.int64], NDArray[np.float64]]], match: str
) -> None:
    a = _Scripted(chunks)
    a.start()
    for _ in range(len(chunks) - 1):
        a.read(8)  # the chunks before the broken one are fine
    with pytest.raises(AdapterStateError, match=match):
        a.read(8)


def test_typed_decoder_answers_only_requested_types() -> None:
    class Dec(TypedDecoderBase):
        def decode_one(self, t: TaossType, features: NeuralFeatures) -> NDArray[np.float64]:
            return np.zeros(L1_DIMS[t])

    feats = band_features(_block())
    d = Dec(frozenset({TaossType.SEN, TaossType.TEM}))
    assert set(d.decode(feats, frozenset({TaossType.TEM, TaossType.EMO}))) == {TaossType.TEM}


def _block():  # type: ignore[no-untyped-def]
    a = SimulatedNeuralAdapter(2, n_channels=2)
    a.start()
    return a.read(512)


# --- JSON lines -----------------------------------------------------------------------------------


def test_info_roundtrips_through_json() -> None:
    for info in (example_adapter().info, SimulatedNeuralAdapter(3).info):
        raw = json.loads(json.dumps(info_to_json(info, CONTRACT_VERSION)))
        assert info_from_json(raw) == info


def test_transcript_replays_byte_identical_blocks() -> None:
    lines = dump_adapter(example_adapter(), CONTRACT_VERSION, reads=4, max_samples=100)
    replay = JsonLinesAdapter.parse(lines)
    assert replay.contract_version == CONTRACT_VERSION
    direct = example_adapter()
    direct.start()
    replay.start()
    for _ in range(4):
        a, b = direct.read(100), replay.read(100)
        assert a is not None
        assert b is not None
        assert a.digest() == b.digest()
    assert check_adapter_contract(replay, max_samples=100).ok


def test_malformed_read_and_verdict_line() -> None:
    lines = dump_adapter(SimulatedNeuralAdapter(1), CONTRACT_VERSION, reads=2, max_samples=32)
    lines.insert(2, json.dumps({"type": "garbage"}))
    lines.append(json.dumps({"type": "verdict", "ok": False, "violations": []}))
    adapter = JsonLinesAdapter.parse(lines)
    assert adapter.verdict is not None
    report = check_adapter_contract(adapter, max_samples=32)
    assert {v.rule for v in report.violations} == {"output"}
    with pytest.raises(ValueError, match="declaration"):
        JsonLinesAdapter.parse(lines[1:])


def test_block_json_is_plain_data() -> None:
    doc = block_to_json(_block())
    assert doc["type"] == "block"
    assert all(isinstance(t, int) for t in doc["timestamps_ns"])
    json.dumps(doc)


def test_vendor_example_script_runs() -> None:
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    out = subprocess.run(
        [sys.executable, str(ROOT / "examples" / "neural_vendor_adapter" / "vendor_adapter.py")],
        capture_output=True,
        text=True,
        env=env,
        timeout=120,
        check=False,
    )
    assert out.returncode == 0, out.stdout + out.stderr
    assert "adapter PASS" in out.stdout
    assert "decoder PASS" in out.stdout
