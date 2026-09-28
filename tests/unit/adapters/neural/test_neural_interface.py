# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-045: neural adapter interface, decoder boundary and simulator contract."""

import dataclasses
from collections.abc import Mapping

import numpy as np
import pytest
from numpy.typing import NDArray

from esp.adapters.neural import (
    NeuralAdapter,
    NeuralAdapterInfo,
    NeuralDecoder,
    NeuralFeatures,
    NeuralLevel,
    SimulatedNeuralAdapter,
    SimulatorDecoder,
    band_features,
    check_adapter_contract,
    check_decoder_contract,
    decode_boundary,
)
from esp.adapters.neural.interface import ContractError
from esp.adapters.physio.stream import ChannelSpec, SampleBlock, concat
from esp.core.taoss_types import L1_DIMS, TaossType
from esp.observation.model import Modality

T = TaossType


def features(seed: int = 0) -> NeuralFeatures:
    a = SimulatedNeuralAdapter(seed, n_channels=4)
    a.start()
    block = a.read(1024)
    assert block is not None
    return band_features(block)


def test_simulator_satisfies_protocols_and_contract() -> None:
    a = SimulatedNeuralAdapter(1)
    assert isinstance(a, NeuralAdapter)
    report = check_adapter_contract(a, reads=5, max_samples=128)
    assert report.ok, report.violations
    assert report.blocks == 5
    assert report.samples == 640
    assert isinstance(SimulatorDecoder(4), NeuralDecoder)


def test_simulator_is_deterministic_across_chunkings() -> None:
    def run(chunk: int) -> str:
        a = SimulatedNeuralAdapter(7, total_samples=1000)
        a.start()
        blocks = []
        while (b := a.read(chunk)) is not None:
            blocks.append(b)
        return concat(blocks).digest()

    assert run(64) == run(100) == run(1000)
    a = SimulatedNeuralAdapter(8, total_samples=1000)
    a.start()
    first = a.read(1000)
    assert first is not None
    assert first.digest() != run(64)


def test_simulator_rhythm_is_in_alpha_band() -> None:
    f = features()
    alpha = [v for n, v in zip(f.names, f.values, strict=True) if n.endswith(".alpha")]
    beta = [v for n, v in zip(f.names, f.values, strict=True) if n.endswith(".beta")]
    assert min(alpha) > max(beta)


class _Wrapper:
    """An adapter whose declaration or output is broken in one controlled way."""

    def __init__(self, info: NeuralAdapterInfo, blocks: list[object]) -> None:
        self._info, self._blocks = info, blocks

    @property
    def info(self) -> NeuralAdapterInfo:
        return self._info

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def read(self, max_samples: int) -> SampleBlock | None:
        return self._blocks.pop(0) if self._blocks else None  # type: ignore[return-value]


def _sim_blocks(n: int = 3) -> tuple[NeuralAdapterInfo, list[SampleBlock]]:
    a = SimulatedNeuralAdapter(2)
    a.start()
    return a.info, [b for _ in range(n) if (b := a.read(64)) is not None]


def _rules(adapter: _Wrapper) -> set[str]:
    return {v.rule for v in check_adapter_contract(adapter).violations}


def test_invasive_level_refused() -> None:
    info, blocks = _sim_blocks()
    assert _rules(_Wrapper(dataclasses.replace(info, level=NeuralLevel.L4_INVASIVE), blocks)) == {
        "level"
    }


@pytest.mark.parametrize("name", ["valence", "fz_emotion", "stress.index", "fear", "intent-1"])
def test_interpretive_channel_names_refused(name: str) -> None:
    info, _ = _sim_blocks()
    bad = (ChannelSpec(name, Modality.EEG, "uV"), *info.channels[1:])
    assert "neutral" in _rules(_Wrapper(dataclasses.replace(info, channels=bad), []))


def test_non_neural_modality_and_bad_unit_refused() -> None:
    info, _ = _sim_blocks()
    bad = (ChannelSpec("fz", Modality.TEXT, "furlong"), *info.channels[1:])
    rules = _rules(_Wrapper(dataclasses.replace(info, channels=bad), []))
    assert {"modality", "unit"} <= rules


def test_output_must_be_sample_blocks() -> None:
    info, _ = _sim_blocks()
    assert "output" in _rules(_Wrapper(info, [{"fear": 0.9}]))
    assert "output" in _rules(_Wrapper(info, []))  # nothing at all


def test_timestamps_must_increase_across_blocks() -> None:
    info, blocks = _sim_blocks()
    assert "clock" in _rules(_Wrapper(info, [blocks[1], blocks[0]]))


def test_block_identity_must_match_declaration() -> None:
    info, blocks = _sim_blocks()
    other = dataclasses.replace(blocks[0], clock_domain="other")
    assert "identity" in _rules(_Wrapper(info, [other]))


def test_decode_boundary_requests_only_consented_types() -> None:
    f = features()
    seen: list[frozenset[TaossType]] = []

    class Spy(SimulatorDecoder):
        def decode(
            self, features: NeuralFeatures, types: frozenset[TaossType]
        ) -> dict[TaossType, NDArray[np.float64]]:
            seen.append(types)
            return super().decode(features, types)

    dec = Spy(len(f.names), output_types=(T.SEN, T.TEM, T.EMO))
    out = decode_boundary(dec, f, frozenset({T.SEN, T.KNO}))
    assert set(out) == {T.SEN}
    assert seen == [frozenset({T.SEN})]
    assert out[T.SEN].shape == (L1_DIMS[T.SEN],)
    assert decode_boundary(dec, f, frozenset()) == {}
    assert len(seen) == 1  # nothing consented: the decoder is never called


class _Bad:
    decoder_id = "bad@0"

    def __init__(self, out: Mapping[TaossType, NDArray[np.float64]]) -> None:
        self._out = out

    @property
    def output_types(self) -> frozenset[TaossType]:
        return frozenset({T.SEN})

    def decode(
        self, features: NeuralFeatures, types: frozenset[TaossType]
    ) -> Mapping[TaossType, NDArray[np.float64]]:
        return self._out


@pytest.mark.parametrize(
    "out",
    [
        {T.SEN: np.zeros(64), T.EMO: np.zeros(64)},  # undeclared extra type
        {},  # missing type
        {T.SEN: np.zeros(63)},  # wrong dimension
        {T.SEN: np.full(64, np.nan)},  # non-finite
    ],
)
def test_malformed_decoder_output_is_discarded(
    out: Mapping[TaossType, NDArray[np.float64]],
) -> None:
    with pytest.raises(ContractError):
        decode_boundary(_Bad(out), features(), frozenset({T.SEN}))
    assert not check_decoder_contract(_Bad(out), features()).ok


def test_simulator_decoder_contract_and_determinism() -> None:
    f = features()
    dec = SimulatorDecoder(len(f.names))
    assert check_decoder_contract(dec, f).ok
    a = decode_boundary(dec, f, frozenset(T))
    b = decode_boundary(SimulatorDecoder(len(f.names)), f, frozenset(T))
    assert set(a) == {T.SEN, T.TEM}
    assert all(np.array_equal(a[t], b[t]) for t in a)


def test_interpretive_feature_names_flagged() -> None:
    f = features()
    bad = dataclasses.replace(f, names=("arousal.index", *f.names[1:]))
    assert "neutral" in {
        v.rule for v in check_decoder_contract(SimulatorDecoder(len(f.names)), bad).violations
    }


def test_features_validate_shape() -> None:
    f = features()
    with pytest.raises(ValueError, match="one value"):
        dataclasses.replace(f, values=f.values[:-1])
    with pytest.raises(ValueError, match="unique"):
        dataclasses.replace(f, names=(f.names[0], *f.names[:-1]))
