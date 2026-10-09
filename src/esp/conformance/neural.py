# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Neural conformance category (WP-090): ``esp-conformance run`` → ``neural``.

1. **Reference sources pass.** These are the WP-045 simulator, the SDK example
   vendor adapter (declared ``L4-REPLAY``) and the reference decoders.
2. **Every broken source fails for the right reason.** Each built-in broken
   adapter or decoder must be refused, with the expected rule. A checker that
   accepts any of them is itself non-conformant.
3. **External adapters.** ``--neural-adapter module:factory`` loads a vendor
   adapter and requires a clean contract report.
4. **Cross-implementation.** ``--neural-rust <esp-rs>`` runs
   ``esp-rs neural-sim`` for every break mode and replays the JSON lines.
   The Rust simulator and the Rust contract checker must agree with the
   Python checker: same verdict, same rules, same contract version.
"""

from __future__ import annotations

import dataclasses
import importlib
import subprocess
from collections.abc import Callable, Mapping
from functools import partial
from pathlib import Path
from typing import Any, Final

import numpy as np
from numpy.typing import NDArray

from esp.adapters.neural import SimulatedNeuralAdapter, SimulatorDecoder, band_features
from esp.adapters.neural.interface import (
    ContractReport,
    NeuralAdapter,
    NeuralAdapterInfo,
    NeuralDecoder,
    NeuralFeatures,
    NeuralLevel,
    check_adapter_contract,
    check_decoder_contract,
)
from esp.adapters.physio.stream import ChannelSpec, SampleBlock
from esp.core.taoss_types import L1_DIMS, TaossType
from esp.neural_sdk import CONTRACT_VERSION
from esp.neural_sdk.example import example_adapter, example_decoder
from esp.neural_sdk.jsonl import JsonLinesAdapter
from esp.observation.model import Modality

#: esp-rs neural-sim break modes and the rules both implementations must report
RUST_BREAK_MODES: Final[Mapping[str, frozenset[str]]] = {
    "none": frozenset(),
    "l4-replay": frozenset(),
    "non-monotonic-clock": frozenset({"clock"}),
    "interpretive-channel": frozenset({"neutral"}),
    "l4-live-undeclared": frozenset({"level"}),
    "channel-change": frozenset({"channels"}),
    "identity-change": frozenset({"identity"}),
    "oversize-block": frozenset({"size"}),
    "wrong-block-type": frozenset({"output"}),
    "bad-unit": frozenset({"unit"}),
    "replay-closed-license": frozenset({"replay:replay"}),
}
#: modes of the C example adapter (examples/neural_vendor_adapter_c) and the rules both
#: the Rust host (`esp-rs neural-capi`) and Python must report for them
C_EXAMPLE_MODES: Final[Mapping[str, frozenset[str]]] = {
    "": frozenset(),
    "l4-replay": frozenset(),
    "nan-dropout": frozenset(),
    "non-monotonic-clock": frozenset({"clock"}),
    "interpretive-channel": frozenset({"neutral"}),
    "l4-live-undeclared": frozenset({"level"}),
    "null-buffer": frozenset({"output"}),
    "length-mismatch": frozenset({"channels"}),
    "inf-sample": frozenset({"output"}),
    "read-error": frozenset({"output"}),
}
RUST_BLOCKS: Final = 4
RUST_SAMPLES: Final = 64


class NeuralConformanceError(AssertionError):
    pass


def _require(ok: bool, msg: str) -> None:
    if not ok:
        raise NeuralConformanceError(msg)


def _rules(report: ContractReport) -> frozenset[str]:
    return frozenset(v.rule for v in report.violations)


# --- broken adapters ------------------------------------------------------------------------------


class _Scripted:
    """An adapter replaying a fixed list of reads under a (possibly wrong) declaration."""

    def __init__(self, info: NeuralAdapterInfo, reads: list[object]) -> None:
        self._info, self._reads, self._i = info, reads, 0

    @property
    def info(self) -> NeuralAdapterInfo:
        return self._info

    def start(self) -> None:
        self._i = 0

    def stop(self) -> None:
        pass

    def read(self, max_samples: int) -> SampleBlock | None:
        if self._i >= len(self._reads):
            return None
        r = self._reads[self._i]
        self._i += 1
        return r  # type: ignore[return-value]


def _sim(n_blocks: int = 3, size: int = 64) -> tuple[NeuralAdapterInfo, list[SampleBlock]]:
    a = SimulatedNeuralAdapter(3, n_channels=4)
    a.start()
    blocks = [b for _ in range(n_blocks) if (b := a.read(size)) is not None]
    a.stop()
    return a.info, blocks


def _non_monotonic() -> NeuralAdapter:
    info, blocks = _sim()
    b = blocks[1]
    ts = np.array(b.timestamps_ns)
    ts[5] = ts[4]
    return _Scripted(info, [blocks[0], dataclasses.replace(b, timestamps_ns=ts), blocks[2]])


def _interpretive() -> NeuralAdapter:
    info, blocks = _sim()
    chans = (ChannelSpec("valence", Modality.EEG, "uV"), *info.channels[1:])
    return _Scripted(
        dataclasses.replace(info, channels=chans),
        [dataclasses.replace(b, channels=chans) for b in blocks],
    )


def _l4_live() -> NeuralAdapter:
    info, blocks = _sim()
    return _Scripted(dataclasses.replace(info, level=NeuralLevel.L4_INVASIVE), list(blocks))


def _wrong_type() -> NeuralAdapter:
    info, blocks = _sim()
    return _Scripted(info, [blocks[0], {"not": "a block"}])


def _channel_change() -> NeuralAdapter:
    info, blocks = _sim()
    swapped = (info.channels[1], info.channels[0], *info.channels[2:])
    b = blocks[1]
    return _Scripted(info, [blocks[0], dataclasses.replace(b, channels=swapped), blocks[2]])


def _identity_change() -> NeuralAdapter:
    info, blocks = _sim()
    return _Scripted(
        info, [blocks[0], dataclasses.replace(blocks[1], clock_domain="other:mono"), blocks[2]]
    )


def _float_clock() -> NeuralAdapter:
    info, blocks = _sim()
    b = blocks[0]
    return _Scripted(
        info, [dataclasses.replace(b, timestamps_ns=b.timestamps_ns.astype(np.float64))]
    )


def _silent() -> NeuralAdapter:
    info, _ = _sim()
    return _Scripted(info, [])


def _bad_unit() -> NeuralAdapter:
    info, blocks = _sim()
    chans = tuple(ChannelSpec(c.name, c.modality, "microvolt") for c in info.channels)
    return _Scripted(
        dataclasses.replace(info, channels=chans),
        [dataclasses.replace(b, channels=chans) for b in blocks],
    )


def _non_neural_modality() -> NeuralAdapter:
    info, blocks = _sim()
    chans = (ChannelSpec(info.channels[0].name, Modality.ECG, "uV"), *info.channels[1:])
    return _Scripted(
        dataclasses.replace(info, channels=chans),
        [dataclasses.replace(b, channels=chans) for b in blocks],
    )


def _replay_closed_license() -> NeuralAdapter:
    a = example_adapter()
    replay = dataclasses.replace(a.info.replay, license="LicenseRef-proprietary")  # type: ignore[type-var]
    return _Scripted(dataclasses.replace(a.info, replay=replay), [])


#: name -> (factory, rules that must be reported; the checker may add none of the others)
BROKEN_ADAPTERS: Final[Mapping[str, tuple[Callable[[], NeuralAdapter], frozenset[str]]]] = {
    "non_monotonic_clock": (_non_monotonic, frozenset({"clock"})),
    "float_timestamps": (_float_clock, frozenset({"clock"})),
    "interpretive_channel_name": (_interpretive, frozenset({"neutral"})),
    "l4_live_undeclared": (_l4_live, frozenset({"level"})),
    "wrong_block_type": (_wrong_type, frozenset({"output"})),
    "undeclared_channel_change": (_channel_change, frozenset({"channels"})),
    "clock_domain_change": (_identity_change, frozenset({"identity"})),
    "no_output": (_silent, frozenset({"output"})),
    "unnormalized_unit": (_bad_unit, frozenset({"unit"})),
    "non_neural_modality": (_non_neural_modality, frozenset({"modality"})),
    "replay_closed_license": (_replay_closed_license, frozenset({"replay:replay", "output"})),
}


# --- broken decoders ------------------------------------------------------------------------------


class _BadDecoder:
    def __init__(self, mode: str) -> None:
        self.mode = mode
        self.decoder_id = f"broken-{mode}"

    @property
    def output_types(self) -> frozenset[TaossType]:
        return frozenset({TaossType.SEN, TaossType.TEM})

    def decode(
        self, features: NeuralFeatures, types: frozenset[TaossType]
    ) -> Mapping[TaossType, NDArray[np.float64]]:
        out = {t: np.zeros(L1_DIMS[t]) for t in types}
        if self.mode == "wrong_dims":
            out[TaossType.SEN] = np.zeros(L1_DIMS[TaossType.SEN] + 1)
        elif self.mode == "nan_output":
            out[TaossType.TEM] = np.full(L1_DIMS[TaossType.TEM], np.nan)
        elif self.mode == "unrequested_type":
            out[TaossType.EMO] = np.zeros(L1_DIMS[TaossType.EMO])
        elif self.mode == "missing_type":
            out.pop(TaossType.SEN, None)
        return out


BROKEN_DECODERS: Final = ("wrong_dims", "nan_output", "unrequested_type", "missing_type")


def _features() -> NeuralFeatures:
    a = SimulatedNeuralAdapter(4, n_channels=4)
    a.start()
    block = a.read(512)
    a.stop()
    if block is None:  # pragma: no cover - the simulator is unbounded
        msg = "simulator produced no block"
        raise NeuralConformanceError(msg)
    return band_features(block)


# --- checks ---------------------------------------------------------------------------------------


def check_reference_adapter(factory: Callable[[], NeuralAdapter]) -> None:
    report = check_adapter_contract(factory())
    _require(report.ok, f"reference adapter refused: {report.violations}")


def check_reference_decoder(decoder: NeuralDecoder, features: NeuralFeatures) -> None:
    report = check_decoder_contract(decoder, features)
    _require(report.ok, f"reference decoder refused: {report.violations}")


def check_broken_adapter(factory: Callable[[], NeuralAdapter], expected: frozenset[str]) -> None:
    got = _rules(check_adapter_contract(factory()))
    _require(bool(got), "broken adapter was accepted")
    _require(got == expected, f"expected rules {sorted(expected)}, got {sorted(got)}")


def check_broken_decoder(mode: str) -> None:
    report = check_decoder_contract(_BadDecoder(mode), _features())
    _require(not report.ok, f"broken decoder {mode!r} was accepted")
    _require({v.rule for v in report.violations} == {"decode"}, f"wrong rule: {report.violations}")


def load_factory(spec: str) -> Callable[[], Any]:
    """``package.module:callable`` → the callable (vendor adapter factory)."""
    module, _, attr = spec.partition(":")
    if not module or not attr:
        msg = "expected module:factory"
        raise ValueError(msg)
    factory: Callable[[], Any] = getattr(importlib.import_module(module), attr)
    return factory


def check_external_adapter(spec: str) -> None:
    adapter = load_factory(spec)()
    report = check_adapter_contract(adapter)
    _require(report.ok, f"{spec}: {[(v.rule, v.detail) for v in report.violations]}")


def run_rust_sim(binary: Path, mode: str) -> JsonLinesAdapter:
    out = subprocess.run(  # noqa: S603 - binary path given by the operator
        [
            str(binary),
            "neural-sim",
            "--blocks",
            str(RUST_BLOCKS),
            "--samples",
            str(RUST_SAMPLES),
            "--break",
            mode,
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    return JsonLinesAdapter.parse(out.stdout.splitlines())


def check_rust_mode(binary: Path, mode: str, expected: frozenset[str]) -> None:
    _cross_check(run_rust_sim(binary, mode), expected, f"mode {mode}")


def _cross_check(adapter: JsonLinesAdapter, expected: frozenset[str], what: str) -> None:
    """Python's rules == the producer's own verdict == ``expected``."""
    _require(adapter.contract_version == CONTRACT_VERSION, "contract version differs")
    verdict = adapter.verdict
    if verdict is None:
        msg = "esp-rs printed no verdict"
        raise NeuralConformanceError(msg)
    py = _rules(check_adapter_contract(adapter, reads=RUST_BLOCKS + 2, max_samples=RUST_SAMPLES))
    rs = frozenset(v["rule"] for v in verdict["violations"])
    _require(py == rs, f"Python rules {sorted(py)} != Rust rules {sorted(rs)}")
    _require(py == expected, f"{what}: expected {sorted(expected)}, got {sorted(py)}")
    _require(verdict["ok"] == (not py), "Rust verdict flag disagrees")


def run_c_adapter(binary: Path, library: Path, config: str = "") -> JsonLinesAdapter:
    """Run a C-ABI vendor adapter through `esp-rs neural-capi` and parse its JSON lines."""
    out = subprocess.run(  # noqa: S603 - binary and library chosen by the operator
        [
            str(binary),
            "neural-capi",
            "--lib",
            str(library),
            "--config",
            config,
            "--blocks",
            str(RUST_BLOCKS),
            "--samples",
            str(RUST_SAMPLES),
        ],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if out.returncode != 0:
        msg = f"esp-rs neural-capi refused the library: {out.stderr.strip()}"
        raise NeuralConformanceError(msg)
    return JsonLinesAdapter.parse(out.stdout.splitlines())


def check_c_adapter(
    binary: Path, library: Path, config: str = "", expected: frozenset[str] = frozenset()
) -> None:
    """Rust host and Python must agree on a C adapter, and report exactly ``expected``."""
    _cross_check(run_c_adapter(binary, library, config), expected, f"C adapter {config!r}")


def neural_checks(
    neural_adapter: str | None = None,
    neural_rust: Path | None = None,
    neural_c: Path | None = None,
    neural_c_config: str = "",
) -> list[tuple[str, Callable[[], None]]]:
    """All checks of the ``neural`` category as ``(name, fn)`` pairs."""
    feats = _features()
    checks: list[tuple[str, Callable[[], None]]] = [
        ("simulator_adapter", lambda: check_reference_adapter(lambda: SimulatedNeuralAdapter(1))),
        ("example_vendor_l4_replay", lambda: check_reference_adapter(example_adapter)),
        (
            "simulator_decoder",
            lambda: check_reference_decoder(SimulatorDecoder(len(feats.names)), feats),
        ),
        (
            "example_vendor_decoder",
            lambda: check_reference_decoder(example_decoder(len(feats.names)), feats),
        ),
    ]
    for name, (factory, expected) in BROKEN_ADAPTERS.items():
        checks.append((f"refuses_{name}", partial(check_broken_adapter, factory, expected)))
    for mode in BROKEN_DECODERS:
        checks.append((f"refuses_decoder_{mode}", partial(check_broken_decoder, mode)))
    if neural_adapter is not None:
        checks.append(
            (f"external:{neural_adapter}", partial(check_external_adapter, neural_adapter))
        )
    if neural_rust is not None:
        for mode, expected in RUST_BREAK_MODES.items():
            checks.append((f"rust:{mode}", partial(check_rust_mode, neural_rust, mode, expected)))
    if neural_c is not None:
        if neural_rust is None:
            msg = "--neural-c needs --neural-rust (the esp-rs binary hosts the C library)"
            raise ValueError(msg)
        checks.append(
            (
                f"c:{neural_c.name}",
                partial(check_c_adapter, neural_rust, neural_c, neural_c_config),
            )
        )
    return checks
