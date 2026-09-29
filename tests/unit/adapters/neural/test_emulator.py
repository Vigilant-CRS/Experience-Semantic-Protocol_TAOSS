# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-088: implant stream emulator — declared perturbations, event log, detection."""

import dataclasses

import numpy as np
import pytest

from esp.adapters.neural import (
    ElectrodeSpec,
    NeuralAdapterInfo,
    NeuralDeviceDescriptor,
    NeuralLevel,
    ReplayDeclaration,
    SimulatedNeuralAdapter,
    check_adapter_contract,
)
from esp.adapters.neural.emulator import (
    EmulatorConfig,
    ImplantStreamEmulator,
    Perturbation,
    detect,
)
from esp.adapters.physio.stream import ChannelSpec, SampleBlock, concat, regular_timestamps
from esp.observation.model import DeviceMetadata, Modality

P = Perturbation
S = 1_000_000_000
RATE = 256.0


class SpikeCountReplay:
    """Invasive replay-like stub: binned spike counts at 50 Hz (Poisson), L4-REPLAY declared."""

    def __init__(self, seconds: int = 30, n_ch: int = 16, seed: int = 0) -> None:
        names = tuple(f"ch{i:03d}" for i in range(n_ch))
        desc = NeuralDeviceDescriptor(
            manufacturer="(recording)",
            model="stub array",
            firmware="n/a",
            device_id="stub-array-1",
            modalities=frozenset({Modality.SPIKE_COUNTS}),
            electrodes=tuple(ElectrodeSpec(n) for n in names),
            unit="count",
            clock_domain="replay:stub",
            bin_width_s=0.02,
        )
        self._info = NeuralAdapterInfo(
            adapter_id="stub-spikes",
            device=DeviceMetadata(device_id="stub-array-1", kind="intracortical-array"),
            channels=tuple(ChannelSpec(n, Modality.SPIKE_COUNTS, "count") for n in names),
            nominal_rate_hz=50.0,
            level=NeuralLevel.L4_INVASIVE,
            clock_domain="replay:stub",
            descriptor=desc,
            replay=ReplayDeclaration(
                dataset_id="STUB:1",
                version="1",
                license="CC0-1.0",
                consent_basis="synthetic stub",
                url="https://example.org/stub",
            ),
        )
        rng = np.random.default_rng(seed)
        self._counts = rng.poisson(rng.uniform(2, 8, n_ch), size=(seconds * 50, n_ch))
        self._pos = 0

    @property
    def info(self) -> NeuralAdapterInfo:
        return self._info

    def start(self) -> None:
        self._pos = 0

    def stop(self) -> None:
        pass

    def read(self, max_samples: int) -> SampleBlock | None:
        n = min(max_samples, self._counts.shape[0] - self._pos)
        if n <= 0:
            return None
        block = SampleBlock(
            stream="stub-spikes",
            channels=self._info.channels,
            timestamps_ns=regular_timestamps(self._pos * 20_000_000, n, 50.0),
            values=self._counts[self._pos : self._pos + n].astype(np.float64),
            device=self._info.device,
            clock_domain=self._info.clock_domain,
            nominal_rate_hz=50.0,
        )
        self._pos += n
        return block


def run(
    cfg: EmulatorConfig, *, chunk: int = 64, seconds: int = 30, spikes: bool = False
) -> tuple[list[SampleBlock], ImplantStreamEmulator]:
    src = (
        SpikeCountReplay(seconds)
        if spikes
        else SimulatedNeuralAdapter(3, total_samples=int(RATE) * seconds)
    )
    emu = ImplantStreamEmulator(src, cfg)
    emu.start()
    blocks = []
    while (b := emu.read(chunk)) is not None:
        blocks.append(b)
    emu.stop()
    return blocks, emu


CASES = {
    P.JITTER: EmulatorConfig(jitter_ns=0.05 * 1e9 / RATE),
    P.DROPOUT: EmulatorConfig(dropout_rate=0.01),
    P.CHANNEL_DEATH: EmulatorConfig(channel_death=(("cz", 10 * S),)),
    P.CLOCK_DRIFT: EmulatorConfig(clock_drift_ppm=500.0),
    P.RECONNECT: EmulatorConfig(reconnects=(12 * S,)),
    P.DAY_DRIFT: EmulatorConfig(day_drift_gain_per_hour=120.0),
    P.GAIN_STEP: EmulatorConfig(gain_steps=((15 * S, 2.0),)),
    P.PACKET_LOSS: EmulatorConfig(packet_loss=0.05, seed=1),
    P.ELECTRODE_REMOVAL: EmulatorConfig(electrode_removal=(("pz", 10 * S),)),
    P.BURST_NOISE: EmulatorConfig(bursts=((10 * S, S, 60.0),)),
}


def test_every_perturbation_is_declared_logged_and_detected_alone() -> None:
    assert set(CASES) == set(Perturbation)
    for kind, cfg in CASES.items():
        blocks, emu = run(cfg)
        assert cfg.declared() == {kind}
        assert {e.kind for e in emu.events} == {kind}, kind
        assert detect(blocks, RATE).visible == {kind}, kind


def test_clean_stream_reports_nothing_for_eeg_and_spike_counts() -> None:
    blocks, emu = run(EmulatorConfig())
    assert not emu.events
    assert detect(blocks, RATE).visible == frozenset()
    blocks, _ = run(EmulatorConfig(), spikes=True, chunk=50)
    assert detect(blocks, 50.0).visible == frozenset()


@pytest.mark.parametrize(
    ("kind", "cfg"),
    [
        (P.GAIN_STEP, EmulatorConfig(gain_steps=((15 * S, 0.4),))),
        (P.DAY_DRIFT, EmulatorConfig(day_drift_offset_per_hour=3600.0 * 4)),
        (P.CHANNEL_DEATH, EmulatorConfig(channel_death=(("ch003", 12 * S),))),
        (P.RECONNECT, EmulatorConfig(reconnects=(8 * S, 20 * S))),
        (P.DROPOUT, EmulatorConfig(dropout_rate=0.02)),
    ],
)
def test_detection_on_invasive_spike_counts(kind: Perturbation, cfg: EmulatorConfig) -> None:
    blocks, _ = run(cfg, spikes=True, chunk=50)
    assert kind in detect(blocks, 50.0).visible


@pytest.mark.parametrize(("start_s", "dur_s"), [(2, 3), (3, 4), (22, 3), (14, 2), (1, 8), (21, 8)])
def test_a_burst_never_looks_like_a_gain_step_or_drift(start_s: int, dur_s: int) -> None:
    blocks, _ = run(EmulatorConfig(bursts=((start_s * S, dur_s * S, 60.0),)))
    assert detect(blocks, RATE).visible == {P.BURST_NOISE}


def test_event_log_carries_stream_times_and_channels() -> None:
    cfg = EmulatorConfig(
        channel_death=(("cz", 10 * S),),
        gain_steps=((15 * S, 2.0),),
        reconnects=(12 * S,),
    )
    _, emu = run(cfg)
    by_kind = {e.kind: e for e in emu.events}
    assert by_kind[P.CHANNEL_DEATH].channel == "cz"
    assert by_kind[P.CHANNEL_DEATH].t_ns == 10 * S
    assert by_kind[P.GAIN_STEP].t_ns == 15 * S
    assert by_kind[P.RECONNECT].t_ns == 12 * S


def test_electrode_removal_is_never_silent() -> None:
    src = SpikeCountReplay()
    emu = ImplantStreamEmulator(src, EmulatorConfig(electrode_removal=(("ch005", 5 * S),)))
    emu.start()
    before = emu.info
    blocks = []
    while (b := emu.read(50)) is not None:
        blocks.append(b)
    assert len(emu.descriptor_changes) == 1
    change = emu.descriptor_changes[0]
    assert change.removed == ("ch005",)
    assert "ch005" not in {c.name for c in emu.info.channels}
    assert emu.info.descriptor is not None
    assert "ch005" not in {e.name for e in emu.info.descriptor.electrodes}
    assert len(before.channels) == len(emu.info.channels) + 1
    assert blocks[-1].channels == emu.info.channels
    # a consumer that pinned the old declaration notices the change
    rules = {v.rule for v in check_adapter_contract(_Frozen(before, blocks)).violations}
    assert "channels" in rules


class _Frozen:
    """Replays emitted blocks under a fixed (stale) declaration."""

    def __init__(self, info: NeuralAdapterInfo, blocks: list[SampleBlock]) -> None:
        self._info, self._blocks = info, blocks

    @property
    def info(self) -> NeuralAdapterInfo:
        return self._info

    def start(self) -> None:
        self._it = iter(self._blocks)

    def stop(self) -> None:
        pass

    def read(self, max_samples: int) -> SampleBlock | None:
        return next(self._it, None)


def test_time_based_perturbations_are_chunking_invariant() -> None:
    cfg = EmulatorConfig(
        seed=5,
        jitter_ns=2_000.0,
        dropout_rate=0.01,
        channel_death=(("cz", 9 * S),),
        clock_drift_ppm=80.0,
        reconnects=(11 * S,),
        day_drift_gain_per_hour=10.0,
        gain_steps=((14 * S, 1.5),),
        bursts=((5 * S, S // 2, 30.0),),
    )
    digests = {concat(run(cfg, chunk=c, seconds=20)[0]).digest() for c in (32, 100, 256)}
    assert len(digests) == 1


def test_seed_determinism_and_seed_dependence() -> None:
    cfg = EmulatorConfig(seed=2, jitter_ns=5_000.0, dropout_rate=0.02, packet_loss=0.1)
    a = concat(run(cfg, seconds=10)[0]).digest()
    b = concat(run(cfg, seconds=10)[0]).digest()
    c = concat(run(dataclasses.replace(cfg, seed=3), seconds=10)[0]).digest()
    assert a == b
    assert a != c


def test_clean_emulation_passes_the_adapter_contract_for_both_profiles() -> None:
    emu = ImplantStreamEmulator(SimulatedNeuralAdapter(1), EmulatorConfig(jitter_ns=100.0))
    assert check_adapter_contract(emu).ok
    replay = ImplantStreamEmulator(SpikeCountReplay(), EmulatorConfig(dropout_rate=0.01))
    report = check_adapter_contract(replay)
    assert report.ok, report.violations


def test_realtime_pacing_uses_the_injected_clock() -> None:
    now = [0]
    slept: list[float] = []

    def clock() -> int:
        return now[0]

    def sleep(s: float) -> None:
        slept.append(s)
        now[0] += round(s * 1e9)

    src = SimulatedNeuralAdapter(1, total_samples=int(RATE) * 4)
    emu = ImplantStreamEmulator(
        src, EmulatorConfig(realtime=True, speed=2.0), clock=clock, sleep=sleep
    )
    emu.start()
    while emu.read(64) is not None:
        pass
    last_sample_s = (int(RATE) * 4 - 1) / RATE
    assert sum(slept) == pytest.approx(last_sample_s / 2.0, rel=1e-3)


def test_config_validation() -> None:
    with pytest.raises(ValueError, match="dropout_rate"):
        EmulatorConfig(dropout_rate=1.0)
    with pytest.raises(ValueError, match="speed"):
        EmulatorConfig(speed=0.0)
    with pytest.raises(ValueError, match="gain"):
        EmulatorConfig(gain_steps=((0, 0.0),))
