# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-086: neural modality model, device descriptor and the L4-REPLAY profile."""

import dataclasses

import numpy as np
import pytest

from esp.adapters.neural import (
    ElectrodeSpec,
    NeuralAdapterInfo,
    NeuralDeviceDescriptor,
    NeuralLevel,
    NeuralProfile,
    ReplayDeclaration,
    check_adapter_contract,
    check_descriptor,
    check_profile,
)
from esp.adapters.physio.stream import ChannelSpec, SampleBlock, regular_timestamps
from esp.observation.model import DeviceMetadata, Modality

pytestmark = pytest.mark.security
N_CH = 4
DEVICE = DeviceMetadata(device_id="replay-falcon-h1", kind="intracortical-array", synthetic=False)
DESC = NeuralDeviceDescriptor(
    manufacturer="(recording)",
    model="Utah array",
    firmware="n/a",
    device_id="replay-falcon-h1",
    modalities=frozenset({Modality.SPIKE_COUNTS}),
    electrodes=tuple(ElectrodeSpec(f"ch{i:03d}", group="M1") for i in range(N_CH)),
    unit="count",
    clock_domain="replay:nwb",
    bin_width_s=0.02,
)
REPLAY = ReplayDeclaration(
    dataset_id="DANDI:000954",
    version="draft",
    license="CC-BY-4.0",
    consent_basis="participant consent in the clinical trial (see dataset documentation)",
    url="https://dandiarchive.org/dandiset/000954",
)
CHANNELS = tuple(ChannelSpec(e.name, Modality.SPIKE_COUNTS, "count") for e in DESC.electrodes)


class _Replay:
    """A minimal invasive replay source emitting binned spike counts."""

    def __init__(self, info: NeuralAdapterInfo, n_blocks: int = 3) -> None:
        self._info, self._n, self._i = info, n_blocks, 0
        self._rng = np.random.default_rng(0)

    @property
    def info(self) -> NeuralAdapterInfo:
        return self._info

    def start(self) -> None:
        self._i = 0

    def stop(self) -> None:
        pass

    def read(self, max_samples: int) -> SampleBlock | None:
        if self._i >= self._n:
            return None
        n = min(50, max_samples)
        ts = regular_timestamps(self._i * n * 20_000_000, n, 50.0)
        self._i += 1
        return SampleBlock(
            stream="spikes",
            channels=self._info.channels,
            timestamps_ns=ts,
            values=self._rng.poisson(2.0, size=(n, N_CH)).astype(np.float64),
            device=self._info.device,
            clock_domain=self._info.clock_domain,
            nominal_rate_hz=50.0,
        )


def info(**kw: object) -> NeuralAdapterInfo:
    base = NeuralAdapterInfo(
        adapter_id="falcon-h1-replay",
        device=DEVICE,
        channels=CHANNELS,
        nominal_rate_hz=50.0,
        level=NeuralLevel.L4_INVASIVE,
        clock_domain="replay:nwb",
        descriptor=DESC,
        replay=REPLAY,
    )
    return dataclasses.replace(base, **kw)  # type: ignore[arg-type]


def test_declared_invasive_replay_passes_the_contract() -> None:
    report = check_adapter_contract(_Replay(info()))
    assert report.ok, report.violations
    assert info().profile is NeuralProfile.L4_REPLAY


def test_live_invasive_is_refused_even_with_a_descriptor() -> None:
    rules = {v.rule for v in check_adapter_contract(_Replay(info(replay=None))).violations}
    assert "level" in rules
    assert "modality" in rules  # invasive channels are only admitted under L4-REPLAY
    assert info(replay=None).profile is NeuralProfile.L4_LIVE
    assert not check_profile(DESC, NeuralProfile.L4_LIVE, REPLAY).ok


@pytest.mark.parametrize(
    ("change", "rule"),
    [
        ({"license": "proprietary"}, "not open"),
        ({"consent_basis": "  "}, "consent basis"),
        ({"url": "http://example.org"}, "pinned https"),
        ({"version": ""}, "pinned https"),
    ],
)
def test_replay_declaration_must_be_complete(change: dict[str, str], rule: str) -> None:
    bad = dataclasses.replace(REPLAY, **change)
    report = check_adapter_contract(_Replay(info(replay=bad)))
    assert any(rule in v.detail for v in report.violations)


def test_invasive_modalities_are_refused_under_l3() -> None:
    check = check_profile(DESC, NeuralProfile.L3_LIVE)
    assert any("L4-REPLAY" in i.detail for i in check.issues)
    rules = {
        v.rule
        for v in check_adapter_contract(
            _Replay(info(level=NeuralLevel.L3_NON_INVASIVE, replay=None))
        ).violations
    }
    assert "modality" in rules
    assert "descriptor:profile" in rules


@pytest.mark.parametrize(
    ("change", "rule"),
    [
        ({"device_id": "serial-00123"}, "device_id"),
        ({"device_id": "has space"}, "device_id"),
        ({"unit": "spikes"}, "unit"),
        ({"sampling_rate_hz": 30000.0}, "rate"),
        ({"bin_width_s": None}, "rate"),
        ({"electrodes": ()}, "electrodes"),
        ({"electrodes": (ElectrodeSpec("a"), ElectrodeSpec("a"))}, "electrodes"),
        ({"modalities": frozenset()}, "modality"),
        ({"clock_domain": ""}, "clock"),
    ],
)
def test_descriptor_structure(change: dict[str, object], rule: str) -> None:
    bad = dataclasses.replace(DESC, **change)  # type: ignore[arg-type]
    assert rule in {i.rule for i in check_descriptor(bad)}


def test_rate_from_bins_or_sampling() -> None:
    assert DESC.rate_hz == pytest.approx(50.0)
    ecog = dataclasses.replace(
        DESC,
        modalities=frozenset({Modality.ECOG}),
        unit="uV",
        bin_width_s=None,
        sampling_rate_hz=3051.76,
    )
    assert ecog.rate_hz == pytest.approx(3051.76)
    assert ecog.invasive
    assert not check_descriptor(ecog)


def test_interpretive_channel_names_still_refused_for_replay() -> None:
    bad = (ChannelSpec("intent_x", Modality.SPIKE_COUNTS, "count"), *CHANNELS[1:])
    rules = {v.rule for v in check_adapter_contract(_Replay(info(channels=bad))).violations}
    assert "neutral" in rules
