# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""BIDS-iEEG reader on real depth-electrode (sEEG) data and the gaps it revealed.

Real data: OpenNeuro ds003688 (Berezutskaya et al., Sci Data 2022, CC0), subject 01, rest
run, 103 sEEG contacts at 2048 Hz in BrainVision format, fetched by
``scripts/fetch_openneuro.py`` into ``$ESP_DATA_DIR`` (never committed). The synthetic tests
always run and pin the rules the real data exposed:

- sidecars are found by BIDS inheritance (the events file omits ``acq-clinical``);
- the electrode group can come from ``channels.tsv`` when ``electrodes.tsv`` has none;
- the per-channel hardware filter is part of the declared processing chain;
- ECG is an auxiliary modality; TRIG/MISC have no neutral modality.
"""

import os
import re
from pathlib import Path

import numpy as np
import pytest

from esp.adapters.neural import NeuralProfile, check_adapter_contract
from esp.adapters.neural.bids_ieeg import BidsRecording, bids_ieeg_adapter, read_bids_events
from esp.adapters.neural.emulator import EmulatorConfig, ImplantStreamEmulator, Perturbation, detect
from esp.adapters.neural.model import ElectrodeStatus
from esp.adapters.physio.stream import concat
from esp.observation.model import Modality
from tests.unit.adapters.neural.test_bids_ieeg import PREFIX, build, tsv

pytestmark = pytest.mark.security
ROOT = Path(__file__).resolve().parents[4]
DATA = Path(os.environ.get("ESP_DATA_DIR", ROOT / "data" / "external")) / "ds003688-seeg"
IEEG = DATA / "sub-01" / "ses-iemu" / "ieeg"
VHDR = IEEG / "sub-01_ses-iemu_task-rest_acq-clinical_run-1_ieeg.vhdr"
HAS_DATA = VHDR.is_file()
S = 1_000_000_000


# --- always-run: the rules the real data exposed ----------------------------------------------


def test_sidecars_follow_bids_inheritance(tmp_path: Path) -> None:
    data = build(tmp_path)
    d = data.parent
    exact = d / f"{PREFIX}_events.tsv"
    inherited = d / "sub-01_ses-01_task-speech_events.tsv"  # no run entity: still applies
    exact.rename(inherited)
    tsv(d / "sub-01_ses-01_task-rest_events.tsv", [{"onset": 0.0, "trial_type": "other"}])
    tsv(d / "sub-01_ses-01_acq-other_electrodes.tsv", [{"name": "Sig0", "x": 9, "y": 9, "z": 9}])
    rec = BidsRecording.locate(data)
    assert rec.events == inherited  # the other task's events never apply
    assert rec.electrodes == d / "sub-01_ses-01_electrodes.tsv"  # acq-other is not ours
    assert read_bids_events(data).labels  # events are readable through inheritance


def test_most_specific_sidecar_wins(tmp_path: Path) -> None:
    data = build(tmp_path)
    d = data.parent
    tsv(d / "sub-01_ses-01_task-speech_events.tsv", [{"onset": 0.0, "trial_type": "general"}])
    assert BidsRecording.locate(data).events == d / f"{PREFIX}_events.tsv"


def test_group_from_channels_and_hardware_filter(tmp_path: Path) -> None:
    data = build(tmp_path)
    d = data.parent
    tsv(
        d / f"{PREFIX}_channels.tsv",
        [
            {
                "name": f"Sig{i}",
                "type": t,
                "units": "uV",
                "status": "good",
                "group": g,
                "low_cutoff": "0.5",
                "high_cutoff": "500",
            }
            for i, (t, g) in enumerate(
                [("ECOG", "A"), ("ECOG", "A"), ("SEEG", "B"), ("ECG", "n/a")]
            )
        ],
    )
    tsv(
        d / "sub-01_ses-01_electrodes.tsv",
        [{"name": f"Sig{i}", "x": 1, "y": 2, "z": 3} for i in range(3)],
    )
    info = bids_ieeg_adapter(data).info
    assert info.descriptor is not None
    assert [e.group for e in info.descriptor.electrodes] == ["A", "A", "B"]
    steps = {s.kind: dict(s.parameters) for s in info.descriptor.processing}
    assert steps["hardware_filter"] == {"low_cutoff_hz": "0.5", "high_cutoff_hz": "500"}


def test_ecg_is_auxiliary_and_triggers_are_refused(tmp_path: Path) -> None:
    data = build(tmp_path)
    a = bids_ieeg_adapter(data, types=("ECOG", "ECG"))
    assert {c.modality for c in a.info.channels} == {Modality.ECOG, Modality.ECG}
    assert check_adapter_contract(a).ok


@pytest.mark.parametrize("rate", [2048.0, 1000.0, 512.0, 30_000.0])
def test_emulated_reconnect_is_never_mistaken_for_packet_loss(rate: float) -> None:
    """Regression: a fixed clock offset was nearly a whole period at 2048 Hz (real sEEG)."""
    from esp.adapters.neural import SimulatedNeuralAdapter  # noqa: PLC0415

    src = SimulatedNeuralAdapter(3, n_channels=4, rate_hz=rate, total_samples=int(4 * rate))
    emu = ImplantStreamEmulator(src, EmulatorConfig(reconnects=(2 * S,)))
    emu.start()
    blocks = []
    while (b := emu.read(512)) is not None:
        blocks.append(b)
    visible = detect(blocks, rate).visible
    assert Perturbation.RECONNECT in visible
    assert Perturbation.PACKET_LOSS not in visible


# --- data-gated: real sEEG -----------------------------------------------------------------------

needs_data = pytest.mark.skipif(not HAS_DATA, reason="run scripts/fetch_openneuro.py ds003688-seeg")


def _reference(names: list[str]) -> np.ndarray:
    """Independent read: BrainVision multiplexed float32, resolution 1 µV, by channel name."""
    header = VHDR.read_text(encoding="utf-8")
    order = [m.group(1).lower() for m in re.finditer(r"^Ch\d+=([^,]*),", header, re.M)]
    raw = np.fromfile(VHDR.with_suffix(".eeg"), dtype="<f4").reshape(-1, len(order))
    return raw[:, [order.index(n) for n in names]].astype(np.float64)


@needs_data
def test_real_seeg_passes_the_contract_under_l4_replay() -> None:
    a = bids_ieeg_adapter(VHDR)
    info = a.info
    assert info.profile is NeuralProfile.L4_REPLAY
    assert info.nominal_rate_hz == 2048.0
    assert len(info.channels) == 103
    assert all(c.modality is Modality.SEEG and c.unit == "uV" for c in info.channels)
    assert info.replay is not None
    assert info.replay.license == "CC0-1.0"
    assert info.replay.version == "1.0.7"
    assert info.replay.dataset_id == "DOI:10.18112/openneuro.ds003688.v1.0.7"
    assert "Medical Ethical Committee" in info.replay.consent_basis
    report = check_adapter_contract(a, reads=8, max_samples=2048)
    assert report.ok, report.violations


@needs_data
def test_real_seeg_values_equal_an_independent_read() -> None:
    a = bids_ieeg_adapter(VHDR)
    a.start()
    first = concat([b for _ in range(10) if (b := a.read(4096)) is not None])
    ref = _reference([c.name for c in a.info.channels])
    np.testing.assert_array_equal(first.values, ref[: first.n_samples])


@needs_data
def test_real_electrodes_bad_channels_and_groups() -> None:
    a = bids_ieeg_adapter(VHDR)
    assert a.info.descriptor is not None
    electrodes = {e.name: e for e in a.info.descriptor.electrodes}
    assert electrodes["mfl15"].status is ElectrodeStatus.BAD
    assert sum(e.status is ElectrodeStatus.BAD for e in electrodes.values()) == 1
    assert all(e.x_mm is not None for e in electrodes.values())
    assert electrodes["ar1"].group == "AR"
    clean = bids_ieeg_adapter(VHDR, include_bad=False)
    assert "mfl15" not in {c.name for c in clean.info.channels}
    assert len(clean.info.channels) == 102


@needs_data
def test_real_events_are_inherited() -> None:
    assert BidsRecording.locate(VHDR).events == IEEG / "sub-01_ses-iemu_task-rest_run-1_events.tsv"
    ev = read_bids_events(VHDR)
    assert ev.labels == ("start task", "end task")
    assert ev.timestamps_ns == (1 * S, 181 * S)


@needs_data
def test_real_stream_is_chunking_invariant() -> None:
    def digest(chunk: int) -> str:
        a = bids_ieeg_adapter(VHDR)
        a.start()
        blocks, n = [], 0
        while n < 40_960 and (b := a.read(chunk)) is not None:
            blocks.append(b)
            n += b.n_samples
        return concat(blocks).values[:40_960].tobytes().hex()[:64] + str(n)

    assert digest(1000)[:64] == digest(4096)[:64]


@needs_data
def test_emulated_implant_perturbations_are_detected_on_real_seeg() -> None:
    emu = ImplantStreamEmulator(
        bids_ieeg_adapter(VHDR),
        EmulatorConfig(reconnects=(10 * S,), channel_death=(("ar2", 15 * S),)),
    )
    emu.start()
    blocks, samples = [], 0
    while samples < 30 * 2048 and (b := emu.read(2048)) is not None:
        blocks.append(b)
        samples += b.n_samples
    emu.stop()
    visible = detect(blocks, 2048.0).visible
    assert {Perturbation.RECONNECT, Perturbation.CHANNEL_DEATH} <= visible
