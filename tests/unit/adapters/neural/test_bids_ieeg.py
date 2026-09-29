# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-087: BIDS-iEEG recordings replay through the same neural adapter contract."""

import json
from pathlib import Path

import numpy as np
import pytest

from esp.adapters.neural import NeuralProfile, check_adapter_contract
from esp.adapters.neural.bids_ieeg import (
    BidsRecording,
    bids_declaration,
    bids_ieeg_adapter,
    read_bids_events,
)
from esp.adapters.neural.model import ElectrodeStatus
from esp.adapters.neural.replay import ReplayError
from esp.adapters.physio.stream import concat
from esp.observation.model import Modality
from tests.unit.adapters.test_physio_files import write_edf

pytestmark = pytest.mark.security
RATE = 100
T = np.arange(4 * RATE) / RATE
SIGNALS = [
    np.round(200 * np.sin(2 * np.pi * 3 * T)) / 2,
    np.round(100 * np.cos(2 * np.pi * 5 * T)) / 2,
    np.round(np.linspace(-80, 80, T.size)) / 2,
    np.round(50 * np.sin(2 * np.pi * 1 * T)) / 2,
]
PREFIX = "sub-01_ses-01_task-speech_run-01"


def tsv(path: Path, rows: list[dict[str, object]]) -> None:
    cols = list(rows[0])
    lines = ["\t".join(cols)] + ["\t".join(str(r[c]) for c in cols) for r in rows]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def build(
    root: Path,
    *,
    units: tuple[str, ...] = ("uV", "uV", "uV", "uV"),
    doi: bool = True,
    writer: str = "minimal",
) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "dataset_description.json").write_text(
        json.dumps(
            {
                "Name": "synthetic-ieeg",
                "BIDSVersion": "1.9.0",
                "License": "CC0",
                "EthicsApprovals": ["Example University IRB #123"],
                **({"DatasetDOI": "doi:10.18112/openneuro.ds000000.v1.2.3"} if doi else {}),
            }
        )
    )
    d = root / "sub-01" / "ses-01" / "ieeg"
    d.mkdir(parents=True)
    data = d / f"{PREFIX}_ieeg.edf"
    if writer == "pyedflib":
        write_with_pyedflib(data)
    else:
        write_edf(data, SIGNALS, [RATE] * 4)
    (d / f"{PREFIX}_ieeg.json").write_text(
        json.dumps(
            {
                "SamplingFrequency": RATE,
                "iEEGReference": "common average",
                "PowerLineFrequency": 50,
                "Manufacturer": "Synthetic",
            }
        )
    )
    tsv(
        d / f"{PREFIX}_channels.tsv",
        [
            {"name": "Sig0", "type": "ECOG", "units": units[0], "status": "good"},
            {"name": "Sig1", "type": "ECOG", "units": units[1], "status": "good"},
            {"name": "Sig2", "type": "SEEG", "units": units[2], "status": "bad"},
            {"name": "Sig3", "type": "ECG", "units": units[3], "status": "good"},
        ],
    )
    tsv(
        d / "sub-01_ses-01_electrodes.tsv",
        [
            {
                "name": "Sig0",
                "x": 1.0,
                "y": 2.0,
                "z": 3.0,
                "size": 4,
                "group": "G1",
                "location": "stg",
            },
            {
                "name": "Sig1",
                "x": "n/a",
                "y": "n/a",
                "z": "n/a",
                "size": 4,
                "group": "G1",
                "location": "n/a",
            },
            {
                "name": "Sig2",
                "x": -1.0,
                "y": 0.5,
                "z": 0.0,
                "size": 1,
                "group": "D1",
                "location": "hippocampus",
            },
        ],
    )
    tsv(
        d / f"{PREFIX}_events.tsv",
        [
            {"onset": 2.5, "duration": 0.5, "trial_type": "ba"},
            {"onset": 0.75, "duration": 0.5, "trial_type": "da"},
        ],
    )
    return data


def write_with_pyedflib(path: Path) -> None:
    pyedflib = pytest.importorskip("pyedflib")
    headers = [
        {
            "label": f"Sig{i}",
            "dimension": "uV",
            "sample_frequency": RATE,
            "physical_max": 200.0,
            "physical_min": -200.0,
            "digital_max": 32767,
            "digital_min": -32768,
        }
        for i in range(len(SIGNALS))
    ]
    with pyedflib.EdfWriter(str(path), len(SIGNALS), file_type=pyedflib.FILETYPE_EDFPLUS) as w:
        w.setSignalHeaders(headers)
        w.writeSamples([np.asarray(s, dtype=np.float64) for s in SIGNALS])


@pytest.fixture
def data(tmp_path: Path) -> Path:
    return build(tmp_path)


def test_ecog_and_seeg_replay_under_l4_with_the_bids_declaration(data: Path) -> None:
    a = bids_ieeg_adapter(data)
    report = check_adapter_contract(a, reads=20, max_samples=64)
    assert report.ok, report.violations
    assert a.info.profile is NeuralProfile.L4_REPLAY
    assert a.info.replay is not None
    assert a.info.replay.license == "CC0-1.0"
    assert a.info.replay.version == "1.2.3"
    assert a.info.replay.url == "https://doi.org/10.18112/openneuro.ds000000.v1.2.3"
    assert "IRB #123" in a.info.replay.consent_basis
    block = concat(a.read_all(37))
    assert [c.name for c in block.channels] == ["sig0", "sig1", "sig2"]  # ECG not selected
    assert [c.modality for c in block.channels] == [Modality.ECOG, Modality.ECOG, Modality.SEEG]
    np.testing.assert_allclose(block.values, np.stack(SIGNALS[:3], axis=1), atol=1e-9)
    assert int(block.timestamps_ns[0]) == 0  # relative to the recording, like events.tsv
    assert int(block.timestamps_ns[1]) == 10_000_000


def test_values_match_an_independent_edf_reader(tmp_path: Path) -> None:
    pyedflib = pytest.importorskip("pyedflib")
    data = build(tmp_path, writer="pyedflib")
    block = concat(bids_ieeg_adapter(data).read_all())
    with pyedflib.EdfReader(str(data)) as ref:
        for j in range(3):
            np.testing.assert_allclose(block.values[:, j], ref.readSignal(j), rtol=1e-12)


def test_sidecars_become_electrode_metadata(data: Path) -> None:
    a = bids_ieeg_adapter(data)
    d = a.info.descriptor
    assert d is not None
    e = {x.name: x for x in d.electrodes}
    assert (e["sig0"].x_mm, e["sig0"].y_mm, e["sig0"].z_mm) == (1.0, 2.0, 3.0)
    assert (e["sig0"].group, e["sig0"].location) == ("G1", "stg")
    assert e["sig1"].x_mm is None
    assert e["sig2"].status is ElectrodeStatus.BAD
    assert e["sig0"].status is ElectrodeStatus.GOOD
    assert d.reference == "common average"
    assert d.sampling_rate_hz == RATE
    assert d.manufacturer == "Synthetic"
    assert d.modalities == frozenset({Modality.ECOG, Modality.SEEG})


def test_bad_channels_can_be_excluded_and_types_selected(data: Path) -> None:
    good = bids_ieeg_adapter(data, include_bad=False)
    assert [c.name for c in good.info.channels] == ["sig0", "sig1"]
    seeg = bids_ieeg_adapter(data, types=("SEEG",))
    assert [c.name for c in seeg.info.channels] == ["sig2"]


def test_no_channels_of_the_requested_type_is_refused(data: Path) -> None:
    with pytest.raises(ReplayError, match="no channels"):
        bids_ieeg_adapter(data, types=("EEG",))
    with pytest.raises(ReplayError, match="unsupported channel types"):
        bids_ieeg_adapter(data, types=("ECG",))


def test_non_invasive_eeg_replays_under_l3_without_declaration(tmp_path: Path) -> None:
    data = build(tmp_path)
    ch = data.with_name(f"{PREFIX}_channels.tsv")
    ch.write_text(ch.read_text().replace("ECOG", "EEG").replace("SEEG", "EEG"))
    a = bids_ieeg_adapter(data, types=("EEG",))
    assert a.info.profile is NeuralProfile.L3_LIVE
    assert a.info.replay is None
    assert check_adapter_contract(a).ok
    decl = bids_declaration(tmp_path)
    assert decl is not None
    b = bids_ieeg_adapter(data, types=("EEG",), replay=decl)  # a declaration never upgrades EEG
    assert b.info.replay is None
    assert b.info.profile is NeuralProfile.L3_LIVE
    assert check_adapter_contract(b).ok


def test_sidecar_units_convert_values(tmp_path: Path) -> None:
    a = bids_ieeg_adapter(build(tmp_path, units=("mV", "mV", "mV", "uV")))
    block = concat(a.read_all())
    assert {c.unit for c in block.channels} == {"mV"}
    np.testing.assert_allclose(block.values, np.stack(SIGNALS[:3], axis=1) / 1000.0, atol=1e-12)


def test_unit_dimension_mismatch_is_refused(tmp_path: Path) -> None:
    with pytest.raises(ReplayError, match="cannot convert"):
        bids_ieeg_adapter(build(tmp_path, units=("count", "count", "count", "uV")))


def test_without_doi_the_invasive_recording_is_not_admitted(tmp_path: Path) -> None:
    a = bids_ieeg_adapter(build(tmp_path, doi=False))
    assert a.info.replay is None
    assert "level" in {v.rule for v in check_adapter_contract(a).violations}
    assert bids_declaration(tmp_path) is None
    decl = bids_declaration(
        tmp_path, url="https://openneuro.org/datasets/ds000000", version="1.0.0"
    )
    assert decl is not None
    assert check_adapter_contract(
        bids_ieeg_adapter(build(tmp_path / "b", doi=False), replay=decl)
    ).ok


def test_events_are_sorted_and_share_the_clock(data: Path) -> None:
    ev = read_bids_events(data)
    a = bids_ieeg_adapter(data)
    assert ev.labels == ("da", "ba")
    assert ev.timestamps_ns == (750_000_000, 2_500_000_000)
    assert ev.clock_domain == a.info.clock_domain


def test_missing_sidecars_and_channels_are_refused(tmp_path: Path) -> None:
    data = build(tmp_path)
    ch = data.with_name(f"{PREFIX}_channels.tsv")
    ch.write_text(ch.read_text().replace("Sig1", "Sig9"))
    with pytest.raises(ReplayError, match="not in the data file"):
        bids_ieeg_adapter(data)
    data.with_name(f"{PREFIX}_ieeg.json").unlink()
    with pytest.raises(ReplayError, match="missing BIDS file"):
        BidsRecording.locate(data)
    with pytest.raises(ReplayError, match="not a BIDS-iEEG"):
        BidsRecording.locate(tmp_path / "recording.edf")


def test_sampling_rate_must_match_the_data(tmp_path: Path) -> None:
    data = build(tmp_path)
    side = data.with_name(f"{PREFIX}_ieeg.json")
    side.write_text(json.dumps({"SamplingFrequency": 256}))
    with pytest.raises(ReplayError, match="no unique data block"):
        bids_ieeg_adapter(data)
    side.write_text(json.dumps({}))
    with pytest.raises(ReplayError, match="SamplingFrequency"):
        bids_ieeg_adapter(data)


@pytest.mark.parametrize("chunk", [1, 13, 400, 1000])
def test_chunking_does_not_change_the_stream(data: Path, chunk: int) -> None:
    ref = concat(bids_ieeg_adapter(data).read_all(400)).digest()
    assert concat(bids_ieeg_adapter(data).read_all(chunk)).digest() == ref
