# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-087: NWB replay adapters satisfy the same contract as a live neural device.

Synthetic NWB files built at test time always run. Tests on the public human
datasets (FALCON H1/H2, DANDI 000019) run only when ``scripts/fetch_dandi.py``
has put them into ``$ESP_DATA_DIR`` (default ``data/external``); they are never
copied into the repository.
"""

import datetime as dt
import enum
import glob
import importlib.util
import json
import os
import sys
import types
from pathlib import Path

import numpy as np
import pytest

pynwb = pytest.importorskip("pynwb")

from pynwb import NWBHDF5IO, NWBFile, TimeSeries  # noqa: E402
from pynwb.behavior import Position, SpatialSeries  # noqa: E402
from pynwb.ecephys import ElectricalSeries  # noqa: E402

from esp.adapters.neural import (  # noqa: E402
    NeuralProfile,
    ReplayDeclaration,
    check_adapter_contract,
)
from esp.adapters.neural.model import ElectrodeStatus  # noqa: E402
from esp.adapters.neural.nwb import (  # noqa: E402
    NwbFile,
    dandi_asset_url,
    electrical_series_adapter,
    read_events,
    time_axis,
    timeseries_adapter,
    units_binned_adapter,
)
from esp.adapters.neural.replay import ReplayError  # noqa: E402
from esp.adapters.physio.stream import concat  # noqa: E402
from esp.observation.model import Modality  # noqa: E402

pytestmark = pytest.mark.security
ROOT = Path(__file__).resolve().parents[4]
DATA = Path(os.environ.get("ESP_DATA_DIR", ROOT / "data" / "external"))
CONV = 0.5e-6
RAW = (np.arange(2000 * 4, dtype=np.int64).reshape(2000, 4) % 997 - 498).astype(np.int16)
SPIKES = [
    np.array([0.0, 0.019999, 0.02, 0.5, 1.0]),  # 0.02 sits exactly on an edge; 1.0 = last end
    np.array([-0.02, 0.3, 0.31, 0.99]),  # -0.02 = first bin start
    np.array([], dtype=np.float64),
]


def build(tmp: Path, *, dandiset: str = "999999", period_quirk: bool = False) -> Path:
    nwb = NWBFile(
        session_description="synthetic replay fixture",
        identifier="subject-alpha-session-7",
        session_start_time=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
    )
    dev = nwb.create_device(name="grid", description="synthetic")
    grp = nwb.create_electrode_group(name="G", description="g", location="cortex", device=dev)
    nwb.add_electrode_column(name="bad", description="bad channel flag")
    for i in range(4):
        nwb.add_electrode(x=float(i), y=1.5, z=-2.0, location=f"region{i}", group=grp, bad=(i == 3))
    region = nwb.create_electrode_table_region(list(range(4)), "all electrodes")
    nwb.add_acquisition(
        ElectricalSeries(
            name="ElectricalSeries",
            data=RAW,
            electrodes=region,
            rate=1000.0,
            starting_time=0.25,
            conversion=CONV,
        )
    )
    kin_t = 0.01 * np.arange(100) + 0.005
    nwb.add_acquisition(
        TimeSeries(name="kin", data=np.arange(200.0).reshape(100, 2), unit="m", timestamps=kin_t)
    )
    grid_rate = 0.02 if period_quirk else 50.0
    nwb.add_acquisition(
        TimeSeries(
            name="grid",
            data=np.zeros((51, 1)),
            unit="arbitrary",
            rate=grid_rate,
            starting_time=0.0,
        )
    )
    for s in SPIKES:
        nwb.add_unit(spike_times=s)
    nwb.add_trial_column(name="condition", description="task condition")
    nwb.add_trial(start_time=0.7, stop_time=0.9, condition="b")
    nwb.add_trial(start_time=0.1, stop_time=0.3, condition="a")
    mod = nwb.create_processing_module(name="behavior", description="pose")
    pos = Position(name="Position")
    pos.add_spatial_series(
        SpatialSeries(
            name="wrist",
            data=np.ones((10, 2)),
            reference_frame="camera",
            unit="meters",
            rate=10.0,
        )
    )
    mod.add(pos)
    path = tmp / "sub-x" / "sub-x_ses-1.nwb"
    path.parent.mkdir(parents=True)
    with NWBHDF5IO(str(path), "w") as io:
        io.write(nwb)
    (tmp / "MANIFEST.json").write_text(
        json.dumps(
            {
                "id": "synthetic",
                "dandiset": dandiset,
                "version": "0.1.0",
                "license": ["spdx:CC-BY-4.0"],
                "citation": "synthetic fixture",
                "url": f"https://dandiarchive.org/dandiset/{dandiset}/0.1.0",
                "files": {},
            }
        )
    )
    return path


@pytest.fixture
def nwb_path(tmp_path: Path) -> Path:
    return build(tmp_path)


# --- ElectricalSeries -----------------------------------------------------------------------------


def test_electrical_series_values_timestamps_and_contract(nwb_path: Path) -> None:
    with NwbFile(nwb_path) as f:
        a = electrical_series_adapter(f, modality=Modality.ECOG, unit="uV")
        report = check_adapter_contract(a, reads=50, max_samples=128)
        assert report.ok, report.violations
        assert a.info.profile is NeuralProfile.L4_REPLAY
        block = concat(a.read_all(333))
    np.testing.assert_array_equal(block.values, RAW.astype(np.float64) * CONV * 1e6)  # V -> uV
    assert int(block.timestamps_ns[0]) == 250_000_000
    assert int(block.timestamps_ns[1]) == 251_000_000
    assert block.timestamps_ns.dtype == np.int64


def test_electrodes_table_becomes_electrode_specs(nwb_path: Path) -> None:
    with NwbFile(nwb_path) as f:
        a = electrical_series_adapter(f)
        d = a.info.descriptor
    assert d is not None
    e = d.electrodes
    assert [x.name for x in e] == ["e000", "e001", "e002", "e003"]
    assert (e[2].x_mm, e[2].y_mm, e[2].z_mm, e[2].location) == (2.0, 1.5, -2.0, "region2")
    assert e[3].status is ElectrodeStatus.BAD
    assert e[0].status is ElectrodeStatus.GOOD
    assert d.sampling_rate_hz == 1000.0
    assert d.bin_width_s is None


def test_device_id_is_pseudonymous(nwb_path: Path) -> None:
    with NwbFile(nwb_path) as f:
        a = electrical_series_adapter(f)
    assert "alpha" not in a.info.device.device_id
    assert "subject" not in a.info.clock_domain
    assert a.info.device.device_id.startswith("replay-999999-")


@pytest.mark.parametrize("chunk", [1, 7, 64, 2000, 5000])
def test_chunking_does_not_change_the_stream(nwb_path: Path, chunk: int) -> None:
    with NwbFile(nwb_path) as f:
        ref = concat(electrical_series_adapter(f).read_all(2000)).digest()
        assert concat(electrical_series_adapter(f).read_all(chunk)).digest() == ref
        units_ref = concat(units_binned_adapter(f, bin_width_s=0.02).read_all(1000)).digest()
        units = concat(units_binned_adapter(f, bin_width_s=0.02).read_all(chunk)).digest()
        assert units == units_ref


def test_channel_subset_and_unit_conversion(nwb_path: Path) -> None:
    with NwbFile(nwb_path) as f:
        full = concat(electrical_series_adapter(f).read_all())
        sub = concat(electrical_series_adapter(f, channels=[3, 1]).read_all())
        mv = concat(electrical_series_adapter(f, unit="mV").read_all())
    np.testing.assert_array_equal(sub.values, full.values[:, [1, 3]])
    assert [c.name for c in sub.channels] == ["e001", "e003"]
    np.testing.assert_allclose(mv.values, full.values / 1000.0, rtol=1e-12)
    with NwbFile(nwb_path) as f, pytest.raises(ReplayError, match="out of range"):
        electrical_series_adapter(f, channels=[4])
    with NwbFile(nwb_path) as f, pytest.raises(ReplayError, match="cannot convert"):
        electrical_series_adapter(f, unit="count")


# --- Units -> spike counts ---------------------------------------------------------------------


def _histogram(spikes: list[np.ndarray], ends: np.ndarray, width: float) -> np.ndarray:
    edges = np.concatenate([[ends[0] - width], ends])
    return np.stack([np.histogram(s, bins=edges)[0] for s in spikes], axis=1)


def test_units_binned_on_a_grid_match_the_histogram_convention(nwb_path: Path) -> None:
    with NwbFile(nwb_path) as f:
        a = units_binned_adapter(f, bin_width_s=0.02, grid_from="grid")
        assert check_adapter_contract(a, reads=10, max_samples=16).ok
        block = concat(a.read_all(5))
    ends = 0.02 * np.arange(51)
    np.testing.assert_array_equal(block.values, _histogram(SPIKES, ends, 0.02))
    assert block.values[:, 0].sum() == 5  # the spike at exactly 1.0 lands in the closed last bin
    assert block.values[0, 1] == 1  # -0.02 is the first bin's inclusive start
    assert block.values[:, 2].sum() == 0
    assert [c.name for c in a.info.channels] == ["u000", "u001", "u002"]
    assert a.info.descriptor is not None
    assert a.info.descriptor.bin_width_s == pytest.approx(0.02)


def test_units_default_grid_and_width_checks(nwb_path: Path) -> None:
    with NwbFile(nwb_path) as f:
        block = concat(units_binned_adapter(f, bin_width_s=0.1, start_s=-0.1).read_all())
        ends = -0.1 + 0.1 * np.arange(1, block.n_samples + 1)
        np.testing.assert_array_equal(block.values, _histogram(SPIKES, ends, 0.1))
        with pytest.raises(ReplayError, match="grid spacing"):
            units_binned_adapter(f, bin_width_s=0.01, grid_from="grid")
        with pytest.raises(ReplayError, match="positive"):
            units_binned_adapter(f, bin_width_s=0.0)


def test_rate_quirk_only_for_the_declared_dataset(tmp_path: Path) -> None:
    quirk = build(tmp_path / "a", dandiset="000954", period_quirk=True)
    plain = build(tmp_path / "b", dandiset="999999", period_quirk=True)
    with NwbFile(quirk) as f:
        assert time_axis(f, f.series("grid")).rate_hz == pytest.approx(50.0)
    with NwbFile(plain) as f:  # no guessing: 0.02 Hz stays 0.02 Hz elsewhere
        assert time_axis(f, f.series("grid")).rate_hz == pytest.approx(0.02)


# --- other series and events --------------------------------------------------------------------


def test_timestamped_series_and_processing_paths(nwb_path: Path) -> None:
    with NwbFile(nwb_path) as f:
        kin = timeseries_adapter(f, "kin", modality=Modality.MOTION)
        assert check_adapter_contract(kin).ok
        k = concat(kin.read_all(9))
        pose = concat(
            timeseries_adapter(f, "behavior/Position/wrist", modality=Modality.MOTION).read_all()
        )
        mm = concat(timeseries_adapter(f, "kin", modality=Modality.MOTION, unit="mm").read_all())
    expected_ns = np.rint((0.01 * np.arange(100) + 0.005) * 1e9).astype(np.int64)
    np.testing.assert_array_equal(k.timestamps_ns, expected_ns)
    np.testing.assert_array_equal(k.values, np.arange(200.0).reshape(100, 2))
    np.testing.assert_allclose(mm.values, k.values * 1000.0)
    assert [c.name for c in k.channels] == ["kin.000", "kin.001"]
    assert pose.n_samples == 10
    assert pose.channels[0].unit == "m"


def test_events_are_sorted_and_share_the_clock(nwb_path: Path) -> None:
    with NwbFile(nwb_path) as f:
        ev = read_events(f, "trials", label_column="condition")
        clock = f.clock_domain
        with pytest.raises(ReplayError, match="no interval table"):
            read_events(f, "nope")
    assert ev.labels == ("a", "b")
    assert ev.timestamps_ns == (100_000_000, 700_000_000)
    assert ev.clock_domain == clock


# --- refusals -------------------------------------------------------------------------------------


def test_without_a_manifest_invasive_replay_is_refused(nwb_path: Path) -> None:
    (nwb_path.parent.parent / "MANIFEST.json").unlink()
    with NwbFile(nwb_path) as f:
        report = check_adapter_contract(electrical_series_adapter(f))
    assert "level" in {v.rule for v in report.violations}


def test_explicit_declaration_overrides_and_is_checked(nwb_path: Path) -> None:
    bad = ReplayDeclaration("X:1", "1", "proprietary", "consent", "https://example.org")
    with NwbFile(nwb_path) as f:
        report = check_adapter_contract(electrical_series_adapter(f, replay=bad))
    assert any("not open" in v.detail for v in report.violations)


def test_incomplete_and_insecure_sources_are_refused(nwb_path: Path, tmp_path: Path) -> None:
    part = tmp_path / "x.nwb.part"
    part.write_bytes(nwb_path.read_bytes())
    with pytest.raises(ReplayError, match="not a complete"):
        NwbFile(part)
    with pytest.raises(ReplayError, match="https"):
        NwbFile("http://example.org/x.nwb")
    with NwbFile(nwb_path) as f, pytest.raises(ReplayError, match="no series"):
        f.series("missing")


def test_read_requires_start_and_positive_size(nwb_path: Path) -> None:
    with NwbFile(nwb_path) as f:
        a = electrical_series_adapter(f)
        with pytest.raises(ReplayError, match="start"):
            a.read(10)
        a.start()
        with pytest.raises(ReplayError, match="positive"):
            a.read(0)


# --- real public human data (skipped without the downloads) -------------------------------


def _files(dataset: str) -> list[Path]:
    return [Path(p) for p in sorted(glob.glob(str(DATA / dataset / "*" / "*.nwb")))]


needs_h1 = pytest.mark.skipif(
    not _files("falcon-h1"), reason="run scripts/fetch_dandi.py falcon-h1"
)
needs_h2 = pytest.mark.skipif(
    not _files("falcon-h2"), reason="run scripts/fetch_dandi.py falcon-h2"
)
needs_ecog = pytest.mark.skipif(
    not _files("dandi-000019"), reason="run scripts/fetch_dandi.py dandi-000019"
)


@pytest.mark.dataset
@needs_h1
def test_falcon_h1_spikes_and_kinematics_replay() -> None:
    path = _files("falcon-h1")[0]
    with NwbFile(path) as f:
        units = units_binned_adapter(f, bin_width_s=0.02, grid_from="OpenLoopKinematics")
        report = check_adapter_contract(units, reads=10_000, max_samples=1000)
        assert report.ok, report.violations
        assert units.info.profile is NeuralProfile.L4_REPLAY
        assert units.info.replay is not None
        assert "NCT01894802" in units.info.replay.consent_basis
        block = concat(units.read_all(997))
        spikes = [np.asarray(f.nwb.units["spike_times"][i]) for i in range(len(f.nwb.units))]
        kin = timeseries_adapter(f, "OpenLoopKinematics", modality=Modality.MOTION)
        assert check_adapter_contract(kin, reads=10_000, max_samples=1000).ok
        k = concat(kin.read_all(4096))
        direct = np.asarray(f.nwb.acquisition["OpenLoopKinematics"].data[:], dtype=np.float64)
    ends = 0.02 * np.arange(block.n_samples)
    np.testing.assert_array_equal(block.values, _histogram(spikes, ends, 0.02))
    assert block.values.sum() == sum(s.size for s in spikes)  # no spike lost at bin edges
    assert bool((np.diff(block.timestamps_ns) == 20_000_000).all())
    np.testing.assert_array_equal(k.values, direct)
    np.testing.assert_array_equal(k.timestamps_ns, block.timestamps_ns)  # one session clock


@pytest.mark.dataset
@needs_h1
def test_falcon_h1_chunking_invariance() -> None:
    with NwbFile(_files("falcon-h1")[0]) as f:
        a = concat(
            units_binned_adapter(f, bin_width_s=0.02, grid_from="OpenLoopKinematics").read_all(50)
        )
        b = concat(
            units_binned_adapter(f, bin_width_s=0.02, grid_from="OpenLoopKinematics").read_all(7919)
        )
    assert a.digest() == b.digest()


@pytest.mark.dataset
@needs_h2
def test_falcon_h2_binned_spikes_match_pynwb_exactly() -> None:
    with NwbFile(_files("falcon-h2")[0]) as f:
        a = timeseries_adapter(f, "binned_spikes", modality=Modality.SPIKE_COUNTS)
        assert check_adapter_contract(a, reads=100, max_samples=1000).ok
        block = concat(a.read_all(10_000))
        ts = f.nwb.acquisition["binned_spikes"]
        direct = np.asarray(ts.data[:], dtype=np.float64)
        direct_ns = np.rint(np.asarray(ts.timestamps[:]) * 1e9).astype(np.int64)
        ev = read_events(f, "trials", label_column="cue")
    assert block.values.shape[1] == 192
    assert a.info.channels[0].unit == "count"
    assert a.info.replay is not None
    assert "NCT00912041" in a.info.replay.consent_basis
    np.testing.assert_array_equal(block.values, direct)
    np.testing.assert_array_equal(block.timestamps_ns, direct_ns)
    assert len(ev.labels) > 0
    assert list(ev.timestamps_ns) == sorted(ev.timestamps_ns)


ECOG_DECL = ReplayDeclaration(
    dataset_id="DANDI:000019",
    version="0.220126.2148",
    license="CC-BY-4.0",
    consent_basis="see dataset documentation https://dandiarchive.org/dandiset/000019/0.220126.2148",
    url="https://dandiarchive.org/dandiset/000019/0.220126.2148",
)


@pytest.mark.dataset
@needs_ecog
def test_dandi_000019_ecog_grid_in_microvolts() -> None:
    with NwbFile(_files("dandi-000019")[0], dandiset="000019") as f:
        a = electrical_series_adapter(f, unit="uV", replay=f.replay or ECOG_DECL)
        report = check_adapter_contract(a, reads=3, max_samples=4096)
        assert report.ok, report.violations
        a.start()
        block = a.read(4096)
        es = f.nwb.acquisition["ElectricalSeries"]
        direct = np.asarray(es.data[:4096], dtype=np.float64) * float(es.conversion) * 1e6
        assert block is not None
        assert len(a.info.channels) == 256
        assert {c.unit for c in a.info.channels} == {"uV"}
        assert a.info.nominal_rate_hz == pytest.approx(3051.7578, rel=1e-6)
        np.testing.assert_array_equal(block.values, direct)
        assert a.info.descriptor is not None
        assert any(e.location for e in a.info.descriptor.electrodes)
        if f.replay is None:  # without a manifest the recording is refused, not guessed
            no_decl = electrical_series_adapter(f, replay=None)
            rules = {v.rule for v in check_adapter_contract(no_decl, reads=1).violations}
            assert "level" in rules


@pytest.mark.dataset
@needs_h1
@pytest.mark.skipif(os.environ.get("ESP_NETWORK_TESTS") != "1", reason="set ESP_NETWORK_TESTS=1")
def test_streaming_equals_local_for_the_same_asset() -> None:
    manifest = json.loads((DATA / "falcon-h1" / "MANIFEST.json").read_text())
    rel, meta = sorted(manifest["files"].items())[0]
    with NwbFile(DATA / "falcon-h1" / rel) as local:
        want = concat(
            units_binned_adapter(local, bin_width_s=0.02, grid_from="OpenLoopKinematics").read_all()
        ).digest()
        decl = local.replay
    with NwbFile(dandi_asset_url(meta["asset_id"]), dandiset="000954") as remote:
        a = units_binned_adapter(
            remote, bin_width_s=0.02, grid_from="OpenLoopKinematics", replay=decl
        )
        got = concat(a.read_all()).digest()
        assert check_adapter_contract(a, reads=100, max_samples=1000).ok
    assert got == want


def _official_falcon_loader():  # type: ignore[no-untyped-def]
    """The unmodified ``falcon_challenge/dataloaders.py`` (its hydra-based config is stubbed)."""
    path = os.environ["ESP_FALCON_LOADER"]
    config = types.ModuleType("falcon_challenge.config")
    config.FalconTask = enum.Enum("FalconTask", "h1 h2 m1 m2 b1")  # type: ignore[attr-defined]
    pkg = types.ModuleType("falcon_challenge")
    pkg.__path__ = [str(Path(path).parent)]  # type: ignore[attr-defined]
    sys.modules.setdefault("falcon_challenge", pkg)
    sys.modules["falcon_challenge.config"] = config
    spec = importlib.util.spec_from_file_location("falcon_challenge.dataloaders", path)
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod, config.FalconTask  # type: ignore[attr-defined]


@pytest.mark.dataset
@needs_h1
@pytest.mark.skipif(
    not os.environ.get("ESP_FALCON_LOADER"),
    reason="set ESP_FALCON_LOADER to falcon_challenge/dataloaders.py (pip install --no-deps)",
)
@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_falcon_h1_identical_to_the_official_benchmark_loader() -> None:
    loader, task = _official_falcon_loader()
    for path in _files("falcon-h1"):
        binned, kin, _change, _mask = loader.load_nwb(str(path), dataset=task.h1)
        with NwbFile(path) as f:
            u = concat(
                units_binned_adapter(f, bin_width_s=0.02, grid_from="OpenLoopKinematics").read_all()
            )
            k = concat(
                timeseries_adapter(
                    f, "OpenLoopKinematicsVelocity", modality=Modality.MOTION
                ).read_all()
            )
        np.testing.assert_array_equal(u.values, binned.astype(np.float64), err_msg=path.name)
        np.testing.assert_array_equal(k.values, np.asarray(kin, dtype=np.float64))


def test_non_monotonic_timestamps_are_refused(tmp_path: Path) -> None:
    nwb = NWBFile(
        session_description="broken clock",
        identifier="broken",
        session_start_time=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
    )
    nwb.add_acquisition(
        TimeSeries(name="x", data=np.zeros(3), unit="m", timestamps=np.array([0.0, 0.2, 0.1]))
    )
    path = tmp_path / "broken.nwb"
    with NWBHDF5IO(str(path), "w") as io:
        io.write(nwb)
    with NwbFile(path) as f, pytest.raises(ReplayError, match="strictly increasing"):
        timeseries_adapter(f, "x", modality=Modality.MOTION)


def test_unsupported_nwb_units_are_refused(tmp_path: Path) -> None:
    nwb = NWBFile(
        session_description="odd unit",
        identifier="odd",
        session_start_time=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
    )
    nwb.add_acquisition(TimeSeries(name="x", data=np.zeros(3), unit="furlongs", rate=1.0))
    path = tmp_path / "odd.nwb"
    with NWBHDF5IO(str(path), "w") as io:
        io.write(nwb)
    with NwbFile(path) as f, pytest.raises(ReplayError, match="unsupported NWB unit"):
        timeseries_adapter(f, "x", modality=Modality.MOTION)


def test_explicit_timestamp_grid_keeps_the_files_float_edges(tmp_path: Path) -> None:
    """Bin edges from explicit timestamps are used exactly as stored, never ns-rounded."""
    ends = 0.1 + np.arange(1, 31) / 3.0 * 0.06  # 0.02 s spacing, not representable in ns
    nwb = NWBFile(
        session_description="explicit grid",
        identifier="explicit-grid",
        session_start_time=dt.datetime(2026, 1, 1, tzinfo=dt.UTC),
    )
    nwb.add_acquisition(TimeSeries(name="grid", data=np.zeros((30, 1)), unit="m", timestamps=ends))
    on_edges = ends[[0, 4, 9, 19]]  # spikes exactly on stored edges
    nwb.add_unit(spike_times=on_edges)
    nwb.add_unit(spike_times=np.nextafter(on_edges, 0))  # one ulp before each edge
    path = tmp_path / "explicit.nwb"
    with NWBHDF5IO(str(path), "w") as io:
        io.write(nwb)
    with NwbFile(path) as f:
        block = concat(units_binned_adapter(f, bin_width_s=0.02, grid_from="grid").read_all())
    np.testing.assert_array_equal(
        block.values, _histogram([on_edges, np.nextafter(on_edges, 0)], ends, 0.02)
    )


@pytest.mark.skipif(
    not glob.glob(str(DATA / "ajile12" / "sub-01" / "*.nwb")), reason="run scripts/fetch_dandi.py"
)
def test_ajile12_naturalistic_ecog_streams_under_l4_replay() -> None:
    """Long naturalistic recordings: lazy reads, a small slice of a ~16 GB file."""
    path = sorted(glob.glob(str(DATA / "ajile12" / "sub-01" / "*.nwb")))[0]
    with NwbFile(Path(path)) as f:
        a = electrical_series_adapter(f, "ElectricalSeries")
        assert a.info.profile is NeuralProfile.L4_REPLAY
        assert a.info.replay is not None
        assert a.info.replay.dataset_id == "DANDI:000055"
        assert a.info.nominal_rate_hz == pytest.approx(500.0)
        assert all(c.modality is Modality.ECOG and c.unit == "uV" for c in a.info.channels)
        report = check_adapter_contract(a, reads=3, max_samples=500)
    assert report.ok, report.violations
    assert report.samples == 1500
