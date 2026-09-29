# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-088: pinned public invasive datasets (registry, local verification, replay declaration)."""

import hashlib
import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest

from esp.adapters.neural import (
    ElectrodeSpec,
    NeuralDeviceDescriptor,
    NeuralProfile,
    check_profile,
)
from esp.adapters.neural.datasets import (
    PinStatus,
    data_dir,
    load_registry,
    replay_declaration,
    verify_local,
)
from esp.observation.model import Modality

ROOT = Path(__file__).resolve().parents[4]
IDS = {"falcon-h1", "falcon-h2", "dandi-000019", "ajile12"}
DANDISETS = {
    "falcon-h1": "000954",
    "falcon-h2": "000950",
    "dandi-000019": "000019",
    "ajile12": "000055",
}


def _pin_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "pin", ROOT / "scripts" / "pin_neural_datasets.py"
    )
    assert spec is not None
    assert spec.loader is not None
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_registry_declares_the_four_m18_datasets() -> None:
    reg = load_registry()
    assert set(reg) == IDS
    assert set(_pin_script().SPEC) == IDS
    for ds in reg.values():
        assert ds.dandiset == DANDISETS[ds.id]
        assert ds.role
        assert ds.consent_basis
        assert ds.consent_pointer.startswith("https://dandiarchive.org/dandiset/")
        if ds.status is PinStatus.PINNED:
            assert ds.license == "CC-BY-4.0"
            assert ds.version
            assert ds.version_mutable == (ds.version == "draft")
            assert ds.files
            for f in ds.files:
                assert len(f.sha256) == 64
                int(f.sha256, 16)
                assert f.size > 0
                assert f.path.endswith(".nwb")


def test_no_neural_data_is_tracked_in_the_repository() -> None:
    assert not list((ROOT / "datasets").rglob("*.nwb"))
    assert not list((ROOT / "src").rglob("*.nwb"))
    assert not list((ROOT / "tests").rglob("*.nwb"))


def _fake(tmp_path: Path, content: bytes = b"neural bytes") -> tuple[Path, Path]:
    data = tmp_path / "data"
    (data / "falcon-h1" / "sub-x").mkdir(parents=True)
    f = data / "falcon-h1" / "sub-x" / "a.nwb"
    f.write_bytes(content)
    manifest = {
        "id": "falcon-h1",
        "dandiset": "000954",
        "version": "draft",
        "license": ["spdx:CC-BY-4.0"],
        "citation": "Test (2024)",
        "url": "https://dandiarchive.org/dandiset/000954/draft",
        "files": {
            "sub-x/a.nwb": {
                "asset_id": "00000000-0000-0000-0000-000000000001",
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }
        },
    }
    (data / "falcon-h1" / "MANIFEST.json").write_text(json.dumps(manifest))
    reg_path = tmp_path / "neural.json"
    reg_path.write_text(json.dumps(_pin_script().build({}, data)))
    return data, reg_path


def test_verify_local_detects_missing_size_and_digest(tmp_path: Path) -> None:
    data, reg_path = _fake(tmp_path)
    reg = load_registry(reg_path)
    assert reg["falcon-h1"].status is PinStatus.PINNED
    assert reg["ajile12"].status is PinStatus.PENDING
    assert verify_local("falcon-h1", root=data, registry=reg).ok
    f = data / "falcon-h1" / "sub-x" / "a.nwb"
    f.write_bytes(b"neural bytez")  # same size, other content
    rep = verify_local("falcon-h1", root=data, registry=reg)
    assert rep.digest_mismatch == ("sub-x/a.nwb",)
    assert not rep.ok
    assert verify_local("falcon-h1", root=data, registry=reg, deep=False).ok  # size-only
    f.write_bytes(b"short")
    assert verify_local("falcon-h1", root=data, registry=reg).size_mismatch == ("sub-x/a.nwb",)
    f.unlink()
    rep = verify_local("falcon-h1", root=data, registry=reg)
    assert rep.missing == ("sub-x/a.nwb",)
    assert not rep.complete
    with pytest.raises(ValueError, match="not pinned"):
        verify_local("ajile12", root=data, registry=reg)


def test_pin_build_keeps_earlier_pins_and_rejects_wrong_dandiset(tmp_path: Path) -> None:
    pin = _pin_script()
    data, reg_path = _fake(tmp_path)
    previous = json.loads(reg_path.read_text())
    (data / "falcon-h1" / "MANIFEST.json").unlink()
    rebuilt = pin.build(previous, data)
    h1 = next(d for d in rebuilt["datasets"] if d["id"] == "falcon-h1")
    assert h1["status"] == "pinned"
    bad = data / "falcon-h2"
    bad.mkdir()
    (bad / "MANIFEST.json").write_text(json.dumps({"dandiset": "999999", "files": {}}))
    with pytest.raises(ValueError, match="dandiset"):
        pin.build(previous, data)


def test_replay_declaration_satisfies_the_l4_replay_profile(tmp_path: Path) -> None:
    data, reg_path = _fake(tmp_path)
    reg = load_registry(reg_path)
    decl = replay_declaration("falcon-h1", root=data, registry=reg)
    assert decl.dataset_id == "DANDI:000954"
    manifest = data / "falcon-h1" / "MANIFEST.json"
    assert decl.manifest_sha256 == hashlib.sha256(manifest.read_bytes()).hexdigest()
    desc = NeuralDeviceDescriptor(
        manufacturer="(recording)",
        model="Utah array",
        firmware="n/a",
        device_id="replay-falcon-h1",
        modalities=frozenset({Modality.SPIKE_COUNTS}),
        electrodes=(ElectrodeSpec("ch000"),),
        unit="count",
        clock_domain="replay:nwb",
        bin_width_s=0.02,
    )
    assert check_profile(desc, NeuralProfile.L4_REPLAY, decl).ok
    with pytest.raises(ValueError, match="not pinned"):
        replay_declaration("ajile12", root=data, registry=reg)


# --- data-gated: the real downloads (skip cleanly without data) ------------------------------


def _pinned_and_present(ds_id: str) -> bool:
    ds = load_registry()[ds_id]
    return ds.status is PinStatus.PINNED and (data_dir() / ds_id / "MANIFEST.json").is_file()


@pytest.mark.skipif(not _pinned_and_present("falcon-h1"), reason="FALCON H1 not downloaded")
def test_falcon_h1_local_copy_matches_the_pins() -> None:
    rep = verify_local("falcon-h1")
    assert rep.ok, (rep.missing, rep.size_mismatch, rep.digest_mismatch)
    assert replay_declaration("falcon-h1").manifest_sha256


@pytest.mark.skipif(not _pinned_and_present("falcon-h2"), reason="FALCON H2 not downloaded")
def test_falcon_h2_local_copy_matches_the_pins_by_size() -> None:
    assert verify_local("falcon-h2", deep=False).ok
