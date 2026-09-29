# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M18 gate: implant-ready protocol profile (WP-086 … WP-091).

Public human intracortical data (FALCON H1, DANDI 000954) travels the whole path
a future device would take:

replay adapter (same contract as a live device) → emulated implant stream with
declared perturbations → binned features → reference decoder → mapping profile
(never EMO or KNO) → typed ESP frame → encrypted session → receiver.

No ESP wire change. Live-implant validation remains claims level 6.
"""

import json
import os
import re
import uuid
from pathlib import Path

import numpy as np
import pytest

from esp.adapters.neural.emulator import EmulatorConfig, ImplantStreamEmulator, Perturbation, detect
from esp.adapters.neural.interface import NeuralFeatures, check_adapter_contract
from esp.adapters.neural.mapping import MappedNeuralDecoder, typed_frame
from esp.adapters.neural.model import NeuralProfile
from esp.adapters.neural.nwb import NwbFile, units_binned_adapter
from esp.bench.neural_falcon import _fit, features, load_session
from esp.conformance import neural
from esp.core.provenance import Provenance, SourceKind
from esp.core.taoss_types import TaossType
from esp.crypto.noise_ik import StaticKeyPair
from esp.session.endpoint import ReceiverEndpoint, SenderEndpoint
from esp.session.profiles import custom_profile_digest
from tests.integration.test_endpoint import (
    ALL,
    DECLARATION,
    MASTER,
    NOW,
    RECEIVER_ID,
    REGISTRIES,
    WIRE,
    descriptor,
    establish,
    receiver_capability_for,
    sender_capability,
)

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]
DATA = Path(os.environ.get("ESP_DATA_DIR", ROOT / "data" / "external")) / "falcon-h1"
HAS_DATA = (DATA / "MANIFEST.json").exists()
S = 1_000_000_000


NEURAL = "esp-typeset-neural-v1"


def neural_pair(tmp: Path) -> tuple[SenderEndpoint, ReceiverEndpoint]:
    """A session pinned to the neural type-set profile (INT; EMO masked; KNO never)."""
    desc = descriptor(registries=REGISTRIES | {NEURAL: custom_profile_digest(NEURAL)})
    r_static = StaticKeyPair.generate()
    sender = SenderEndpoint(
        master=MASTER,
        static=StaticKeyPair.generate(),
        responder_static=r_static.public_bytes,
        receiver_identity=RECEIVER_ID.public_bytes,
        descriptor=desc,
        capability=sender_capability(),
        state_dir=tmp,
        wire=WIRE,
        declaration=DECLARATION,
    )
    receiver = ReceiverEndpoint(
        identity=RECEIVER_ID,
        static=r_static,
        descriptor=desc,
        capability=receiver_capability_for(0x3F),
        trusted_issuers=frozenset({MASTER.public_bytes}),
        wire=WIRE,
        declaration=DECLARATION,
    )
    return sender, receiver


def test_m18_work_packages_verified() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    for wp in ("WP-086", "WP-087", "WP-088", "WP-089", "WP-090", "WP-091"):
        m = re.search(rf"^## {wp} — .*?\*\*Status:\*\* `([A-Z_]+)`", plan, re.S | re.M)
        assert m is not None
        assert m.group(1) == "VERIFIED", wp


def test_neural_conformance_category_passes() -> None:
    checks = neural.neural_checks()
    assert checks
    for name, fn in checks:
        fn()  # raises on the first failure, naming it
        assert name


@pytest.mark.skipif(not HAS_DATA, reason="run scripts/fetch_dandi.py falcon-h1")
def test_real_implant_recording_passes_the_live_device_contract_and_emulation() -> None:
    path = sorted((DATA / "sub-HumanPitt-held-in-calib").glob("*.nwb"))[0]
    with NwbFile(path) as f:
        adapter = units_binned_adapter(f, bin_width_s=0.02, grid_from="OpenLoopKinematics")
        assert adapter.info.profile is NeuralProfile.L4_REPLAY
        assert check_adapter_contract(adapter, reads=20, max_samples=250).ok
        emu = ImplantStreamEmulator(
            units_binned_adapter(f, bin_width_s=0.02, grid_from="OpenLoopKinematics"),
            EmulatorConfig(reconnects=(20 * S,), gain_steps=((40 * S, 0.4),)),
        )
        emu.start()
        blocks = []
        while (b := emu.read(250)) is not None:
            blocks.append(b)
        emu.stop()
    visible = detect(blocks, 50.0).visible
    assert Perturbation.RECONNECT in visible
    assert {e.kind for e in emu.events} >= {Perturbation.RECONNECT, Perturbation.GAIN_STEP}


@pytest.mark.skipif(not HAS_DATA, reason="run scripts/fetch_dandi.py falcon-h1")
def test_decoded_implant_intention_travels_as_typed_consented_esp(tmp_path: Path) -> None:
    manifest = json.loads((DATA / "MANIFEST.json").read_text(encoding="utf-8"))
    calib = load_session(
        sorted((DATA / "sub-HumanPitt-held-in-calib").glob("*19250108*"))[0], manifest
    )
    z = features(calib, lags=4, tau_bins=3.0)
    ridge = _fit([z], [calib.velocity], [calib.mask], 100.0, [calib.name])
    mapped = MappedNeuralDecoder([ridge], n_features=z.shape[1])
    t = int(np.flatnonzero(calib.mask)[500])
    feats = NeuralFeatures(
        names=tuple(f"f{i}" for i in range(z.shape[1])),
        values=z[t],
        window_start_ns=t * 20_000_000,
        window_end_ns=(t + 1) * 20_000_000,
        provenance=Provenance(
            source_kind=SourceKind.DERIVED,
            producer_id="esp-neural-features",
            producer_version="1.0.0",
            source_refs=("dataset:DANDI.000954",),
        ),
    )
    s, r = neural_pair(tmp_path)
    establish(s, r)
    frame = typed_frame(
        mapped,
        feats,
        frozenset({TaossType.INT, TaossType.EMO, TaossType.KNO}),  # EMO/KNO are never decoded
        timeline_id=s.timeline_id,
        sequence=1,
        now_ns=NOW,
        source_refs=("dataset:DANDI.000954",),
    )
    assert [b.type for b in frame.types] == [TaossType.INT]
    keep = ALL.model_copy(update={"keep_evidence_refs": True})
    res = r.receive(s.send_frame(frame, keep, now_ns=NOW), now_ns=NOW)
    assert res.accepted, res.violations
    assert res.frame is not None
    got = {b.type: b for b in res.frame.types}
    assert set(got) == {TaossType.INT}  # KNO never sent, EMO explicitly masked
    assert TaossType.EMO in res.frame.masked_types
    expected = mapped.decode(feats, frozenset({TaossType.INT}))[TaossType.INT]
    assert np.allclose(got[TaossType.INT].latent, expected, atol=1e-5)
    prov = res.frame.provenance
    assert prov.encoder_id == "esp-neural-ridge@1.0.0"
    assert any(ref.startswith("calibration:") for ref in prov.evidence_refs)
    assert "dataset:DANDI.000954" in prov.evidence_refs
    # data minimization: without explicit permission the evidence references stay home
    frame2 = frame.model_copy(update={"frame_id": uuid.uuid4(), "sequence": 2})
    res2 = r.receive(s.send_frame(frame2, ALL, now_ns=NOW + 1), now_ns=NOW + 1)
    assert res2.accepted
    assert res2.frame is not None
    assert res2.frame.provenance.evidence_refs == ()


def test_neural_profile_never_carries_kno_and_always_masks_emo() -> None:
    from esp.codec.errors import WireError  # noqa: PLC0415
    from esp.session.profiles import CUSTOM_PROFILES  # noqa: PLC0415

    p = CUSTOM_PROFILES[NEURAL]
    p.check(frozenset({TaossType.INT, TaossType.SEN}), frozenset({TaossType.EMO}))
    with pytest.raises(WireError, match="not allowed"):
        p.check(frozenset({TaossType.INT, TaossType.KNO}), frozenset({TaossType.EMO}))
    with pytest.raises(WireError, match="explicitly masked"):
        p.check(frozenset({TaossType.INT}), frozenset())
    with pytest.raises(WireError, match="missing"):
        p.check(frozenset({TaossType.SEN}), frozenset({TaossType.EMO}))
