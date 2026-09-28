# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M16 gate: horizon interfaces (WP-045, WP-071, WP-075).

Plan gate: "interfaces, simulator contracts and conformance tests only; no
functional claim (class FUTURE)". Details in ``tests/unit/adapters/neural``,
``tests/unit/legacy_profile`` and ``tests/unit/session/test_pq.py``.
"""

import re
import uuid
from pathlib import Path

import pytest

from esp.adapters import neural
from esp.adapters.neural import SimulatedNeuralAdapter, SimulatorDecoder, band_features
from esp.core.taoss_types import TaossType
from esp.crypto.primitives import SigningKey
from esp.legacy_profile import (
    ActivationCondition,
    ActivationRule,
    LegacyOrigin,
    LegacyPolicy,
    LegacyRefused,
    Quorum,
    RecipientClass,
    RendererRight,
    UseRequest,
    activate,
    attest_activation,
    authorize_use,
)
from esp.session.descriptor import PqMode, SessionDescriptor
from esp.session.pq import assess
from tests.unit.session.test_pq import claim_violations, scanned_files

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]
T = TaossType


def _status(plan: str, wp: str) -> str:
    m = re.search(rf"^## {wp} — .*?\*\*Status:\*\* `([A-Z_]+)`", plan, re.S | re.M)
    assert m is not None, wp
    return m.group(1)


def test_m16_work_packages_status() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    assert _status(plan, "WP-075") == "VERIFIED"
    for wp in ("WP-045", "WP-071"):  # class FUTURE: interface verified, no functional claim
        assert _status(plan, wp) in {"VERIFIED", "FUTURE"}, wp


def test_future_modules_make_no_functional_claim() -> None:
    import esp.legacy_profile.policy as legacy  # noqa: PLC0415

    assert neural.CLAIM_CLASS == legacy.CLAIM_CLASS == "FUTURE"
    for mod in (neural.interface, legacy):
        assert mod.__doc__ is not None
        assert "FUTURE" in mod.__doc__


def test_neural_simulator_contract_end_to_end() -> None:
    a = SimulatedNeuralAdapter(16, n_channels=6)
    report = neural.check_adapter_contract(a, reads=4, max_samples=512)
    assert report.ok, report.violations
    a.start()
    block = a.read(1024)
    assert block is not None
    f = band_features(block)
    dec = SimulatorDecoder(len(f.names), output_types=(T.SEN, T.TEM, T.EMO))
    assert neural.check_decoder_contract(dec, f).ok
    # EMO is declared by the decoder but not consented: it is never produced.
    out = neural.decode_boundary(dec, f, frozenset({T.SEN, T.TEM}))
    assert set(out) == {T.SEN, T.TEM}


def test_legacy_emo_synthesis_needs_explicit_prior_consent() -> None:
    originator = SigningKey.from_seed(b"\x16" * 32)
    witnesses = [SigningKey.from_seed(bytes([0x60 + i]) * 32) for i in range(2)]
    p = LegacyPolicy(
        policy_id=uuid.UUID("16161616-1616-4616-8616-161616161616"),
        originator_pk=originator.public_bytes,
        created_ns=1,
        types=frozenset({T.KNO, T.EMO}),
        recipients=frozenset({RecipientClass.FAMILY}),
        activation=(ActivationRule(ActivationCondition.DEATH_CERTIFIED),),
        retention_until_ns=10**15,
        renderer_rights=RendererRight.TEXT,
        machine_continuation=True,
        posthumous_emo_synthesis=False,
        quorum=Quorum(tuple(w.public_bytes for w in witnesses), 2),
    ).signed(originator)
    c = ActivationCondition.DEATH_CERTIFIED
    act = activate(p, c, 100, [attest_activation(p, c, 100, w) for w in witnesses])
    base = {"recipient": RecipientClass.FAMILY, "renderer": RendererRight.TEXT, "now_ns": 101}
    recorded = UseRequest(
        types=frozenset({T.EMO}),
        origin=LegacyOrigin.RECORDED_HUMAN_STATE,
        **base,  # type: ignore[arg-type]
    )
    assert authorize_use(p, act, recorded) is LegacyOrigin.RECORDED_HUMAN_STATE
    synth = UseRequest(
        types=frozenset({T.EMO}),
        origin=LegacyOrigin.LATER_SYNTHETIC_INFERENCE,
        **base,  # type: ignore[arg-type]
    )
    with pytest.raises(LegacyRefused):
        authorize_use(p, act, synth)
    with pytest.raises(LegacyRefused):  # no unilateral activation
        activate(p, c, 100, [attest_activation(p, c, 100, witnesses[0])])


def test_pq_declaration_and_claim_lint() -> None:
    assert SessionDescriptor().pq_mode is PqMode.CLASSICAL_ONLY
    assert not assess(SessionDescriptor()).outer_hybrid_verified
    violations = {
        str(p): claim_violations(p.read_text("utf-8", errors="replace")) for p in scanned_files()
    }
    assert not {k: v for k, v in violations.items() if v}
