# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-055 acceptance tests: runtime DP, TLV_DP_PARAMS, ledger, receiver audit."""

import math
import uuid
from pathlib import Path

import numpy as np
import pytest

from esp.codec.errors import WireError
from esp.codec.header import DpLevel
from esp.codec.tlv import Tlv
from esp.core.taoss_types import TaossType
from esp.privacy.dp import (
    REFERENCE_PROFILES,
    Adjacency,
    DpAuditor,
    DpParams,
    PrivacyBudgetError,
    PrivacyLedger,
    classical_sigma,
    clip_and_noise,
    consent_text,
    effective_information_bits,
    epsilon_rdp,
    epsilon_rdp_grid,
    rdp_coefficient,
)

T = TaossType
CAP = uuid.UUID("31313131-3131-4131-8131-313131313131")
BAL = REFERENCE_PROFILES[DpLevel.L1_BALANCED_REF][1]
FIVE = [T.KNO, T.INT, T.CTX, T.SEN, T.TEM]


# --- V13 reference numbers ----------------------------------------------------------


def test_reference_sigmas_match_v13() -> None:
    assert math.isclose(BAL, 24.42, abs_tol=0.01)
    assert math.isclose(REFERENCE_PROFILES[DpLevel.L1_PRIVATE_REF][1], 122.13, abs_tol=0.01)


def test_per_type_composition_matches_v13() -> None:
    c = 100 * rdp_coefficient({T.EMO: 1.0}, {T.EMO: BAL})
    eps, alpha = epsilon_rdp(c, 1e-6)
    assert math.isclose(eps, 4.6, abs_tol=0.05)
    assert math.isclose(alpha, 7.4, abs_tol=0.05)
    assert epsilon_rdp_grid(c, 1e-6) >= eps  # grid is never tighter than the optimum


def test_joint_multitype_composition_matches_v13() -> None:
    c = 100 * rdp_coefficient(dict.fromkeys(FIVE, 1.0), dict.fromkeys(FIVE, BAL))
    assert math.isclose(c, 1.677, abs_tol=0.001)
    eps, alpha = epsilon_rdp(c, 1e-6)
    assert math.isclose(eps, 11.3, abs_tol=0.05)
    assert math.isclose(alpha, 3.87, abs_tol=0.01)


def test_effective_information_rate_matches_v13() -> None:
    assert math.isclose(effective_information_bits(64, 1.0, BAL), 1.2e-3, rel_tol=0.02)


def test_classical_calibration_only_for_eps_below_one() -> None:
    with pytest.raises(ValueError, match="0 < eps < 1"):
        classical_sigma(1.0, 1.0, 1e-8)


# --- mechanism --------------------------------------------------------------------------


def test_clipping_then_noise(rng: np.random.Generator) -> None:
    big = np.full(64, 10.0)
    out = clip_and_noise(big, 1.0, 1e-12, rng)
    assert math.isclose(float(np.linalg.norm(out)), 1.0, rel_tol=1e-6)
    small = np.full(64, 0.01)
    assert np.allclose(clip_and_noise(small, 1.0, 1e-12, rng), small)
    noisy = clip_and_noise(np.zeros(20000), 1.0, 2.0, rng)
    assert math.isclose(float(np.std(noisy)), 2.0, rel_tol=0.03)


# --- TLV --------------------------------------------------------------------------------------


def params(**kw: object) -> DpParams:
    fields: dict[str, object] = {
        "capability_id": CAP,
        "adjacency": Adjacency.FRAME,
        "segment_window": 0,
        "clip_norms": dict.fromkeys(FIVE, 1.0),
        "sigmas": dict.fromkeys(FIVE, float(np.float32(BAL))),
        "composition_k": 100,
        "epsilon_spent": 11.31,
        "delta_target": 1e-6,
    }
    return DpParams(**(fields | kw))  # type: ignore[arg-type]


def test_dp_params_layout_is_82_bytes_for_five_types() -> None:
    tlv = params().encode()
    assert len(tlv.value) == 82  # V13: 87-byte TLV = 5-byte header + 82-byte body
    back = DpParams.decode(tlv)
    assert back.composition_k == 100
    assert set(back.clip_norms) == set(FIVE)


@pytest.mark.parametrize(
    ("patch", "match"),
    [
        (lambda v: v[:21] + b"\x04" + v[22:], "n_types"),
        (lambda v: v[:-1] + b"\x01", "reserved"),
        (lambda v: v[:-7] + b"\x02" + v[-6:], "flags"),
        (lambda v: v[:10], "malformed"),
    ],
)
def test_dp_params_rejects_malformed(patch, match: str) -> None:  # type: ignore[no-untyped-def]
    with pytest.raises(WireError, match=match):
        DpParams.decode(Tlv(0x30, patch(params().encode().value)))


# --- ledger --------------------------------------------------------------------------------


def test_ledger_is_monotone_persistent_and_bounded(tmp_path: Path) -> None:
    path = tmp_path / "ledger.json"
    c = rdp_coefficient(dict.fromkeys(FIVE, 1.0), dict.fromkeys(FIVE, BAL))
    ledger = PrivacyLedger(path, CAP, ceiling=11.5)
    for _ in range(100):
        ledger.charge(c)
    assert ledger.k == 100
    assert math.isclose(ledger.epsilon_spent, 11.3, abs_tol=0.05)
    reloaded = PrivacyLedger(path, CAP, ceiling=11.5)  # crash / restart: no budget reset
    assert (reloaded.k, reloaded.c_total) == (ledger.k, ledger.c_total)
    while epsilon_rdp(reloaded.c_total + c, 1e-6)[0] <= 11.5:
        reloaded.charge(c)
    k_before = reloaded.k
    with pytest.raises(PrivacyBudgetError, match="exceed the DP ceiling"):
        reloaded.charge(c)
    assert reloaded.k == k_before  # a refused release changes nothing
    assert PrivacyLedger(path, CAP, ceiling=11.5).k == k_before
    with pytest.raises(PrivacyBudgetError, match="another capability"):
        PrivacyLedger(path, uuid.uuid4(), ceiling=11.5)


# --- receiver audit ------------------------------------------------------------------------


def test_receiver_audit_accepts_consistent_accounting() -> None:
    auditor = DpAuditor(ceiling=12.0)
    eps = auditor.audit(DpLevel.L1_BALANCED_REF, params(), frozenset(FIVE))
    assert math.isclose(eps, 11.31, abs_tol=1e-3)


def test_receiver_audit_rejects_inconsistencies() -> None:
    a = DpAuditor(ceiling=12.0)
    with pytest.raises(PrivacyBudgetError, match="below the accountant"):
        a.audit(DpLevel.L1_BALANCED_REF, params(epsilon_spent=5.0), frozenset(FIVE))
    with pytest.raises(PrivacyBudgetError, match="ceiling"):
        DpAuditor(ceiling=10.0).audit(DpLevel.L1_BALANCED_REF, params(), frozenset(FIVE))
    with pytest.raises(PrivacyBudgetError, match="below the L1_BALANCED_REF reference"):
        a.audit(
            DpLevel.L1_BALANCED_REF,
            params(sigmas=dict.fromkeys(FIVE, 10.0), epsilon_spent=11.99),
            frozenset(FIVE),
        )
    with pytest.raises(PrivacyBudgetError, match="not clipped"):
        a.audit(DpLevel.L1_BALANCED_REF, params(), frozenset({T.EMO}))
    with pytest.raises(WireError, match="requires TLV_DP_PARAMS"):
        a.audit(DpLevel.L1_BALANCED_REF, None, frozenset(FIVE))
    with pytest.raises(WireError, match="must not carry"):
        a.audit(DpLevel.NONE, params(), frozenset(FIVE))


def test_receiver_detects_ledger_rollback() -> None:
    a = DpAuditor(ceiling=20.0)
    a.audit(DpLevel.L1_BALANCED_REF, params(), frozenset(FIVE))
    rollback = params(composition_k=50, epsilon_spent=7.7)  # consistent for k=50, but lower
    with pytest.raises(PrivacyBudgetError, match="rollback"):
        a.audit(DpLevel.L1_BALANCED_REF, rollback, frozenset(FIVE))


def test_consent_text_never_calls_none_differentially_private() -> None:
    assert "not differentially private" in consent_text(DpLevel.NONE)
    assert "Local differential privacy" in consent_text(DpLevel.L1_PRIVATE_REF)
