# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M3a gate: key lifecycle and runtime privacy (plan section 54a).

Rotation/revocation lineage green; DP numbers from V13 reproduced; ledger
crash-safe. Evidence runs via ``run_milestone.py M3a``.
"""

import math
import re
from pathlib import Path

import pytest

from esp.codec.header import DpLevel
from esp.core.taoss_types import TaossType
from esp.privacy.dp import REFERENCE_PROFILES, epsilon_rdp, rdp_coefficient

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]


def test_m3a_work_packages_verified() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    for wp in ("WP-053", "WP-055", "WP-072"):
        m = re.search(rf"^## {wp} — .*?\*\*Status:\*\* `([A-Z_]+)`", plan, re.S | re.M)
        assert m is not None
        assert m.group(1) == "VERIFIED", wp


def test_v13_dp_numbers_reproduced() -> None:
    sigma = REFERENCE_PROFILES[DpLevel.L1_BALANCED_REF][1]
    five = [TaossType.KNO, TaossType.INT, TaossType.CTX, TaossType.SEN, TaossType.TEM]
    eps, _ = epsilon_rdp(
        100 * rdp_coefficient(dict.fromkeys(five, 1.0), dict.fromkeys(five, sigma)), 1e-6
    )
    assert math.isclose(sigma, 24.42, abs_tol=0.01)
    assert math.isclose(eps, 11.3, abs_tol=0.05)
