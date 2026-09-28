# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M15 gate: Typed Hive (research track).

- All four Hive TLVs have golden vectors.
- A simulated episode with >= 5 synthetic members runs the full lifecycle.
- EMO mixing = 0 is enforced.
- The quorum and the FROST signature are verified (plain Ed25519).
- The emergence audit runs on synthetic episodes. It supports no claims about humans.

Details in ``tests/unit/hive``.
"""

import json
import os
import re
from pathlib import Path

import pytest

from esp.codec.tlv import iter_tlvs
from esp.core.taoss_types import TaossType as T
from esp.crypto.primitives import ed25519_verify
from esp.hive.episode import HIVE_CAPSULE, Phase
from esp.hive.simulation import simulate
from esp.hive.tlv import CollectiveIntent

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]


def test_m15_work_package_verified() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    m = re.search(r"^## WP-070 — .*?\*\*Status:\*\* `([A-Z_]+)`", plan, re.S | re.M)
    assert m is not None
    assert m.group(1) == "VERIFIED"


def test_all_four_hive_tlvs_have_golden_vectors() -> None:
    doc = json.loads((ROOT / "vectors" / "hive" / "tlvs.json").read_text())
    codes = set()
    for v in doc["vectors"]:
        if "expect_error" not in v:
            (tlv,) = iter_tlvs(bytes.fromhex(v["tlv_hex"]))
            codes.add(tlv.code)
    assert codes == {0x70, 0x71, 0x72, 0x73}
    index = json.loads((ROOT / "vectors" / "INDEX.json").read_text())
    assert "hive/tlvs.json" in index["files"]


def test_simulated_episode_full_lifecycle() -> None:
    r = simulate(n=6, machines=1, rounds=3, seed=0)
    ep = r.episode
    assert len(r.members) >= 5
    assert ep.phase is Phase.PUBLISH
    # EMO mixing = 0 and EMO only as a distribution
    assert ep.config.coupling[T.EMO] == 0.0
    emo = next(t for t in r.report.types if t.type is T.EMO)
    assert emo.emo_mixing == 0.0
    assert emo.min_autonomy == 1.0
    # quorum + FROST, verified as a plain Ed25519 signature
    cic = CollectiveIntent.decode(r.cic_tlv)
    assert cic.n_contributors >= ep.config.quorum_min
    ed25519_verify(r.guardians.group_public, cic.signing_message(), r.cic_tlv.value[-64:])
    # emergence audit executed on synthetic held-out episodes
    kno = next(t for t in r.report.types if t.type is T.KNO)
    assert kno.emergence is not None
    assert r.capsule_kind == HIVE_CAPSULE
    assert r.report.label == "hive"
    out = os.environ.get("ESP_REPORT_DIR")
    if out:
        metrics = {
            "members": len(r.members),
            "machines": sum(1 for m in r.members if m.kind.value == "machine"),
            "audit": r.report.as_dict(),
            "releases": r.releases,
            "cic": {"n_contributors": cic.n_contributors, "rule": cic.rule_id.name},
            "note": "synthetic members only; no claim about humans or collective cognition",
        }
        Path(out, "M15-metrics.json").write_text(json.dumps(metrics, indent=2) + "\n")
