# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""M14 gate: persistence and recall (XCF).

148-byte header byte-exact, CID/signature golden vectors; gate revocation
prevents first access; recall respects NO_REPLAY across the whole lineage;
trust-vector admissibility enforced. Details in ``tests/unit/xcf``.
"""

import json
import re
from pathlib import Path

import pytest

from esp.xcf.capsule import HEADER, Capsule

pytestmark = pytest.mark.milestone
ROOT = Path(__file__).resolve().parents[2]


def test_m14_work_packages_verified() -> None:
    plan = (ROOT / "docs" / "MASTER_IMPLEMENTATION_PLAN.md").read_text(encoding="utf-8")
    for wp in ("WP-068", "WP-069"):
        m = re.search(rf"^## {wp} — .*?\*\*Status:\*\* `([A-Z_]+)`", plan, re.S | re.M)
        assert m is not None
        assert m.group(1) == "VERIFIED", wp


def test_golden_capsules() -> None:
    assert HEADER.size == 148
    vectors = json.loads((ROOT / "vectors" / "xcf" / "capsules.json").read_text())["vectors"]
    parent = bytes(32)
    for v in vectors:
        c = Capsule(bytes.fromhex(v["capsule_hex"]))
        assert c.raw[:148].hex() == v["header_hex"]
        c.verify_signature()
        assert c.cid.hex() == v["cid"]
        assert c.header.parent_cid == parent  # the chain is explicit lineage
        parent = c.cid
