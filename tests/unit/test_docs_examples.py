# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Every ```python block in docs/guide runs (WP-046): the guides cannot silently rot.

The blocks of one guide share a namespace and run in order, as a reader would.
"""

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
GUIDES = sorted((ROOT / "docs" / "guide").glob("*.md"))
BLOCK = re.compile(r"^```python\n(.*?)^```", re.DOTALL | re.MULTILINE)
EXPECTED = {
    "ARCHITECTURE.md",
    "PSYCHOLOGY_MODEL.md",
    "PROTOCOL_WALKTHROUGH.md",
    "CONSENT_EXAMPLES.md",
    "SECURITY_EXAMPLES.md",
    "WHAT_ESP_IS_NOT.md",
    "ADAPTER_GUIDE.md",
    "README.md",
    "VISION.md",
    "DOCKING.md",
}


def test_all_guides_present() -> None:
    assert {g.name for g in GUIDES} == EXPECTED


RUNNABLE = [g for g in GUIDES if BLOCK.search(g.read_text("utf-8"))]


@pytest.mark.parametrize("guide", RUNNABLE, ids=lambda g: g.name)
def test_guide_examples_run(guide: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(ROOT)
    namespace: dict[str, object] = {"__name__": f"guide_{guide.stem.lower()}"}
    blocks = BLOCK.findall(guide.read_text("utf-8"))
    for i, code in enumerate(blocks):
        exec(compile(code, f"{guide.name}[block {i}]", "exec"), namespace)


def test_guides_have_license_headers() -> None:
    for g in GUIDES:
        assert "SPDX-" + "License-Identifier: CC-BY-SA-4.0" in g.read_text("utf-8"), g.name
