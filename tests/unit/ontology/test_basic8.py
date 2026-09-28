# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-009 acceptance tests for ``esp-emo-v13-basic8-v1``."""

from pathlib import Path

from esp.core.taoss_types import TaossType
from esp.ontology.profiles import BASIC8_ID, BASIC8_ORDER, basic8_registry

GOLDEN = Path(__file__).resolve().parents[3] / "vectors" / "ontology"


def test_exactly_eight_canonical_ids() -> None:
    r = basic8_registry()
    ids = {a.id for a in r.anchors}
    assert ids == {f"esp:emo:{label}:v1" for label in BASIC8_ORDER}
    assert len(ids) == 8
    assert all(a.type is TaossType.EMO for a in r.anchors)


def test_v13_order_is_stable() -> None:
    s = basic8_registry().anchor_set(BASIC8_ID)
    assert s.anchors == tuple(f"esp:emo:{label}:v1" for label in BASIC8_ORDER)
    assert BASIC8_ORDER == (
        "joy",
        "trust",
        "fear",
        "surprise",
        "sadness",
        "anger",
        "disgust",
        "anticipation",
    )


def test_registry_digest_fixed_by_golden_vector() -> None:
    golden = (GOLDEN / f"{BASIC8_ID}.registry.blake2b256").read_text().strip()
    assert basic8_registry().digest_hex() == golden


def test_anchor_set_uuid_is_deterministic() -> None:
    s = basic8_registry().anchor_set(BASIC8_ID)
    assert str(s.uuid) == "8c41c8d9-63e0-5005-a469-aa00dfb4828b"
