# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-077: registry snapshots, governance process, signed export over BULK."""

import asyncio
import json
from pathlib import Path

import pytest

from esp.crypto.primitives import SigningKey
from esp.registry_service import (
    REGULATED,
    GovernanceError,
    Role,
    Snapshot,
    State,
    builtin_entries,
    export_bundle,
    import_bundle,
)
from esp.transport.base import Channel
from esp.transport.memory import memory_link

ROOT = Path(__file__).resolve().parents[2]
MAINT, REVIEW, REG = (SigningKey.generate() for _ in range(3))
TRUST = {
    Role.MAINTAINER: frozenset({MAINT.public_bytes}),
    Role.REVIEWER: frozenset({REVIEW.public_bytes}),
    Role.REGULATOR: frozenset({REG.public_bytes}),
}


def frozen(name: str, entries: object) -> Snapshot:
    s = Snapshot(name, 1, entries)
    s.review(REVIEW)
    s.freeze(MAINT, REG if name in REGULATED else None)
    return s


def test_all_v1_registries_exist_and_digests_are_stable() -> None:
    entries = builtin_entries()
    assert set(entries) == {
        "esp-emo-v13-basic8-v1",
        "esp-taoss-profiles-v1",
        "esp-dp-profiles-v1",
        "esp-addendum-tlv-codes-v1",
        "esp-error-codes-v1",
        "esp-decoder-policies-v1",
        "esp-relation-classes-v1",
    }
    a = Snapshot("esp-error-codes-v1", 1, entries["esp-error-codes-v1"]).digest
    b = Snapshot("esp-error-codes-v1", 1, builtin_entries()["esp-error-codes-v1"]).digest
    assert a == b
    onto = Snapshot("esp-emo-v13-basic8-v1", 1, entries["esp-emo-v13-basic8-v1"]).digest.hex()
    pinned = (
        (ROOT / "vectors" / "ontology" / "esp-emo-v13-basic8-v1.registry.blake2b256")
        .read_text()
        .strip()
    )
    assert onto == pinned  # the snapshot digest is the digest sessions pin


def test_change_process_is_enforced() -> None:
    s = Snapshot("esp-relation-classes-v1", 1, ["a"])
    with pytest.raises(GovernanceError, match="reviewed"):
        s.freeze(MAINT)
    s.review(REVIEW)
    s.freeze(MAINT)
    assert s.state is State.FROZEN
    with pytest.raises(GovernanceError, match="frozen"):
        s.sign(Role.MAINTAINER, MAINT)
    nxt = s.successor(["a", "b"])
    assert (nxt.version, nxt.supersedes, nxt.state) == (2, s.digest.hex(), State.PROPOSED)
    dp = Snapshot("esp-dp-profiles-v1", 1, {})
    dp.review(REVIEW)
    with pytest.raises(GovernanceError, match="regulator"):
        dp.freeze(MAINT)


def test_bundle_travels_on_bulk_and_is_verified() -> None:
    snaps = [frozen(n, e) for n, e in builtin_entries().items()]
    raw = export_bundle(snaps)
    pins = {s.name: s.digest for s in snaps}

    async def transfer() -> bytes:
        a, b = memory_link()
        await a.send(Channel.BULK, raw)
        msg = await b.receive()
        assert msg.channel is Channel.BULK
        return msg.data

    got = import_bundle(asyncio.run(transfer()), TRUST, pins)
    assert set(got) == set(pins)


def test_tampering_untrusted_keys_and_pin_mismatch_are_refused() -> None:
    snaps = [frozen("esp-relation-classes-v1", ["a"])]
    raw = export_bundle(snaps)
    doc = json.loads(raw)
    doc["snapshots"][0]["entries"] = ["a", "evil"]
    with pytest.raises(GovernanceError, match="digest"):
        import_bundle(json.dumps(doc).encode(), TRUST, {})
    stranger = {**TRUST, Role.MAINTAINER: frozenset({SigningKey.generate().public_bytes})}
    with pytest.raises(GovernanceError, match="not trusted"):
        import_bundle(raw, stranger, {})
    with pytest.raises(GovernanceError, match="session pin"):
        import_bundle(raw, TRUST, {"esp-relation-classes-v1": b"\x00" * 32})
    with pytest.raises(GovernanceError, match="frozen"):
        export_bundle([Snapshot("x", 1, [])])
