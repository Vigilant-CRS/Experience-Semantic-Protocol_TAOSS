# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GAP-017: the Typed Hive over a real MLS (RFC 9420, openmls) group, one process per member."""

import os
import subprocess
from pathlib import Path

import numpy as np
import pytest

from esp.core.taoss_types import TaossType as T
from esp.hive.episode import contribution_commitment
from esp.hive.membership import identified_proof
from esp.hive.mls import HiveGroup, MlsError, cargo, round_context
from esp.hive.simulation import build_episode, contribute
from esp.hive.tlv import HiveContribution, HiveError

pytestmark = [pytest.mark.integration, pytest.mark.security]
ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "rust" / "esp-rs"
CARGO = cargo()

if CARGO is None:  # pragma: no cover
    pytest.skip("Rust toolchain not available", allow_module_level=True)

NAMES = [f"m{i}" for i in range(6)]


@pytest.fixture(scope="module")
def esp_rs() -> Path:
    assert CARGO is not None
    subprocess.run([CARGO, "build", "--release", "--quiet"], cwd=CRATE, check=True, timeout=1800)
    target = Path(os.environ.get("CARGO_TARGET_DIR", CRATE / "target"))
    return target / "release" / "esp-rs"


@pytest.fixture
def group(esp_rs: Path):  # type: ignore[no-untyped-def]
    g = HiveGroup(NAMES[0], binary=esp_rs)
    g.add(NAMES[1:])
    yield g
    g.close()


def _each(g: HiveGroup, ctx: bytes) -> dict[str, bytes]:
    return {n: m.export(ctx) for n, m in g.members.items()}


def test_six_members_derive_one_round_secret(group: HiveGroup) -> None:
    assert group.epoch() == 1
    ctx = round_context(__import__("uuid").UUID(int=7), 0, 1)
    secrets = _each(group, ctx)
    assert len(secrets) == 6
    assert len(set(secrets.values())) == 1
    other_round = group.members["m0"].export(round_context(__import__("uuid").UUID(int=7), 0, 2))
    assert other_round != next(iter(secrets.values()))


def test_exited_member_cannot_derive_the_next_epoch(group: HiveGroup) -> None:
    ctx = b"round-context"
    before = group.members["m5"].export(ctx)
    epoch = group.remove("m5")
    assert epoch == 2
    assert "m5" not in group.members
    gone = group.removed["m5"]
    with pytest.raises(MlsError, match="export"):
        gone.export(ctx)  # its group is inactive: no exporter for any later epoch
    after = set(_each(group, ctx).values())
    assert len(after) == 1
    assert before not in after
    assert gone.state()["active"] is False


def test_self_update_changes_epoch_and_secret(group: HiveGroup) -> None:
    ctx = b"r"
    before = group.members["m0"].export(ctx)
    assert group.update("m3") == 2
    after = set(_each(group, ctx).values())
    assert len(after) == 1
    assert before not in after


def test_tampered_commit_is_refused_by_every_receiver(group: HiveGroup) -> None:
    out = group.members["m1"].call("update")
    bad = bytearray(bytes.fromhex(out["commit"]))
    bad[-1] ^= 1
    for name in ("m0", "m2"):
        with pytest.raises(MlsError, match="refused"):
            group.members[name].call("process", message=bad.hex())


def test_tampered_welcome_is_refused(esp_rs: Path) -> None:
    with HiveGroup("a", binary=esp_rs) as g:
        joiner = g._spawn("b")
        out = g.members["a"].call("add", key_packages=[joiner.key_package()])
        w = bytearray(bytes.fromhex(out["welcome"]))
        w[-1] ^= 1
        with pytest.raises(MlsError, match="refused"):
            joiner.call("join", welcome=w.hex())


def _contribute_at(ep, m, t: T, x: np.ndarray, epoch: int) -> None:  # type: ignore[no-untyped-def]
    """Like simulation.contribute, but with an explicitly chosen mls_epoch."""
    opening = os.urandom(32)
    commitment = contribution_commitment(ep.config.episode_id, t, ep.round_no, x, opening)
    obj = HiveContribution(ep.config.episode_id, m.ref, epoch, commitment, b"")
    obj = HiveContribution(
        obj.episode_id, obj.member_ref, epoch, commitment, identified_proof(m.key, obj)
    )
    ep.contribute(t, obj.encode(), x, opening, adds_noise=True)


def test_episode_over_mls_binds_epochs_and_round_secrets(esp_rs: Path) -> None:
    rng = np.random.default_rng(0)
    ep, members, _pre, _shares = build_episode(6, machines=1, rounds=3)
    names = [f"member-{i}" for i in range(len(members))]
    with HiveGroup(names[0], binary=esp_rs) as g:
        g.add(names[1:])
        g.update(names[2])  # decouple the MLS epoch (2) from the round number (1)
        calls: list[tuple[object, int, int]] = []

        class Recording:
            def epoch(self) -> int:
                return g.epoch()

            def round_secret(self, episode_id, type_code: int, round_no: int) -> bytes:  # type: ignore[no-untyped-def]
                calls.append((episode_id, type_code, round_no))
                return g.round_secret(episode_id, type_code, round_no)

        ep.mls = Recording()
        ep.start_rounds()
        assert ep.round_no == 1
        assert ep.current_epoch == g.epoch() == 2
        for bad_epoch in (1, 3):  # stale and future MLS epochs are refused
            with pytest.raises(HiveError, match="MLS epoch"):
                _contribute_at(ep, members[0], T.KNO, rng.normal(size=4), bad_epoch)
        for m in members:
            contribute(ep, m, T.KNO, rng.normal(size=4))
        assert ep.release(T.KNO, rng) is not None
        assert calls == [(ep.config.episode_id, int(T.KNO), 1)]  # release is MLS-keyed
        # member 5 leaves the MLS group: new epoch, and the old one is now stale
        g.remove(names[5])
        ep.exited.add(members[5].ref)
        ep.next_round()
        assert ep.round_no == 2
        assert ep.current_epoch == 3
        with pytest.raises(HiveError, match="MLS epoch"):
            _contribute_at(ep, members[0], T.KNO, rng.normal(size=4), 2)
        for m in members[:5]:
            contribute(ep, m, T.KNO, rng.normal(size=4))
        assert ep.release(T.KNO, rng) is not None


def test_mls_round_secret_keys_the_masks(esp_rs: Path) -> None:
    """Same inputs and noise, different MLS round secret -> different masked vectors."""
    from esp.hive.aggregation import SecAggMember, to_fixed  # noqa: PLC0415

    with HiveGroup("a", binary=esp_rs) as g:
        s1 = g.round_secret(__import__("uuid").UUID(int=1), 0, 1)
        g.update("a")
        s2 = g.round_secret(__import__("uuid").UUID(int=1), 0, 1)
    assert s1 != s2
    a, b = SecAggMember(0), SecAggMember(1)
    peers = {0: a.public, 1: b.public}
    v = to_fixed(np.ones(4))
    plain = a.mask(v, peers, b"r")
    k1, k2 = a.mask(v, peers, b"r", s1), a.mask(v, peers, b"r", s2)
    assert not np.array_equal(plain, k1)
    assert not np.array_equal(k1, k2)
    # masks still cancel when both members use the same epoch secret
    total = (k1 + b.mask(v, peers, b"r", s1)) & np.uint64(2**64 - 1)
    np.testing.assert_array_equal(total, (v + v) & np.uint64(2**64 - 1))
    with pytest.raises(HiveError, match="32 bytes"):
        a.mask(v, peers, b"r", b"short")
