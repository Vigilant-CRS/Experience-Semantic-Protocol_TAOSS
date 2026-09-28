# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-040..042: independent Rust implementation and the interoperability matrix.

| sender \\ receiver | Python | Rust |
|--------------------|--------|------|
| Python             | suite (`tests/integration`) | live |
| Rust               | live   | live |

Each live cell covers packets and consent (signed capabilities, handshake with
the same transcript id), streams (CONTROL + STATE) and revocation (a sender
that keeps sending after withdrawing consent is rejected). Negative cells: an
untrusted capability issuer is refused on both sides. Bundles (persistent
capsules) belong to XCF, M14. The Rust codec also passes the shared vectors.
"""

import asyncio
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from esp.conformance.interop import (
    finish,
    peer_receiver,
    peer_to_python,
    python_sender,
    python_to_peer,
    sender_args,
)
from esp.crypto.primitives import CryptoError, SigningKey
from esp.frame.model import DisclosurePolicy
from esp.session.driver import establish_sender
from esp.transport.base import Channel
from esp.transport.tcp import connect_tcp

pytestmark = pytest.mark.integration
ROOT = Path(__file__).resolve().parents[2]
CRATE = ROOT / "rust" / "esp-rs"
CARGO = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo")
HOUR = 3600 * 10**9
KNO = DisclosurePolicy(allowed_types=("KNO",))  # type: ignore[arg-type]

if not Path(CARGO).exists():  # pragma: no cover
    pytest.skip("Rust toolchain not available", allow_module_level=True)


def now() -> int:
    return time.time_ns()


@pytest.fixture(scope="module")
def esp_rs() -> Path:
    subprocess.run([CARGO, "build", "--release", "--quiet"], cwd=CRATE, check=True, timeout=900)
    return CRATE / "target" / "release" / "esp-rs"


def test_rust_codec_passes_the_shared_vectors() -> None:
    out = subprocess.run(
        [CARGO, "test", "--release", "--quiet"],
        check=False,
        cwd=CRATE,
        capture_output=True,
        text=True,
        timeout=900,
    )
    assert out.returncode == 0, out.stdout + out.stderr


# --- Rust -> Python -----------------------------------------------------------------------------


def test_rust_sender_to_python_receiver(esp_rs: Path) -> None:
    receiver, pump, report = peer_to_python(esp_rs, frames=3)
    assert pump.metrics.accepted_frames == 3
    frames = [d.result.frame for d in pump.metrics.deliveries if d.result.frame]
    assert [[t.name for t in f.present_types] for f in frames] == [["KNO"]] * 3
    assert report["receiver_capability"] is True
    assert report["noise_h"] == receiver._noise.noise_h.hex()  # same transcript id (GAP-026)


def test_rust_revocation_is_enforced_by_python(esp_rs: Path) -> None:
    receiver, pump, report = peer_to_python(esp_rs, frames=4, revoke_after=2)
    assert report["revoked"] is True
    d = pump.metrics.deliveries
    assert [x.channel for x in d] == [Channel.STATE] * 2 + [Channel.CONTROL] + [Channel.STATE] * 2
    assert [x.result.accepted for x in d] == [True, True, True, False, False]
    assert all("13:capability or timeline revoked" in x.result.violations for x in d[3:])
    assert receiver.decoder_invocations == 2


def test_python_refuses_untrusted_rust_issuer(esp_rs: Path) -> None:
    with pytest.raises(CryptoError, match="not trusted"):
        peer_to_python(esp_rs, frames=1, trust=False)


# --- Python -> Rust -----------------------------------------------------------------------------


def test_python_sender_to_rust_receiver(esp_rs: Path, tmp_path: Path) -> None:
    rc, events, err = python_to_peer(esp_rs, tmp_path, revoke=False)
    assert rc == 0, err
    assert events[0]["event"] == "active"
    frames = [e for e in events if e["event"] == "frame"]
    assert [f["seq"] for f in frames] == [0, 1, 2, 3]
    assert all(f["types"] == 1 and f["norms"][0] > 0 for f in frames)


def test_python_revocation_is_enforced_by_rust(esp_rs: Path, tmp_path: Path) -> None:
    rc, events, err = python_to_peer(esp_rs, tmp_path, revoke=True)
    assert rc == 0, err
    kinds = [e["event"] for e in events]
    assert kinds == ["active", "frame", "frame", "revoked", "rejected", "rejected", "closed"]
    assert {e["reason"] for e in events if e["event"] == "rejected"} == {"revoked"}


def test_rust_refuses_untrusted_python_issuer(esp_rs: Path, tmp_path: Path) -> None:
    master = SigningKey.generate()
    proc, port, identity, r_static = peer_receiver(esp_rs, os.urandom(32))
    sender = python_sender(tmp_path, identity, r_static, master)

    async def scenario() -> None:
        conn = await connect_tcp("127.0.0.1", port)
        await establish_sender(sender, conn)
        await asyncio.sleep(0.3)
        await conn.close()

    asyncio.run(scenario())
    rc, events, err = finish(proc)
    assert rc != 0
    assert "sender capability not acceptable" in err
    assert not any(e["event"] == "active" for e in events)


# --- Rust -> Rust -------------------------------------------------------------------------------


@pytest.mark.parametrize("revoke", [False, True])
def test_rust_to_rust(esp_rs: Path, revoke: bool) -> None:
    master_seed = os.urandom(32)
    master = SigningKey.from_seed(master_seed)
    proc, port, identity, r_static = peer_receiver(esp_rs, master.public_bytes)
    sender = subprocess.run(
        [
            str(esp_rs),
            *sender_args(port, r_static, identity, master_seed, 4, 2 if revoke else None),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert sender.returncode == 0, sender.stderr
    rc, events, err = finish(proc)
    assert rc == 0, err
    kinds = [e["event"] for e in events]
    if revoke:
        assert kinds == ["active", "frame", "frame", "revoked", "rejected", "rejected", "closed"]
    else:
        assert kinds == ["active", "frame", "frame", "frame", "frame", "closed"]
