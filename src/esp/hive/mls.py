# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""MLS (RFC 9420) group layer for the Typed Hive (GAP-017, ADR-0021).

MLS is never re-implemented here. Each member is one ``esp-rs mls`` process built
on the audited ``openmls`` crate, ciphersuite
``MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`` (0x0001). Its signature and HPKE
keys and its group state never leave that process. :class:`HiveGroup` is only
the delivery service: it relays opaque key packages, commits and welcomes, and
it checks that all members agree on the result.

- **Epoch:** every commit (add, remove, self-update) starts a new MLS epoch.
  Hive contributions must carry the group's current epoch (``mls_epoch``).
- **Round secret:** ``MLS-Exporter("esp/v1/hive-round",
  episode_id ‖ u8 type ‖ u32 round, 32)``, bound to the epoch.
  :func:`~esp.hive.aggregation.secure_round` keys every pairwise Bonawitz seed
  with it.
- **Exit:** removing a member moves the group to a new epoch. The removed
  member's process refuses to export, so it cannot derive the next round
  secret.
- **Post-compromise security:** a self-update rotates the member's leaf keys
  and the epoch.

Still open (ADR-0021): anonymous credentials. Members use MLS basic
credentials, so group members see each other's names.
"""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import struct
import subprocess
import uuid
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any, Final

from esp.hive.tlv import HiveError

ROUND_LABEL: Final = "esp/v1/hive-round"
SECRET_LEN: Final = 32
_CRATE: Final = Path(__file__).resolve().parents[3] / "rust" / "esp-rs"


class MlsError(HiveError):
    pass


def default_binary() -> Path:
    """``ESP_RS_BIN``, else ``$CARGO_TARGET_DIR/release/esp-rs``, else the crate's target."""
    if env := os.environ.get("ESP_RS_BIN"):
        return Path(env)
    target = Path(os.environ.get("CARGO_TARGET_DIR", _CRATE / "target"))
    return target / "release" / "esp-rs"


def round_context(episode_id: uuid.UUID, type_code: int, round_no: int) -> bytes:
    return episode_id.bytes + struct.pack(">BI", type_code, round_no)


class MlsMember:
    """One member process. Its keys and state exist only inside that process."""

    def __init__(self, name: str, binary: Path) -> None:
        if not name or "\n" in name:
            msg = "member name must be a non-empty single line"
            raise MlsError(msg)
        self.name = name
        self._proc = subprocess.Popen(  # noqa: S603 - fixed binary, no shell
            [str(binary), "mls", "--name", name],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def call(self, op: str, **fields: Any) -> dict[str, Any]:  # noqa: ANN401 - JSON
        if self._proc.stdin is None or self._proc.stdout is None or self._proc.poll() is not None:
            msg = f"member process {self.name} is not running"
            raise MlsError(msg)
        self._proc.stdin.write(json.dumps({"op": op, **fields}) + "\n")
        self._proc.stdin.flush()
        line = self._proc.stdout.readline()
        if not line:
            msg = f"member process {self.name} ended unexpectedly"
            raise MlsError(msg)
        reply: dict[str, Any] = json.loads(line)
        if not reply.get("ok"):
            msg = f"{self.name}: {op} refused: {reply.get('error')}"
            raise MlsError(msg)
        return reply

    def key_package(self) -> str:
        return str(self.call("key_package")["key_package"])

    def export(
        self, context: bytes, *, label: str = ROUND_LABEL, length: int = SECRET_LEN
    ) -> bytes:
        return bytes.fromhex(
            self.call("export", label=label, context=context.hex(), length=length)["secret"]
        )

    def state(self) -> dict[str, Any]:
        return self.call("state")

    def close(self) -> None:
        if self._proc.poll() is None:
            if self._proc.stdin is not None:
                self._proc.stdin.close()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:  # pragma: no cover - defensive
                self._proc.kill()
        for stream in (self._proc.stdout, self._proc.stderr):
            if stream is not None:
                stream.close()


class HiveGroup:
    """An MLS group of Hive members, with the delivery service in between."""

    def __init__(self, founder: str, *, binary: Path | None = None) -> None:
        self.binary = binary or default_binary()
        if not self.binary.exists():
            msg = f"esp-rs binary not found at {self.binary} (cargo build --release)"
            raise MlsError(msg)
        self.members: dict[str, MlsMember] = {}
        self.removed: dict[str, MlsMember] = {}
        m = self._spawn(founder)
        m.call("create")

    def _spawn(self, name: str) -> MlsMember:
        if name in self.members or name in self.removed:
            msg = f"member {name} exists already"
            raise MlsError(msg)
        m = MlsMember(name, self.binary)
        self.members[name] = m
        return m

    def _relay(self, commit: str, *, sender: str, extra: Iterable[MlsMember] = ()) -> None:
        for name, m in self.members.items():
            if name != sender:
                m.call("process", message=commit)
        for m in extra:  # a removed member learns that it is out
            with contextlib.suppress(MlsError):
                m.call("process", message=commit)

    def _committer(self, exclude: Sequence[str] = ()) -> str:
        for name in self.members:
            if name not in exclude:
                return name
        msg = "no member left to commit"
        raise MlsError(msg)

    def add(self, names: Sequence[str]) -> int:
        committer = self._committer()
        joiners = [self._spawn(n) for n in names]
        out = self.members[committer].call("add", key_packages=[j.key_package() for j in joiners])
        joiner_names = {j.name for j in joiners}
        for name, m in self.members.items():
            if name != committer and name not in joiner_names:
                m.call("process", message=out["commit"])
        for j in joiners:
            j.call("join", welcome=out["welcome"])
        return self.epoch()

    def remove(self, name: str) -> int:
        if name not in self.members:
            msg = f"unknown member {name}"
            raise MlsError(msg)
        committer = self._committer(exclude=(name,))
        out = self.members[committer].call("remove", members=[name])
        gone = self.members.pop(name)
        self.removed[name] = gone
        self._relay(out["commit"], sender=committer, extra=(gone,))
        return self.epoch()

    def update(self, name: str) -> int:
        out = self.members[name].call("update")
        self._relay(out["commit"], sender=name)
        return self.epoch()

    def epoch(self) -> int:
        """The group's epoch; refuses if members disagree (a broken delivery)."""
        epochs = {n: int(m.state()["epoch"]) for n, m in self.members.items()}
        if len(set(epochs.values())) != 1:
            msg = f"members disagree on the epoch: {epochs}"
            raise MlsError(msg)
        return next(iter(epochs.values()))

    def round_secret(self, episode_id: uuid.UUID, type_code: int, round_no: int) -> bytes:
        """The MLS exporter secret for one Hive round; every active member must agree."""
        ctx = round_context(episode_id, type_code, round_no)
        secrets = {m.export(ctx) for m in self.members.values()}
        if len(secrets) != 1:
            msg = "members derived different round secrets"
            raise MlsError(msg)
        return secrets.pop()

    def close(self) -> None:
        for m in [*self.members.values(), *self.removed.values()]:
            m.close()

    def __enter__(self) -> HiveGroup:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def cargo() -> str | None:
    found = shutil.which("cargo") or str(Path.home() / ".cargo" / "bin" / "cargo")
    return found if Path(found).exists() else None
