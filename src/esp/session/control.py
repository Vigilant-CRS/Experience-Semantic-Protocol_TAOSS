# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Session-control TLVs of the addendum profile ``esp-addendum-v1`` (ADR-0011)."""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from enum import IntEnum, unique
from typing import Final

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv
from esp.core.errors import ErrorCode

SESSION_CLOSE_CODE: Final = 0x81
ERROR_CODE: Final = 0x82
REGISTRY_DIGEST_CODE: Final = 0x83
MAX_DETAIL: Final = 1024
_NAME_RE: Final = re.compile(r"^[a-z0-9][a-z0-9.\-]*[a-z0-9]$")


@unique
class CloseReason(IntEnum):
    NORMAL = 0
    SEQUENCE_EXHAUSTED = 1
    STATE_LOST = 2
    REVOKED = 3
    POLICY_VIOLATION = 4
    KEY_COMPROMISED = 5


def _detail(detail: str) -> bytes:
    raw = detail.encode("utf-8")
    if len(raw) > MAX_DETAIL:
        msg = "detail too long"
        raise WireError(msg)
    return struct.pack(">H", len(raw)) + raw


def _read_detail(value: bytes, off: int) -> str:
    (n,) = struct.unpack_from(">H", value, off)
    raw = value[off + 2 : off + 2 + n]
    if len(raw) != n or off + 2 + n != len(value) or n > MAX_DETAIL:
        msg = "control detail length mismatch"
        raise WireError(msg)
    return raw.decode("utf-8")


@dataclass(frozen=True, slots=True)
class SessionClose:
    reason: CloseReason
    detail: str = ""

    def encode(self) -> Tlv:
        return Tlv(SESSION_CLOSE_CODE, bytes([self.reason]) + _detail(self.detail))

    @classmethod
    def decode(cls, tlv: Tlv) -> SessionClose:
        try:
            if tlv.code != SESSION_CLOSE_CODE:
                raise ValueError
            return cls(CloseReason(tlv.value[0]), _read_detail(tlv.value, 1))
        except (IndexError, ValueError, struct.error, UnicodeDecodeError):
            msg = "malformed SESSION_CLOSE"
            raise WireError(msg) from None


@dataclass(frozen=True, slots=True)
class ErrorNotice:
    code: ErrorCode
    detail: str = ""

    def encode(self) -> Tlv:
        return Tlv(ERROR_CODE, struct.pack(">H", self.code) + _detail(self.detail))

    @classmethod
    def decode(cls, tlv: Tlv) -> ErrorNotice:
        try:
            if tlv.code != ERROR_CODE:
                raise ValueError
            (code,) = struct.unpack_from(">H", tlv.value, 0)
            return cls(ErrorCode(code), _read_detail(tlv.value, 2))
        except (IndexError, ValueError, struct.error, UnicodeDecodeError):
            msg = "malformed ERROR"
            raise WireError(msg) from None


@dataclass(frozen=True, slots=True)
class RegistryDigest:
    name: str
    digest: bytes

    def encode(self) -> Tlv:
        raw = self.name.encode("ascii")
        if not _NAME_RE.fullmatch(self.name) or len(raw) > 128 or len(self.digest) != 32:
            msg = "invalid registry digest notice"
            raise WireError(msg)
        return Tlv(REGISTRY_DIGEST_CODE, bytes([len(raw)]) + raw + self.digest)

    @classmethod
    def decode(cls, tlv: Tlv) -> RegistryDigest:
        v = tlv.value
        try:
            n = v[0]
            name = v[1 : 1 + n].decode("ascii")
            digest = v[1 + n :]
        except (IndexError, UnicodeDecodeError):
            msg = "malformed REGISTRY_DIGEST"
            raise WireError(msg) from None
        if tlv.code != REGISTRY_DIGEST_CODE or len(digest) != 32 or not _NAME_RE.fullmatch(name):
            msg = "malformed REGISTRY_DIGEST"
            raise WireError(msg)
        return cls(name, digest)
