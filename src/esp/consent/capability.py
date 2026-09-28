# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sender capability (0x22) and receiver capability (0x21) codecs. ``V13_NORMATIVE``.

Signature input per ADR-0015: ``domain || TLV bytes up to the signature``.
"""

from __future__ import annotations

import math
import struct
import uuid
from dataclasses import dataclass
from enum import IntEnum, IntFlag, unique
from typing import Final

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv
from esp.core.taoss_types import TaossType, bitmap_to_types
from esp.crypto.primitives import CryptoError
from esp.crypto.signed import Signer, sign_tlv, verify_signed_tlv

SENDER_CAPABILITY_CODE: Final = 0x22
RECEIVER_CAPABILITY_CODE: Final = 0x21
_SENDER_BODY: Final = struct.Struct(">B16sHBQfQB32s32s16s")  # 121 bytes before sig
_SIG: Final = 64


class Rights(IntFlag):
    ALLOW_REPLAY = 1 << 0
    ALLOW_STORE = 1 << 1


RIGHTS_ASSIGNED_MASK: Final = 0x03


@unique
class AudienceMode(IntEnum):
    RECIPIENT_PUBKEY = 0
    AUDIENCE_SET_ROOT = 1


def _types(bitmap: int) -> tuple[TaossType, ...]:
    """``bitmap_to_types`` with wire-level errors (reserved bits are malformed input)."""
    try:
        return bitmap_to_types(bitmap)
    except ValueError as exc:
        raise WireError(str(exc)) from None


def _f32_exact(name: str, value: float) -> None:
    if not math.isfinite(value) or struct.unpack(">f", struct.pack(">f", value))[0] != value:
        msg = f"{name} must be a finite binary32 value"
        raise WireError(msg)


@dataclass(frozen=True, slots=True)
class SenderCapability:
    capability_id: uuid.UUID
    types_allowed: int
    rights: Rights
    max_segments: int
    dp_epsilon_ceiling: float
    valid_until_ns: int
    audience_mode: AudienceMode
    audience_value: bytes
    issuer_pk: bytes
    nonce: bytes
    version: int = 1

    def __post_init__(self) -> None:
        if self.version != 1:
            msg = "unsupported capability version"
            raise WireError(msg)
        _types(self.types_allowed)  # rejects reserved bits
        if int(self.rights) & ~RIGHTS_ASSIGNED_MASK:
            msg = "rights_flags bits 2-7 must be zero in v1"
            raise WireError(msg)
        if not 0 <= self.max_segments <= 2**64 - 1 or not 0 <= self.valid_until_ns <= 2**64 - 1:
            msg = "counter out of range"
            raise WireError(msg)
        _f32_exact("dp_epsilon_ceiling", self.dp_epsilon_ceiling)
        if self.dp_epsilon_ceiling < 0.0:
            msg = "dp_epsilon_ceiling must be non-negative"
            raise WireError(msg)
        for name, value, n in (
            ("audience_value", self.audience_value, 32),
            ("issuer_pk", self.issuer_pk, 32),
            ("nonce", self.nonce, 16),
        ):
            if len(value) != n:
                msg = f"{name} must be {n} bytes"
                raise WireError(msg)

    @property
    def types(self) -> tuple[TaossType, ...]:
        return _types(self.types_allowed)

    def body(self) -> bytes:
        return _SENDER_BODY.pack(
            self.version,
            self.capability_id.bytes,
            self.types_allowed,
            int(self.rights),
            self.max_segments,
            self.dp_epsilon_ceiling,
            self.valid_until_ns,
            int(self.audience_mode),
            self.audience_value,
            self.issuer_pk,
            self.nonce,
        )

    def sign(self, issuer: Signer) -> Tlv:
        return sign_tlv(SENDER_CAPABILITY_CODE, self.body(), issuer)

    @classmethod
    def verify(cls, tlv: Tlv) -> SenderCapability:
        """Parse and verify against the embedded ``issuer_pk``."""
        if tlv.code != SENDER_CAPABILITY_CODE or len(tlv.value) != _SENDER_BODY.size + _SIG:
            msg = "malformed sender capability"
            raise WireError(msg)
        fields = _SENDER_BODY.unpack(tlv.value[: _SENDER_BODY.size])
        (ver, cid, types, rights, max_seg, eps, until, mode, aud, issuer, nonce) = fields
        try:
            audience_mode = AudienceMode(mode)
        except ValueError:
            msg = "unknown audience_mode"
            raise WireError(msg) from None
        cap = cls(
            capability_id=uuid.UUID(bytes=cid),
            types_allowed=types,
            rights=Rights(rights),
            max_segments=max_seg,
            dp_epsilon_ceiling=eps,
            valid_until_ns=until,
            audience_mode=audience_mode,
            audience_value=aud,
            issuer_pk=issuer,
            nonce=nonce,
            version=ver,
        )
        verify_signed_tlv(tlv, issuer)
        return cap


@dataclass(frozen=True, slots=True)
class ReceiverCapability:
    accept_types: int
    max_norm: tuple[float, ...]
    """Per accepted type, in bitmap order (LSB first)."""
    valence_bounds: tuple[float, float] | None
    """Present iff EMO is accepted (ADR-0015)."""
    rate_limit_hz: int
    valid_from_ns: int
    valid_until_ns: int
    nonce: bytes
    pk_receiver: bytes
    noise_h: bytes
    version: int = 1

    def __post_init__(self) -> None:
        types = _types(self.accept_types)
        if self.version != 1:
            msg = "unsupported receiver capability version"
            raise WireError(msg)
        if len(self.max_norm) != len(types):
            msg = "max_norm must have one entry per accepted type"
            raise WireError(msg)
        for v in self.max_norm:
            _f32_exact("max_norm", v)
            if v <= 0.0:
                msg = "max_norm entries must be positive"
                raise WireError(msg)
        emo = TaossType.EMO in types
        if emo != (self.valence_bounds is not None):
            msg = "valence_bounds present iff EMO is accepted"
            raise WireError(msg)
        if self.valence_bounds is not None:
            lo, hi = self.valence_bounds
            _f32_exact("valence_bounds", lo)
            _f32_exact("valence_bounds", hi)
            if not -1.0 <= lo <= hi <= 1.0:
                msg = "valence_bounds must satisfy -1 <= lo <= hi <= 1"
                raise WireError(msg)
        if not 1 <= self.rate_limit_hz <= 0xFFFF:
            msg = "rate_limit_hz must be in [1, 65535]"
            raise WireError(msg)
        if self.valid_from_ns > self.valid_until_ns:
            msg = "empty validity interval"
            raise WireError(msg)
        for name, value in (("nonce", self.nonce), ("pk_receiver", self.pk_receiver)):
            if len(value) != (16 if name == "nonce" else 32):
                msg = f"{name} has wrong length"
                raise WireError(msg)
        if len(self.noise_h) != 32:
            msg = "noise_h must be 32 bytes"
            raise WireError(msg)

    @property
    def types(self) -> tuple[TaossType, ...]:
        return _types(self.accept_types)

    def norm_cap(self, t: TaossType) -> float:
        return self.max_norm[self.types.index(t)]

    def body(self) -> bytes:
        out = struct.pack(">BHB", self.version, self.accept_types, len(self.max_norm))
        out += b"".join(struct.pack(">f", v) for v in self.max_norm)
        if self.valence_bounds is not None:
            out += struct.pack(">ff", *self.valence_bounds)
        out += struct.pack(">HQQ", self.rate_limit_hz, self.valid_from_ns, self.valid_until_ns)
        return out + self.nonce + self.pk_receiver + self.noise_h

    def sign(self, receiver: Signer) -> Tlv:
        return sign_tlv(RECEIVER_CAPABILITY_CODE, self.body(), receiver)

    @classmethod
    def verify(cls, tlv: Tlv, *, noise_h: bytes) -> ReceiverCapability:
        """Parse, verify against ``pk_R`` and require binding to this session."""
        v = tlv.value
        if tlv.code != RECEIVER_CAPABILITY_CODE or len(v) < 4:
            msg = "malformed receiver capability"
            raise WireError(msg)
        version, accept, n_types = struct.unpack_from(">BHB", v, 0)
        types = _types(accept)
        if n_types != len(types):
            msg = "n_types must equal popcount(accept_types)"
            raise WireError(msg)
        emo = TaossType.EMO in types
        expected = 4 + 4 * n_types + (8 if emo else 0) + 2 + 8 + 8 + 16 + 32 + 32 + _SIG
        if len(v) != expected:
            msg = "receiver capability length mismatch"
            raise WireError(msg)
        off = 4
        norms = struct.unpack_from(f">{n_types}f", v, off)
        off += 4 * n_types
        bounds = None
        if emo:
            bounds = struct.unpack_from(">ff", v, off)
            off += 8
        rate, valid_from, valid_until = struct.unpack_from(">HQQ", v, off)
        off += 18
        nonce, pk_r, bound_h = v[off : off + 16], v[off + 16 : off + 48], v[off + 48 : off + 80]
        cap = cls(
            accept_types=accept,
            max_norm=tuple(norms),
            valence_bounds=bounds,
            rate_limit_hz=rate,
            valid_from_ns=valid_from,
            valid_until_ns=valid_until,
            nonce=nonce,
            pk_receiver=pk_r,
            noise_h=bound_h,
            version=version,
        )
        verify_signed_tlv(tlv, pk_r)
        if bound_h != noise_h:
            msg = "receiver capability bound to another session"
            raise CryptoError(msg)
        return cap


@dataclass(frozen=True, slots=True)
class ReceiverPolicy:
    """The effective receiver side of the Accept predicate.

    Either a verified :class:`ReceiverCapability` or the built-in default-deny
    policy (V13 section 7.6): only KNO + CTX at profile-pinned ceilings.
    """

    accept_types: frozenset[TaossType]
    norm_caps: dict[TaossType, float]
    valence_bounds: tuple[float, float] | None
    rate_limit_hz: int
    valid_from_ns: int
    valid_until_ns: int
    policy_id: str

    @classmethod
    def from_capability(cls, cap: ReceiverCapability) -> ReceiverPolicy:
        return cls(
            accept_types=frozenset(cap.types),
            norm_caps={t: cap.norm_cap(t) for t in cap.types},
            valence_bounds=cap.valence_bounds,
            rate_limit_hz=cap.rate_limit_hz,
            valid_from_ns=cap.valid_from_ns,
            valid_until_ns=cap.valid_until_ns,
            policy_id="signed",
        )

    @classmethod
    def default_deny(cls, *, norm_cap: float = 64.0, rate_limit_hz: int = 50) -> ReceiverPolicy:
        return cls(
            accept_types=frozenset({TaossType.KNO, TaossType.CTX}),
            norm_caps={TaossType.KNO: norm_cap, TaossType.CTX: norm_cap},
            valence_bounds=None,
            rate_limit_hz=rate_limit_hz,
            valid_from_ns=0,
            valid_until_ns=2**64 - 1,
            policy_id="esp-default-deny-v1",
        )
