# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Session descriptor, negotiation and application transcript (ADR-0012, WP-048).

The descriptor is exchanged inside the Noise IK handshake payloads. Its
canonical binary form (all integers big-endian)::

    version u8 = 1 · profile u8 · sf_level u8 · nonce_mode u8 · pq_mode u8 · dp_level u8
    w_back u16 · w_fwd u16
    rate_sensor_mhz u32 · rate_latent_mhz u32 · rate_packet_mhz u32 · rate_privacy_mhz u32
    max_payload_len u32 · clock_tolerance_ms u32
    n_registries u8 · n * (name_len u8 · name · digest[32])   (sorted by name)
    decoder_policy u8[6]                                      (TAOSS order)

Negotiation never silently upgrades: profile, SF level, nonce mode, PQ mode
and DP level must be equal on both sides; registries pinned by both sides must
carry identical digests; only registries pinned by both are active.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum, unique
from typing import Final

from esp.codec.errors import WireError
from esp.core.errors import ErrorCode, EspError
from esp.core.taoss_types import TAOSS6_ORDER, TaossType
from esp.crypto.primitives import blake2b
from esp.session.replay import W_BACK_FLOOR, W_CAP, W_FWD_FLOOR

_FIXED: Final = struct.Struct(">BBBBBBHHIIIIII")
_NAME_RE: Final = re.compile(r"^[a-z0-9][a-z0-9.\-]*[a-z0-9]$")
DEFAULT_RECEIVER_POLICY_ID: Final = b"esp-default-deny-v1"


class NegotiationError(EspError):
    code = ErrorCode.SESSION_STATE


@unique
class NonceMode(IntEnum):
    DETERMINISTIC = 0
    RANDOM = 1


@unique
class PqMode(IntEnum):
    CLASSICAL_ONLY = 0
    HYBRID_OUTER = 1
    HYBRID_NOISE = 2


@unique
class DecoderPolicy(IntEnum):
    STRICT_REFUSE = 0
    GRACEFUL = 1
    PRIOR_IMPUTE = 2


@dataclass(frozen=True, slots=True)
class SessionDescriptor:
    profile: int = 0x01
    sf_level: int = 0
    nonce_mode: NonceMode = NonceMode.DETERMINISTIC
    pq_mode: PqMode = PqMode.CLASSICAL_ONLY
    dp_level: int = 0
    w_back: int = W_BACK_FLOOR
    w_fwd: int = W_FWD_FLOOR
    rate_sensor_mhz: int = 0
    rate_latent_mhz: int = 0
    rate_packet_mhz: int = 0
    rate_privacy_mhz: int = 0
    max_payload_len: int = 1 << 20
    clock_tolerance_ms: int = 2000
    registries: Mapping[str, bytes] = field(default_factory=dict)
    decoder_policy: Mapping[TaossType, DecoderPolicy] = field(
        default_factory=lambda: dict.fromkeys(TAOSS6_ORDER, DecoderPolicy.STRICT_REFUSE)
    )
    version: int = 1

    def __post_init__(self) -> None:
        _check(self.version == 1, "unsupported descriptor version")
        _check(0x01 <= self.profile <= 0xFF, "profile out of range")
        _check(0 <= self.sf_level <= 7, "sf_level out of range")
        _check(0 <= self.dp_level <= 3, "dp_level out of range")
        _check(
            self.pq_mode is PqMode.CLASSICAL_ONLY,
            "v1 supports only CLASSICAL_ONLY and never claims post-quantum protection",
        )
        _check(W_BACK_FLOOR <= self.w_back <= W_CAP, "w_back out of range")
        _check(W_FWD_FLOOR <= self.w_fwd <= W_CAP, "w_fwd out of range")
        for rate in (
            self.rate_sensor_mhz,
            self.rate_latent_mhz,
            self.rate_packet_mhz,
            self.rate_privacy_mhz,
        ):
            _check(0 <= rate <= 2**32 - 1, "rate out of range")
        _check(1 <= self.max_payload_len <= 2**32 - 1, "max_payload_len out of range")
        _check(0 <= self.clock_tolerance_ms <= 2**32 - 1, "clock_tolerance_ms out of range")
        _check(len(self.registries) <= 255, "too many registries")
        for name, digest in self.registries.items():
            _check(
                bool(_NAME_RE.fullmatch(name)) and len(name) <= 128, f"bad registry name {name!r}"
            )
            _check(len(digest) == 32, "registry digest must be 32 bytes")
        _check(set(self.decoder_policy) == set(TAOSS6_ORDER), "decoder policy for all six types")

    def encode(self) -> bytes:
        out = _FIXED.pack(
            self.version,
            self.profile,
            self.sf_level,
            self.nonce_mode,
            self.pq_mode,
            self.dp_level,
            self.w_back,
            self.w_fwd,
            self.rate_sensor_mhz,
            self.rate_latent_mhz,
            self.rate_packet_mhz,
            self.rate_privacy_mhz,
            self.max_payload_len,
            self.clock_tolerance_ms,
        )
        out += bytes([len(self.registries)])
        for name in sorted(self.registries):
            raw = name.encode("ascii")
            out += bytes([len(raw)]) + raw + self.registries[name]
        return out + bytes(self.decoder_policy[t] for t in TAOSS6_ORDER)

    def digest(self) -> bytes:
        return blake2b(b"esp/v1/descriptor" + self.encode())

    @classmethod
    def decode(cls, data: bytes) -> SessionDescriptor:
        try:
            fields = _FIXED.unpack_from(data, 0)
            off = _FIXED.size
            n = data[off]
            off += 1
            registries: dict[str, bytes] = {}
            names: list[str] = []
            for _ in range(n):
                length = data[off]
                name = data[off + 1 : off + 1 + length].decode("ascii")
                digest = data[off + 1 + length : off + 33 + length]
                if len(digest) != 32:
                    raise IndexError
                registries[name] = digest
                names.append(name)
                off += 33 + length
            policy_raw = data[off : off + 6]
            if len(policy_raw) != 6 or off + 6 != len(data):
                raise IndexError
            policy = {t: DecoderPolicy(b) for t, b in zip(TAOSS6_ORDER, policy_raw, strict=True)}
            desc = cls(
                version=fields[0],
                profile=fields[1],
                sf_level=fields[2],
                nonce_mode=NonceMode(fields[3]),
                pq_mode=PqMode(fields[4]),
                dp_level=fields[5],
                w_back=fields[6],
                w_fwd=fields[7],
                rate_sensor_mhz=fields[8],
                rate_latent_mhz=fields[9],
                rate_packet_mhz=fields[10],
                rate_privacy_mhz=fields[11],
                max_payload_len=fields[12],
                clock_tolerance_ms=fields[13],
                registries=registries,
                decoder_policy=policy,
            )
        except (IndexError, struct.error, UnicodeDecodeError, ValueError) as exc:
            msg = "malformed session descriptor"
            raise WireError(msg) from exc
        if names != sorted(set(names)):
            msg = "registries must be unique and sorted by name"
            raise WireError(msg)
        return desc


def _check(condition: bool, message: str) -> None:
    if not condition:
        raise WireError(message)


@dataclass(frozen=True, slots=True)
class NegotiatedSession:
    profile: int
    sf_level: int
    nonce_mode: NonceMode
    dp_level: int
    registries: Mapping[str, bytes]
    clock_tolerance_ms: int
    initiator: SessionDescriptor
    responder: SessionDescriptor

    @property
    def max_payload_len(self) -> int:
        return min(self.initiator.max_payload_len, self.responder.max_payload_len)


def negotiate(initiator: SessionDescriptor, responder: SessionDescriptor) -> NegotiatedSession:
    """Agree or abort. There is no silent upgrade or downgrade."""
    for name in ("profile", "sf_level", "nonce_mode", "pq_mode", "dp_level"):
        if getattr(initiator, name) != getattr(responder, name):
            msg = f"descriptor mismatch on {name}; re-handshake with an agreed profile"
            raise NegotiationError(msg)
    common = set(initiator.registries) & set(responder.registries)
    for name in sorted(common):
        if initiator.registries[name] != responder.registries[name]:
            msg = f"registry {name} pinned with different digests"
            raise NegotiationError(msg)
    return NegotiatedSession(
        profile=initiator.profile,
        sf_level=initiator.sf_level,
        nonce_mode=initiator.nonce_mode,
        dp_level=initiator.dp_level,
        registries={n: initiator.registries[n] for n in sorted(common)},
        clock_tolerance_ms=min(initiator.clock_tolerance_ms, responder.clock_tolerance_ms),
        initiator=initiator,
        responder=responder,
    )


def transcript_hash(
    *,
    noise_h: bytes,
    initiator: SessionDescriptor,
    responder: SessionDescriptor,
    sender_capability: bytes,
    receiver_capability: bytes | None,
) -> bytes:
    """Bind both descriptors and both consent objects to the Noise transcript (ADR-0012).

    ``receiver_capability`` is the canonical 0x21 TLV, or ``None`` for the
    built-in default-deny policy (bound by its identifier).
    """
    if len(noise_h) != 32:
        msg = "noise_h must be 32 bytes"
        raise WireError(msg)
    rc = receiver_capability if receiver_capability is not None else DEFAULT_RECEIVER_POLICY_ID
    return blake2b(
        b"esp/v1/transcript"
        + noise_h
        + initiator.digest()
        + responder.digest()
        + blake2b(sender_capability)
        + blake2b(rc)
    )
