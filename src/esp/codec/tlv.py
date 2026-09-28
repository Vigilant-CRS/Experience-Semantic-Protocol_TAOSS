# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""TLV framing and typed-latent TLVs (V13 section 8.4). ``V13_NORMATIVE``.

Every TLV is ``uint8 t || uint32 length_be || value[length]``; ``length``
counts the bytes after the 5-byte common header.

Parsing rules (WP-015):

- truncated headers, lengths beyond the buffer and trailing bytes are errors;
- the number of TLVs per payload is bounded;
- codes that V13 v1 does not assign (and that no pinned profile allocates)
  are returned as *unknown* and never interpreted;
- typed latents (0x60-0x65) appear at most once each and in TAOSS order;
- singleton control TLVs appear at most once.
"""

from __future__ import annotations

import math
import struct
from dataclasses import dataclass
from enum import IntEnum, unique
from typing import Final

import numpy as np
from numpy.typing import NDArray

from esp.codec.errors import WireError
from esp.core.taoss_types import L1_DIMS, TaossType, type_from_tlv_code

TLV_HEADER_LEN: Final = 5
TYPED_SUBHEADER_LEN: Final = 8
MAX_TLVS_PER_PAYLOAD: Final = 1024

#: V13 v1 control/object code registry (V13 section 8.4).
V13_CONTROL_CODES: Final = {
    0x01: "TLV_INNER_SEGMENT",
    0x10: "TLV_CAPABILITIES_EXT",
    0x11: "TLV_TYPE_PROFILE",
    0x20: "TLV_IDENTITY_PROOF",
    0x21: "ReceiverCapability",
    0x22: "TLV_SENDER_CAPABILITY",
    0x23: "TLV_REVOCATION_INTENT",
    0x24: "TLV_DELETION_ATTESTATION",
    0x30: "TLV_DP_PARAMS",
    0x40: "TLV_VENDOR_PROVENANCE",
    0x41: "TLV_KEY_REVOKED",
    0x42: "TLV_ROTATION_BINDING",
    0x50: "TLV_ANCHOR_COORDS",
    0x51: "RECALL_FRAME",
    0x52: "TLV_TURN_TOKEN",
    0x70: "TLV_HIVE_GRANT",
    0x71: "TLV_HIVE_CONTRIBUTION",
    0x72: "TLV_HIVE_EXIT",
    0x73: "TLV_COLLECTIVE_INTENT",
}
TYPED_LATENT_CODES: Final = frozenset(range(0x60, 0x66))
V13_CODES: Final = frozenset(V13_CONTROL_CODES) | TYPED_LATENT_CODES

#: Addendum profile ``esp-addendum-v1`` range (ADR-0011); only used when pinned.
ADDENDUM_V1_CODES: Final = frozenset(range(0x80, 0xA0))

#: Codes that may appear at most once per payload (or inner segment).
SINGLETON_CODES: Final = frozenset({0x10, 0x11, 0x20, 0x21, 0x22, 0x30, 0x51, 0x52}) | (
    TYPED_LATENT_CODES
)


@dataclass(frozen=True, slots=True)
class Tlv:
    code: int
    value: bytes

    def encode(self) -> bytes:
        return encode_tlv(self.code, self.value)


@dataclass(frozen=True, slots=True)
class ParsedPayload:
    known: tuple[Tlv, ...]
    unknown: tuple[Tlv, ...]
    """TLVs with unassigned codes: kept for accounting only, never interpreted."""

    def get(self, code: int) -> Tlv | None:
        for t in self.known:
            if t.code == code:
                return t
        return None

    def all(self, code: int) -> tuple[Tlv, ...]:
        return tuple(t for t in self.known if t.code == code)


def encode_tlv(code: int, value: bytes) -> bytes:
    if not 0 <= code <= 0xFF:
        msg = f"TLV code out of range: {code}"
        raise WireError(msg)
    if len(value) > 2**32 - 1:
        msg = "TLV value too long"
        raise WireError(msg)
    return struct.pack(">BI", code, len(value)) + value


def iter_tlvs(data: bytes, *, max_count: int = MAX_TLVS_PER_PAYLOAD) -> list[Tlv]:
    """Split ``data`` into TLVs. Rejects truncation, overflow and trailing bytes."""
    out: list[Tlv] = []
    offset = 0
    end = len(data)
    while offset < end:
        if len(out) >= max_count:
            msg = f"more than {max_count} TLVs"
            raise WireError(msg)
        if end - offset < TLV_HEADER_LEN:
            msg = "truncated TLV header"
            raise WireError(msg)
        code, length = struct.unpack_from(">BI", data, offset)
        offset += TLV_HEADER_LEN
        if length > end - offset:
            msg = f"TLV 0x{code:02x} length {length} exceeds remaining {end - offset} bytes"
            raise WireError(msg)
        out.append(Tlv(code, bytes(data[offset : offset + length])))
        offset += length
    return out


def parse_payload(
    data: bytes,
    *,
    extra_codes: frozenset[int] = frozenset(),
    max_count: int = MAX_TLVS_PER_PAYLOAD,
) -> ParsedPayload:
    """Parse a decrypted payload (or one inner segment) with the v1 rules.

    ``extra_codes`` are codes allocated by pinned registry profiles
    (e.g. :data:`ADDENDUM_V1_CODES`); anything else unassigned is *unknown*.
    """
    allowed = V13_CODES | extra_codes
    known: list[Tlv] = []
    unknown: list[Tlv] = []
    seen: set[int] = set()
    last_latent = -1
    for tlv in iter_tlvs(data, max_count=max_count):
        if tlv.code not in allowed:
            unknown.append(tlv)
            continue
        if tlv.code in SINGLETON_CODES:
            if tlv.code in seen:
                msg = f"duplicate TLV 0x{tlv.code:02x}"
                raise WireError(msg)
            seen.add(tlv.code)
        if tlv.code in TYPED_LATENT_CODES:
            if tlv.code < last_latent:
                msg = "typed latents must be in TAOSS order"
                raise WireError(msg)
            last_latent = tlv.code
        known.append(tlv)
    return ParsedPayload(tuple(known), tuple(unknown))


# --- typed latents --------------------------------------------------------------


@unique
class LatentEncoding(IntEnum):
    F32_BE = 0
    F16_BE = 1
    INT8_SYM = 2


_BYTES_PER_COORD: Final = {
    LatentEncoding.F32_BE: 4,
    LatentEncoding.F16_BE: 2,
    LatentEncoding.INT8_SYM: 1,
}


@dataclass(frozen=True, slots=True)
class TypedLatent:
    type: TaossType
    encoding: LatentEncoding
    values: NDArray[np.float64]
    """Decoded coordinates (``scale * q`` for INT8_SYM). Read-only."""
    scale: float


def quantize_int8_sym(values: NDArray[np.float64]) -> tuple[NDArray[np.int8], float]:
    """V13 reference quantizer: ``s = max(max|x| / 127, 2^-24)``, ``q = clip(round(x / s))``.

    ``s`` is rounded to binary32 first (it is transmitted as float32) and the
    quantization uses that transmitted value. Rounding is round-half-to-even
    (IEEE default); recorded for the V13.1 errata because V13 writes ``round``.
    """
    x = np.asarray(values, dtype=np.float64)
    if not np.all(np.isfinite(x)):
        msg = "cannot quantize non-finite values"
        raise WireError(msg)
    peak = float(np.max(np.abs(x))) if x.size else 0.0
    s = float(np.float32(max(peak / 127.0, 2.0**-24)))
    q = np.clip(np.rint(x / s), -127, 127).astype(np.int8)
    return q, s


def encode_typed_latent(
    t: TaossType,
    values: NDArray[np.float64],
    encoding: LatentEncoding = LatentEncoding.F32_BE,
) -> bytes:
    """Encode one typed-latent TLV. ``-0.0`` is canonicalized to ``+0.0``."""
    x = np.asarray(values, dtype=np.float64)
    if x.ndim != 1 or x.size > 0xFFFF:
        msg = "typed latent must be a 1-D vector with at most 65535 coordinates"
        raise WireError(msg)
    if not np.all(np.isfinite(x)):
        msg = "typed latent values must be finite"
        raise WireError(msg)
    if encoding is LatentEncoding.INT8_SYM:
        q, scale = quantize_int8_sym(x)
        data = q.tobytes()
    else:
        dtype = ">f2" if encoding is LatentEncoding.F16_BE else ">f4"
        with np.errstate(over="ignore"):
            f = x.astype(dtype)
        if not np.all(np.isfinite(f)):
            msg = f"value overflows {encoding.name}"
            raise WireError(msg)
        f[f == 0] = 0.0
        data, scale = f.tobytes(), 1.0
    body = struct.pack(">BBHf", encoding, 0, x.size, scale) + data
    return encode_tlv(t.tlv_code, body)


def _check_subheader(
    t: TaossType, value: bytes, expected_dims: int | None
) -> tuple[LatentEncoding, int, float]:
    if len(value) < TYPED_SUBHEADER_LEN:
        msg = "typed latent sub-header truncated"
        raise WireError(msg)
    raw_encoding, flags, dims, scale = struct.unpack_from(">BBHf", value, 0)
    try:
        encoding = LatentEncoding(raw_encoding)
    except ValueError:
        msg = f"unknown latent encoding {raw_encoding}"
        raise WireError(msg) from None
    if flags != 0:
        msg = "typed latent flags must be zero in v1"
        raise WireError(msg)
    want = L1_DIMS[t] if expected_dims is None else expected_dims
    if dims != want:
        msg = f"{t.name} latent has {dims} dims, expected {want}"
        raise WireError(msg)
    if len(value) != TYPED_SUBHEADER_LEN + dims * _BYTES_PER_COORD[encoding]:
        msg = f"typed latent body length mismatch for {encoding.name}"
        raise WireError(msg)
    return encoding, dims, scale


def _decode_values(encoding: LatentEncoding, data: bytes, scale: float) -> NDArray[np.float64]:
    if encoding is LatentEncoding.INT8_SYM:
        if not (math.isfinite(scale) and scale > 0.0):
            msg = "INT8_SYM scale must be finite and > 0"
            raise WireError(msg)
        q = np.frombuffer(data, dtype=np.int8)
        if np.any(q == -128):
            msg = "INT8_SYM byte -128 is invalid in v1"
            raise WireError(msg)
        return q.astype(np.float64) * scale
    if scale != 1.0:
        msg = "scale must be exactly 1.0 for float encodings"
        raise WireError(msg)
    dtype = ">f4" if encoding is LatentEncoding.F32_BE else ">f2"
    values = np.frombuffer(data, dtype=dtype).astype(np.float64)
    if not np.all(np.isfinite(values)):
        msg = "typed latent contains NaN or infinity"
        raise WireError(msg)
    return values


def decode_typed_latent(
    tlv: Tlv, *, expected_dims: int | None = None, quantized: bool | None = None
) -> TypedLatent:
    """Decode and validate a typed-latent TLV.

    ``expected_dims`` defaults to the TAOSS-6 L1 dimension of the type.
    ``quantized`` enforces the header QUANTIZED-bit promise when given.
    """
    try:
        t = type_from_tlv_code(tlv.code)
    except ValueError as exc:
        raise WireError(str(exc)) from None
    encoding, _, scale = _check_subheader(t, tlv.value, expected_dims)
    if quantized is not None and quantized != (encoding is LatentEncoding.INT8_SYM):
        msg = "QUANTIZED header bit disagrees with latent encoding"
        raise WireError(msg)
    values = _decode_values(encoding, tlv.value[TYPED_SUBHEADER_LEN:], scale)
    values.flags.writeable = False
    return TypedLatent(type=t, encoding=encoding, values=values, scale=scale)
