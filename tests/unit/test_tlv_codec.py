# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-015 acceptance tests: TLV framing and typed latents."""

import contextlib
import json
import struct
from pathlib import Path
from typing import Any

import numpy as np
import pytest
from hypothesis import given
from hypothesis import strategies as st
from hypothesis.extra.numpy import arrays

from esp.codec.errors import WireError
from esp.codec.tlv import (
    ADDENDUM_V1_CODES,
    LatentEncoding,
    Tlv,
    decode_typed_latent,
    encode_tlv,
    encode_typed_latent,
    iter_tlvs,
    parse_payload,
    quantize_int8_sym,
)
from esp.core.taoss_types import L1_DIMS, TaossType

VECTORS = Path(__file__).resolve().parents[2] / "vectors"
LATENT_VALID = json.loads((VECTORS / "wire" / "latent_valid.json").read_text())["vectors"]
LATENT_INVALID = json.loads((VECTORS / "malformed" / "latent_invalid.json").read_text())["vectors"]


def latent(t: TaossType, enc: LatentEncoding = LatentEncoding.F32_BE, seed: int = 0) -> bytes:
    return encode_typed_latent(t, np.random.default_rng(seed).normal(size=L1_DIMS[t]), enc)


# --- framing -------------------------------------------------------------------


def test_endianness_of_common_header() -> None:
    assert encode_tlv(0x22, b"\xaa\xbb") == b"\x22\x00\x00\x00\x02\xaa\xbb"


def test_truncated_tlv_header_and_value() -> None:
    with pytest.raises(WireError, match="truncated TLV header"):
        iter_tlvs(b"\x22\x00\x00")
    with pytest.raises(WireError, match="exceeds remaining"):
        iter_tlvs(b"\x22\x00\x00\x00\x05abc")


def test_length_overflow() -> None:
    with pytest.raises(WireError, match="exceeds remaining"):
        iter_tlvs(b"\x22\xff\xff\xff\xff" + b"x" * 10)


def test_tlv_count_bounded() -> None:
    with pytest.raises(WireError, match="more than 3 TLVs"):
        iter_tlvs(encode_tlv(0x40, b"") * 4, max_count=3)


def test_unknown_tlvs_are_ignored_not_interpreted() -> None:
    payload = latent(TaossType.KNO) + encode_tlv(0x99, b"secret") + encode_tlv(0xFE, b"")
    parsed = parse_payload(payload)
    assert [t.code for t in parsed.known] == [0x60]
    assert [t.code for t in parsed.unknown] == [0x99, 0xFE]
    pinned = parse_payload(payload, extra_codes=ADDENDUM_V1_CODES)
    assert [t.code for t in pinned.known] == [0x60, 0x99]
    assert [t.code for t in pinned.unknown] == [0xFE]


def test_duplicate_forbidden_tlvs() -> None:
    with pytest.raises(WireError, match="duplicate TLV 0x62"):
        parse_payload(latent(TaossType.EMO) + latent(TaossType.EMO, seed=1))
    with pytest.raises(WireError, match="duplicate TLV 0x30"):
        parse_payload(encode_tlv(0x30, b"a") + encode_tlv(0x30, b"b"))
    chain = parse_payload(encode_tlv(0x40, b"a") + encode_tlv(0x40, b"b"))
    assert len(chain.all(0x40)) == 2  # vendor provenance chains may repeat


def test_latents_must_be_in_taoss_order() -> None:
    ok = parse_payload(latent(TaossType.KNO) + latent(TaossType.EMO) + latent(TaossType.TEM))
    assert [t.code for t in ok.known] == [0x60, 0x62, 0x65]
    with pytest.raises(WireError, match="TAOSS order"):
        parse_payload(latent(TaossType.EMO) + latent(TaossType.KNO))


# --- typed latents -----------------------------------------------------------


@pytest.mark.parametrize("vector", LATENT_VALID, ids=lambda v: v["name"])
def test_latent_golden_vectors(vector: dict[str, Any]) -> None:
    raw = bytes.fromhex(vector["hex"])
    tlv = iter_tlvs(raw)[0]
    decoded = decode_typed_latent(tlv)
    enc = LatentEncoding[vector["encoding"]]
    assert decoded.encoding is enc
    assert encode_typed_latent(TaossType.TEM, np.array(vector["input_values"]), enc) == raw
    tol = {LatentEncoding.F32_BE: 1e-7, LatentEncoding.F16_BE: 2e-3, LatentEncoding.INT8_SYM: 0.02}[
        enc
    ]
    assert np.allclose(decoded.values, vector["input_values"], atol=tol * 4)


@pytest.mark.parametrize("vector", LATENT_INVALID, ids=lambda v: v["name"])
def test_latent_invalid_vectors(vector: dict[str, Any]) -> None:
    with pytest.raises(WireError, match=vector["expect_error"]):
        decode_typed_latent(iter_tlvs(bytes.fromhex(vector["hex"]))[0])


@pytest.mark.parametrize(
    ("enc", "per"),
    [(LatentEncoding.F32_BE, 4), (LatentEncoding.F16_BE, 2), (LatentEncoding.INT8_SYM, 1)],
)
@pytest.mark.parametrize("t", list(TaossType))
def test_body_length_exact(t: TaossType, enc: LatentEncoding, per: int) -> None:
    raw = latent(t, enc)
    (length,) = struct.unpack(">I", raw[1:5])
    assert length == 8 + per * L1_DIMS[t]
    assert raw[0] == t.tlv_code


@given(arrays(np.float64, 64, elements=st.floats(width=32, allow_nan=False, allow_infinity=False)))
def test_f32_roundtrip_exact_for_binary32_values(x: np.ndarray) -> None:
    decoded = decode_typed_latent(iter_tlvs(encode_typed_latent(TaossType.EMO, x))[0])
    assert np.array_equal(decoded.values, x.astype(np.float32).astype(np.float64))


def test_float_canonicalization_negative_zero() -> None:
    raw = encode_typed_latent(TaossType.TEM, np.array([-0.0] * 16))
    assert raw[5 + 8 :] == bytes(64)  # all +0.0
    raw16 = encode_typed_latent(TaossType.TEM, np.array([-0.0] * 16), LatentEncoding.F16_BE)
    assert raw16[5 + 8 :] == bytes(32)


def test_encoder_rejects_non_finite_and_overflow() -> None:
    with pytest.raises(WireError, match="finite"):
        encode_typed_latent(TaossType.TEM, np.array([np.nan] * 16))
    with pytest.raises(WireError, match="overflows F16_BE"):
        encode_typed_latent(TaossType.TEM, np.full(16, 1e6), LatentEncoding.F16_BE)
    with pytest.raises(WireError, match="overflows F32_BE"):
        encode_typed_latent(TaossType.TEM, np.full(16, 1e300))


def test_decoder_rejects_non_finite_f16() -> None:
    body = struct.pack(">BBHf", 1, 0, 16, 1.0) + bytes.fromhex("7c00") * 16  # +inf
    with pytest.raises(WireError, match="NaN or infinity"):
        decode_typed_latent(Tlv(0x65, body))


def test_quantizer_reference_and_bounds() -> None:
    x = np.array([0.0, 1.0, -1.0, 0.5, -0.5] + [0.0] * 11)
    q, s = quantize_int8_sym(x)
    assert s == float(np.float32(1.0 / 127.0))
    assert q.tolist()[:5] == [0, 127, -127, 64, -64]  # 63.5 rounds half-to-even -> 64
    q0, s0 = quantize_int8_sym(np.zeros(16))
    assert s0 == float(np.float32(2.0**-24))
    assert not np.any(q0)
    assert int(np.min(quantize_int8_sym(np.linspace(-9, 9, 64))[0])) >= -127


def test_quantized_bit_must_match_encoding() -> None:
    tlv_i8 = iter_tlvs(latent(TaossType.CTX, LatentEncoding.INT8_SYM))[0]
    tlv_f32 = iter_tlvs(latent(TaossType.CTX))[0]
    decode_typed_latent(tlv_i8, quantized=True)
    decode_typed_latent(tlv_f32, quantized=False)
    with pytest.raises(WireError, match="QUANTIZED"):
        decode_typed_latent(tlv_i8, quantized=False)
    with pytest.raises(WireError, match="QUANTIZED"):
        decode_typed_latent(tlv_f32, quantized=True)


def test_non_latent_code_is_not_reinterpreted_as_latent() -> None:
    with pytest.raises(WireError, match="not a TAOSS-6"):
        decode_typed_latent(Tlv(0x66, bytes(8)))


def test_decoded_values_read_only() -> None:
    d = decode_typed_latent(iter_tlvs(latent(TaossType.TEM))[0])
    with pytest.raises(ValueError, match="read-only"):
        d.values[0] = 1.0


@given(st.binary(max_size=300))
def test_parser_never_raises_anything_but_wire_error(data: bytes) -> None:
    try:
        parsed = parse_payload(data, extra_codes=ADDENDUM_V1_CODES)
    except WireError:
        return
    for tlv in parsed.known:
        if 0x60 <= tlv.code <= 0x65:
            with contextlib.suppress(WireError):
                decode_typed_latent(tlv)
