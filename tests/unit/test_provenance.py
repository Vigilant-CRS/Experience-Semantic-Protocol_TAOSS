# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-054 acceptance tests: vendor provenance chain."""

import numpy as np
import pytest

from esp.codec.errors import WireError
from esp.codec.tlv import Tlv, encode_tlv, encode_typed_latent, parse_payload
from esp.core.taoss_types import TaossType
from esp.crypto.primitives import CryptoError, SigningKey
from esp.crypto.provenance import ProvenanceRole, VendorProvenance, payload_hash, verify_chain

ENCODER = SigningKey.from_seed(b"\x81" * 32)
AGGREGATOR = SigningKey.from_seed(b"\x82" * 32)


def latents() -> bytes:
    rng = np.random.default_rng(3)
    return encode_typed_latent(TaossType.KNO, rng.normal(size=240)) + encode_typed_latent(
        TaossType.TEM, rng.normal(size=16)
    )


def with_chain(payload: bytes) -> bytes:
    h = payload_hash(parse_payload(payload))
    a = VendorProvenance(
        ProvenanceRole.ENCODER_VENDOR,
        "vigilant-verlag.de",
        "esp-encoder-0.1.0",
        ENCODER.public_bytes,
        1,
    ).sign(ENCODER, h)
    b = VendorProvenance(
        ProvenanceRole.EDITOR_AGGREGATOR,
        "aggregator.example",
        "agg-2.0.0",
        AGGREGATOR.public_bytes,
        2,
    ).sign(AGGREGATOR, h)
    return payload + a.encode() + b.encode()


def test_chain_verifies_and_does_not_sign_itself() -> None:
    parsed = parse_payload(with_chain(latents()))
    chain = verify_chain(parsed, trusted_vendors=[ENCODER.public_bytes, AGGREGATOR.public_bytes])
    assert [e.role for e in chain] == [
        ProvenanceRole.ENCODER_VENDOR,
        ProvenanceRole.EDITOR_AGGREGATOR,
    ]
    # adding unrelated non-latent TLVs does not change H_payload
    extended = parse_payload(with_chain(latents()) + encode_tlv(0x52, b"x" * 10))
    assert payload_hash(extended) == payload_hash(parsed)


def test_any_latent_byte_change_breaks_every_signature() -> None:
    payload = bytearray(with_chain(latents()))
    payload[20] ^= 0x01  # inside the KNO latent data
    with pytest.raises(CryptoError):
        verify_chain(parse_payload(bytes(payload)))


def test_untrusted_vendor_rejected_when_filtering() -> None:
    with pytest.raises(CryptoError, match="untrusted vendor"):
        verify_chain(parse_payload(with_chain(latents())), trusted_vendors=[ENCODER.public_bytes])


def test_malformed_provenance() -> None:
    h = payload_hash(parse_payload(latents()))
    tlv = VendorProvenance(ProvenanceRole.CONTENT_CREATOR, "c", "1", ENCODER.public_bytes, 0).sign(
        ENCODER, h
    )
    for bad in (tlv.value[:-1], b"\x07" + tlv.value[1:], tlv.value[:3]):
        with pytest.raises((WireError, CryptoError)):
            VendorProvenance.verify(Tlv(0x40, bad), h)
    with pytest.raises(WireError, match=r"1\.\.255"):
        VendorProvenance(ProvenanceRole.CONTENT_CREATOR, "", "1", ENCODER.public_bytes, 0).sign(
            ENCODER, h
        )
