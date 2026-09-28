# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Vendor provenance chain, TLV 0x40 (V13 section 7.5). ``V13_NORMATIVE``.

Layout::

    role u8 (0 encoder vendor, 1 content creator, 2 editor/aggregator)
    vendor_id_len u16 · vendor_id (UTF-8)
    software_version_len u16 · software_version (UTF-8)
    pk_vendor[32] · signed_at_ns u64 · sig[64]

``sig = Ed25519(sk_vendor, "esp/v1/vendor-provenance" || t || role || vendor_id
|| software_version || signed_at_ns || H_payload)`` with
``H_payload = BLAKE2b-256(L)``, where ``L`` is the TAOSS-ordered concatenation
of the complete typed-latent TLVs in the payload (headers included) and
nothing else, so provenance never signs itself or its siblings.

Encoding of the signed message follows V13 literally: variable fields are
concatenated as raw bytes without their length prefixes, ``t`` and ``role``
as one byte each, ``signed_at_ns`` big-endian.
"""

from __future__ import annotations

import struct
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum, unique
from typing import Final

from esp.codec.errors import WireError
from esp.codec.tlv import TYPED_LATENT_CODES, ParsedPayload, Tlv
from esp.crypto.primitives import CryptoError, blake2b, ed25519_verify
from esp.crypto.signed import Signer

VENDOR_PROVENANCE_CODE: Final = 0x40
DOMAIN: Final = b"esp/v1/vendor-provenance"
MAX_FIELD: Final = 255


@unique
class ProvenanceRole(IntEnum):
    ENCODER_VENDOR = 0
    CONTENT_CREATOR = 1
    EDITOR_AGGREGATOR = 2


def payload_hash(parsed: ParsedPayload) -> bytes:
    """``H_payload`` over the typed-latent TLVs only, in TAOSS order."""
    latents = sorted(
        (t for t in parsed.known if t.code in TYPED_LATENT_CODES), key=lambda t: t.code
    )
    return blake2b(b"".join(t.encode() for t in latents))


@dataclass(frozen=True, slots=True)
class VendorProvenance:
    role: ProvenanceRole
    vendor_id: str
    software_version: str
    pk_vendor: bytes
    signed_at_ns: int

    def _message(self, h_payload: bytes) -> bytes:
        return (
            DOMAIN
            + bytes([VENDOR_PROVENANCE_CODE, self.role])
            + self.vendor_id.encode("utf-8")
            + self.software_version.encode("utf-8")
            + struct.pack(">Q", self.signed_at_ns)
            + h_payload
        )

    def sign(self, signer: Signer, h_payload: bytes) -> Tlv:
        vid = self.vendor_id.encode("utf-8")
        ver = self.software_version.encode("utf-8")
        if not (0 < len(vid) <= MAX_FIELD and 0 < len(ver) <= MAX_FIELD):
            msg = "vendor_id and software_version must be 1..255 UTF-8 bytes"
            raise WireError(msg)
        body = (
            bytes([self.role])
            + struct.pack(">H", len(vid))
            + vid
            + struct.pack(">H", len(ver))
            + ver
            + self.pk_vendor
            + struct.pack(">Q", self.signed_at_ns)
        )
        return Tlv(VENDOR_PROVENANCE_CODE, body + signer.sign(self._message(h_payload)))

    @classmethod
    def verify(cls, tlv: Tlv, h_payload: bytes) -> VendorProvenance:
        v = tlv.value
        try:
            role = ProvenanceRole(v[0])
            (vid_len,) = struct.unpack_from(">H", v, 1)
            vid = v[3 : 3 + vid_len]
            (ver_len,) = struct.unpack_from(">H", v, 3 + vid_len)
            off = 5 + vid_len
            ver = v[off : off + ver_len]
            off += ver_len
            pk, (signed_at,), sig = (
                v[off : off + 32],
                struct.unpack_from(">Q", v, off + 32),
                v[off + 40 :],
            )
            prov = cls(role, vid.decode("utf-8"), ver.decode("utf-8"), pk, signed_at)
        except (IndexError, struct.error, UnicodeDecodeError, ValueError):
            msg = "malformed vendor provenance"
            raise WireError(msg) from None
        if (
            tlv.code != VENDOR_PROVENANCE_CODE
            or len(sig) != 64
            or len(pk) != 32
            or not 0 < vid_len <= MAX_FIELD
            or not 0 < ver_len <= MAX_FIELD
        ):
            msg = "malformed vendor provenance"
            raise WireError(msg)
        ed25519_verify(pk, prov._message(h_payload), sig)
        return prov


def verify_chain(
    parsed: ParsedPayload, *, trusted_vendors: Sequence[bytes] | None = None
) -> tuple[VendorProvenance, ...]:
    """Verify *every* provenance entry; optionally require all signers to be trusted."""
    h = payload_hash(parsed)
    chain = tuple(VendorProvenance.verify(t, h) for t in parsed.all(VENDOR_PROVENANCE_CODE))
    if trusted_vendors is not None:
        for entry in chain:
            if entry.pk_vendor not in trusted_vendors:
                msg = f"untrusted vendor key for {entry.vendor_id!r}"
                raise CryptoError(msg)
    return chain
