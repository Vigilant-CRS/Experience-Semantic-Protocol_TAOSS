# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Metadata-leak mitigations (V13 section 8.3; WP-062; ADR-0027).

The cleartext ``types_bitmap``/``consent_flags``, packet sizes and timing
reveal *whether* EMO or SEN is flowing. The ``esp-metadata-protection-v1``
registry profile (pinned by both sides, digest = configuration) enables:

- **constant type bitmap**: every packet — data, control and decoy — carries
  the same header bitmap. Types that are absent or masked are filled with
  random dummy latents of the right size. Which types are dummies, and which
  are masked, travels only inside the AEAD payload (TLV ``0x87``:
  ``dummy_bitmap u16 · masked_bitmap u16``). ``EMO_MASKED`` is never set in
  the header;
- **size padding**: filler TLV ``0x88`` pads the payload to a multiple of
  ``pad_to`` bytes;
- **decoy traffic**: a packet whose types are all dummies and that carries
  no control TLV; the receiver discards it after authentication;
- **TIMING_OBF**: header timestamps rounded down to ``timing_bucket_ns`` and
  ``dt_ms = 0``. Timing-metadata obfuscation only — *not* differential privacy.

Receivers enforce the profile on every packet; a sender that stops protecting
(e.g. a packet with a different bitmap) is rejected, never silently accepted.
An onion/mixnet overlay is a transport wrapper around any ``Connection``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import struct
from dataclasses import dataclass
from typing import Final

import numpy as np

from esp.codec.errors import WireError
from esp.codec.header import ConsentFlags, Header, PrivacyFlags
from esp.codec.tlv import (
    TLV_HEADER_LEN,
    TYPED_LATENT_CODES,
    LatentEncoding,
    ParsedPayload,
    encode_tlv,
    encode_typed_latent,
    iter_tlvs,
)
from esp.core.taoss_types import L1_DIMS, TaossType, bitmap_to_types, types_to_bitmap

REGISTRY_NAME: Final = "esp-metadata-protection-v1"
DUMMY_TYPES_CODE: Final = 0x87
FILLER_CODE: Final = 0x88
_DUMMY: Final = struct.Struct(">HH")


@dataclass(frozen=True, slots=True)
class MetadataProtection:
    constant_types: frozenset[TaossType]
    pad_to: int = 0
    """Pad payloads to a multiple of this many bytes (0 = off)."""
    timing_bucket_ns: int = 0
    """Round header timestamps down to this bucket and set TIMING_OBF (0 = off)."""

    def __post_init__(self) -> None:
        if not self.constant_types:
            msg = "the constant type set must not be empty"
            raise ValueError(msg)
        if self.pad_to < 0 or self.timing_bucket_ns < 0:
            msg = "padding and timing buckets must be non-negative"
            raise ValueError(msg)

    @property
    def bitmap(self) -> int:
        return types_to_bitmap(self.constant_types)

    def digest(self) -> bytes:
        """Registry digest: both sides must pin the identical configuration."""
        config = {
            "constant_bitmap": self.bitmap,
            "pad_to": self.pad_to,
            "timing_bucket_ns": self.timing_bucket_ns,
        }
        raw = json.dumps(config, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.blake2b(REGISTRY_NAME.encode() + b"\x00" + raw, digest_size=32).digest()

    def registry_entry(self) -> tuple[str, bytes]:
        return REGISTRY_NAME, self.digest()

    # --- sender ----------------------------------------------------------------------

    def protect(
        self,
        *,
        types_bitmap: int,
        masked: frozenset[TaossType],
        payload: bytes,
        encoding: LatentEncoding,
        rng: np.random.Generator,
    ) -> bytes:
        """Wrap a real payload: add dummies, the dummy/mask TLV and filler."""
        real = frozenset(bitmap_to_types(types_bitmap))
        if not real <= self.constant_types:
            msg = f"types {sorted(t.name for t in real - self.constant_types)} not in constant set"
            raise WireError(msg)
        dummies = self.constant_types - real
        tlvs = iter_tlvs(payload)
        latents = [t.encode() for t in tlvs if t.code in TYPED_LATENT_CODES]
        rest = [t.encode() for t in tlvs if t.code not in TYPED_LATENT_CODES]
        for t in dummies:
            values = rng.normal(0.0, 1.0, size=L1_DIMS[t])
            latents.append(encode_typed_latent(t, values, encoding))
        latents.sort(key=lambda b: b[0])  # typed latents stay in TAOSS order
        marker = encode_tlv(
            DUMMY_TYPES_CODE, _DUMMY.pack(types_to_bitmap(dummies), types_to_bitmap(masked))
        )
        body = b"".join([*latents, *rest, marker])
        return body + filler(len(body), self.pad_to)

    def header_fields(self, now_ns: int, privacy_flags: int) -> tuple[int, int]:
        """(timestamp_ns, privacy_flags) for the cleartext header."""
        if not self.timing_bucket_ns:
            return now_ns, privacy_flags
        return now_ns - now_ns % self.timing_bucket_ns, privacy_flags | PrivacyFlags.TIMING_OBF

    # --- receiver --------------------------------------------------------------------

    def unwrap(self, header: Header, plaintext: bytes, parsed: ParsedPayload) -> Unwrapped:
        """Check the protected packet shape and strip dummies/filler.

        Returns the *real* header (real bitmap, EMO_MASKED from the encrypted
        mask) and the real payload, so the rest of the pipeline is unchanged.
        """
        if header.types_bitmap != self.bitmap:
            msg = "metadata protection: header bitmap differs from the constant bitmap"
            raise WireError(msg)
        if header.consent_flags & ConsentFlags.EMO_MASKED:
            msg = "metadata protection: EMO_MASKED must not appear in the header"
            raise WireError(msg)
        if self.pad_to and len(plaintext) % self.pad_to:
            msg = "metadata protection: payload not padded"
            raise WireError(msg)
        if self.timing_bucket_ns and not (
            header.privacy_flags & PrivacyFlags.TIMING_OBF
            and header.timestamp_ns % self.timing_bucket_ns == 0
            and header.dt_ms == 0
        ):
            msg = "metadata protection: timing not obfuscated"
            raise WireError(msg)
        markers = parsed.all(DUMMY_TYPES_CODE)
        if len(markers) != 1 or len(markers[0].value) != _DUMMY.size:
            msg = "metadata protection: exactly one dummy-types TLV required"
            raise WireError(msg)
        dummy_bits, masked_bits = _DUMMY.unpack(markers[0].value)
        try:
            dummies = frozenset(bitmap_to_types(dummy_bits))
            masked = frozenset(bitmap_to_types(masked_bits))
        except ValueError as exc:
            raise WireError(str(exc)) from None
        if not dummies <= self.constant_types:
            msg = "metadata protection: dummy type outside the constant set"
            raise WireError(msg)
        dummy_codes = {t.tlv_code for t in dummies}
        present_dummy = {t.code for t in parsed.known if t.code in dummy_codes}
        if present_dummy != dummy_codes:
            msg = "metadata protection: dummy latent missing"
            raise WireError(msg)
        kept = [
            t
            for t in parsed.known
            if t.code not in dummy_codes and t.code not in {DUMMY_TYPES_CODE, FILLER_CODE}
        ]
        real = self.constant_types - dummies
        flags = header.consent_flags
        if TaossType.EMO in masked:
            flags |= ConsentFlags.EMO_MASKED
        real_header = dataclasses.replace(
            header, types_bitmap=types_to_bitmap(real), consent_flags=int(flags)
        )
        return Unwrapped(real_header, b"".join(t.encode() for t in kept))


@dataclass(frozen=True, slots=True)
class Unwrapped:
    header: Header
    payload: bytes


def filler(payload_len: int, bucket: int) -> bytes:
    """Filler TLV so that ``payload_len + len(filler)`` is a multiple of ``bucket``."""
    if bucket <= 0:
        return b""
    missing = (-(payload_len + TLV_HEADER_LEN)) % bucket
    return encode_tlv(FILLER_CODE, bytes(missing))
