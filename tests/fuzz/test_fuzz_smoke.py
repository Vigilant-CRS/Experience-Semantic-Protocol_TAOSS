# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-022 fuzz smoke: >= 100,000 generated malformed inputs.

Parsers must not crash, hang, allocate unbounded memory, or raise anything
other than the defined error types. Set ``ESP_FUZZ_ITERATIONS`` (e.g. 1000000)
for the nightly full run.
"""

import contextlib
import os
import random
import time
import tracemalloc
from collections.abc import Callable, Iterable

import pytest

from esp.codec.errors import WireError
from esp.codec.frame_wire import frame_to_payload, payload_to_frame
from esp.codec.header import Header
from esp.codec.structure import CapabilitiesExt, TypeProfile, parse_bundle
from esp.codec.tlv import ADDENDUM_V1_CODES, Tlv, decode_typed_latent, iter_tlvs, parse_payload
from esp.consent.capability import ReceiverCapability, SenderCapability
from esp.consent.revocation import RevocationIntent
from esp.crypto.identity import IdentityProof, verify_session_binding
from esp.crypto.primitives import CryptoError
from esp.keys.lineage import KeyRevoked, RotationBinding
from esp.session.control import ErrorNotice, RegistryDigest, SessionClose
from esp.session.descriptor import SessionDescriptor
from tests.unit.frame.test_frame_wire import OPTS, full_anchor_frame, header_for

pytestmark = pytest.mark.fuzz

ITERATIONS = int(os.environ.get("ESP_FUZZ_ITERATIONS", "100000"))
ALLOWED = (WireError, CryptoError)
MAX_PEAK_BYTES = 64 * 1024 * 1024
MAX_SECONDS_PER_10K = 30.0


def mutate(rng: random.Random, data: bytes) -> bytes:
    buf = bytearray(data)
    for _ in range(rng.randint(1, 6)):
        op = rng.randrange(6)
        if op == 0 and buf:  # bit flip
            i = rng.randrange(len(buf))
            buf[i] ^= 1 << rng.randrange(8)
        elif op == 1 and buf:  # byte set to an interesting value
            buf[rng.randrange(len(buf))] = rng.choice((0x00, 0x01, 0x7F, 0x80, 0xFF))
        elif op == 2 and buf:  # truncate
            del buf[rng.randrange(len(buf)) :]
        elif op == 3:  # insert random bytes
            i = rng.randrange(len(buf) + 1)
            buf[i:i] = rng.randbytes(rng.randint(1, 8))
        elif op == 4 and len(buf) >= 5:  # corrupt a length field with a huge value
            i = rng.randrange(len(buf) - 4)
            buf[i : i + 4] = rng.choice(
                (b"\xff\xff\xff\xff", b"\x7f\xff\xff\xff", b"\x00\x01\x00\x00")
            )
        else:  # duplicate a slice
            if buf:
                a = rng.randrange(len(buf))
                buf += buf[a : a + rng.randint(1, 32)]
    return bytes(buf)


VALID_HEADER = header_for(0x0F, 0).encode()
VALID_PAYLOAD = frame_to_payload(full_anchor_frame(), OPTS).payload
VALID_HEADER_FOR_PAYLOAD = header_for(frame_to_payload(full_anchor_frame(), OPTS).types_bitmap, 0)


def _decode_tlvs(data: bytes) -> None:
    parsed = parse_payload(data, extra_codes=ADDENDUM_V1_CODES)
    for t in parsed.known:
        if 0x60 <= t.code <= 0x65:
            decode_typed_latent(t)


CONTROL_DECODERS: list[Callable[[Tlv], object]] = [
    SenderCapability.verify,
    lambda t: ReceiverCapability.verify(t, noise_h=bytes(32)),
    RevocationIntent.verify,
    lambda t: IdentityProof.verify(t, pk_session=bytes(32), noise_h=bytes(32)),
    lambda t: verify_session_binding(t, noise_h=bytes(32)),
    KeyRevoked.decode,
    RotationBinding.decode,
    CapabilitiesExt.decode,
    lambda t: TypeProfile.decode(t, pinned={}),
    SessionClose.decode,
    ErrorNotice.decode,
    RegistryDigest.decode,
]


def run_target(target: Callable[[bytes], object], inputs: Iterable[bytes]) -> None:
    for data in inputs:
        with contextlib.suppress(*ALLOWED):
            target(data)


def test_fuzz_smoke() -> None:
    rng = random.Random(20260925)
    n = ITERATIONS
    plan: list[tuple[str, Callable[[bytes], object], Callable[[], bytes]]] = [
        ("header-random", Header.decode, lambda: rng.randbytes(100)),
        ("header-mutated", Header.decode, lambda: mutate(rng, VALID_HEADER)),
        ("tlv-random", _decode_tlvs, lambda: rng.randbytes(rng.randint(0, 64))),
        ("payload-mutated", _decode_tlvs, lambda: mutate(rng, VALID_PAYLOAD)),
        (
            "frame-mutated",
            lambda d: payload_to_frame(VALID_HEADER_FOR_PAYLOAD, d, OPTS),
            lambda: mutate(rng, VALID_PAYLOAD),
        ),
        (
            "bundle-mutated",
            parse_bundle,
            lambda: mutate(rng, b"\x01" + VALID_PAYLOAD[1:]),
        ),
        ("descriptor-random", SessionDescriptor.decode, lambda: rng.randbytes(rng.randint(0, 120))),
    ]
    shares = [0.2, 0.2, 0.15, 0.15, 0.1, 0.05, 0.05]
    control_share = 1.0 - sum(shares)
    tracemalloc.start()
    started = time.perf_counter()
    total = 0
    try:
        for (name, target, gen), share in zip(plan, shares, strict=True):
            count = int(n * share)
            run_target(target, (gen() for _ in range(count)))  # lazy: measure parsers, not inputs
            total += count
            assert name
        per_decoder = int(n * control_share) // len(CONTROL_DECODERS)
        for decoder in CONTROL_DECODERS:
            for _ in range(per_decoder):
                code = rng.choice(
                    (0x10, 0x11, 0x20, 0x21, 0x22, 0x23, 0x41, 0x42, 0x81, 0x82, 0x83, 0x85)
                )
                value = rng.randbytes(rng.randint(0, 260))
                with contextlib.suppress(*ALLOWED):
                    decoder(Tlv(code, value))
            total += per_decoder
        # the raw TLV iterator on adversarial length fields must stay bounded
        run_target(iter_tlvs, (b"\x22\xff\xff\xff\xff" + rng.randbytes(16) for _ in range(1000)))
        total += 1000
    finally:
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
    elapsed = time.perf_counter() - started
    assert total >= min(n, 100_000)
    assert peak < MAX_PEAK_BYTES, f"peak memory {peak / 1e6:.1f} MB"
    assert elapsed / (total / 10_000) < MAX_SECONDS_PER_10K, f"{elapsed:.1f}s for {total} inputs"
