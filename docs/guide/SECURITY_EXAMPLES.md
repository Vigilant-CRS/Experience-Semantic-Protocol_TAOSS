<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Security examples

Security-relevant behaviour is tested by 121+ `security`-marked tests, a 1-million-iteration
fuzz run (M11), `pip-audit`, `cargo-deny` and the threat model `docs/THREAT_MODEL.md` (T1–T19).
The examples below show the properties directly.

## Any bit flip is detected

The header is authenticated as AEAD associated data, and the whole packet is signed.

```python
import json
from pathlib import Path
from esp.codec.errors import WireError
from esp.codec.header import HEADER_LEN, Header
from esp.crypto.envelope import open_packet
from esp.crypto.keys import DirectionKeys
from esp.crypto.primitives import CryptoError

v = json.loads(Path("vectors/crypto/packet_valid.json").read_text())["vectors"][0]
packet = bytes.fromhex(v["packet_hex"])
keys = DirectionKeys.from_split_key(bytes.fromhex(v["k_split"]))
sender = Header.decode(packet[:HEADER_LEN]).sender_id

refused = 0
for i in range(len(packet)):
    mutated = bytearray(packet)
    mutated[i] ^= 0x01
    try:
        open_packet(bytes(mutated), keys, expected_sender=sender, max_payload_len=1 << 16)
    except (WireError, CryptoError):
        refused += 1
assert refused == len(packet)  # every single-bit flip is refused
```

## Wrong key, wrong sender

```python
import os
try:
    open_packet(packet, DirectionKeys.from_split_key(os.urandom(32)),
                expected_sender=sender, max_payload_len=1 << 16)
    raise AssertionError("must fail")
except CryptoError:
    pass
try:
    open_packet(packet, keys, expected_sender=bytes(32), max_payload_len=1 << 16)
    raise AssertionError("must fail")
except CryptoError:
    pass
```

## Malformed input is refused before any cryptography

```python
from esp.codec.errors import WireError
cases = json.loads(Path("vectors/malformed/header_invalid.json").read_text())["vectors"]
for case in cases:
    try:
        Header.decode(bytes.fromhex(case["hex"]))
    except WireError:
        continue
    raise AssertionError(case["name"])
```

## What the threat model says remains open

- Colluding receivers, model inversion and metadata analysis (T17–T19) are *measured* (leakage
  audits, metadata-protection profile), not eliminated.
- The Gaussian DP sampler is float-based (errata E-11).
- `pq_mode` is `CLASSICAL_ONLY` in v1: no post-quantum claim.
- The manual threat-model review is a human task and is still pending.
