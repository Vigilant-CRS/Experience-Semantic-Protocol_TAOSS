<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ADR-0022: XCF `GATED_CEK` gate protocol

- Status: PROPOSED (implemented; awaiting maintainer review)
- Resolves: GAP-018
- Work package: WP-068

## Context

V13 specifies `GATED_CEK` behaviour: a fixed per-capsule CEK, a gate secret that is never
embedded in the capsule, release only after a live capability and revocation check, and
destruction of the gate secret to block future first-time access. V13 does not specify the
`access_material` layout, the release protocol or the guardian quorum.

## Decision

### `access_material` layout

`gate_id[16] ‖ wrap_nonce[12] ‖ ChaCha20-Poly1305(gate_secret, CEK)[48]`, with
AAD = `"esp/xcf/v1/gate" ‖ gate_id ‖ key-envelope prefix`.

### Release

The gate checks, in order:

1. the capsule signature;
2. that no tombstone exists for the CID;
3. that the capability is neither expired nor revoked;
4. that the capability types cover the capsule types.

It then unwraps the CEK and re-wraps it to a session-bound recipient X25519 key with HPKE
(RFC 9180, X25519 / HKDF-SHA256 / ChaCha20-Poly1305), using
`info = "esp/xcf/v1/gate-release" ‖ CID`.

### Guardian quorum

The gate secret exists only as Shamir shares (threshold `k` of `n`, GF(2^521−1),
`esp.keys.custody`). Release needs at least `k` shares.

### Tombstones

A tombstone is Ed25519 over `"esp/xcf/v1/tombstone" ‖ CID`, signed by the capsule's
lineage master (the `pk_M` in `sender_binding`).

### Destruction

Destroying the gate secret (or every share) makes future first-time release impossible.

## Consequences

- Release is auditable. The reference gate records every released CID.
- CEKs and plaintext already released cannot be revoked (V13). `DIRECT_HPKE` never
  advertises cryptographic erasure.
- Long-lifetime profiles should move the re-wrap to a hybrid ML-KEM suite. `cryptography`
  already offers `MLKEM768_X25519` in HPKE, but it is not pinned before an ADR accepts it.
