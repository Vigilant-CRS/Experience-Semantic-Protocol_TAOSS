# ADR-0023 — Transparency log profile for rotations and DP ledger checkpoints

- Status: PROPOSED. The reference implementation exists; operating the log
  requires a maintainer decision.
- Resolves: GAP-019 (mechanism part)
- Work package: WP-053

## Proposal

- Merkle tree exactly as in RFC 9162 §2.1: SHA-256 with leaf prefix 0x00 and
  node prefix 0x01. Inclusion and consistency proofs use the RFC verification
  algorithms. The implementation reproduces the RFC 6962 reference roots.
- Signed tree head: `"esp/v1/tree-head" || tree_size u64 || timestamp_ns u64 || root`,
  signed with Ed25519 by the log key.
- Independent witnesses cosign the same message. Verifiers require a quorum
  of known witnesses, and the log key never counts as its own witness.
- Pre-registered successors are logged as
  `"esp/v1/pre-registered-successor" || old_pk || new_pk` before the rotation
  becomes effective.

## Open for the maintainer

Who operates the log, who the witnesses are, and the quorum size per profile.
