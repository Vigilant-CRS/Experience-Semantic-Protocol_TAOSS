<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ESP V13 — errata proposals for V13.1 (WP-085)

The specification remains the top of the source hierarchy. These proposals become normative
only once V13.1 adopts them. Each entry records:

- the gap (numbered as in the master plan §52b);
- where it sits in V13;
- the problem;
- the proposed text;
- the decision record (ADR) and the tests that implement it.

**Status key:**

- **ACCEPTED**: ADR accepted in this project.
- **PROPOSED**: ADR awaits the maintainer.
- **FINDING**: discovered while implementing.

## Wire format and cryptography

**E-01 (GAP-002, ACCEPTED, ADR-0009): deterministic nonce derivation**

- *V13:* "HKDF-derived from timeline_id‖segment_seq". This names no KDF, salt, info or
  length, and the 16+4 input bytes do not fit a 12-byte nonce.
- *Proposed:*
  - `k_nonce = BLAKE2b-256(key=k_split, "esp/v1/nonce-key")`;
  - `nonce = BLAKE2b-64(key=k_nonce, "esp/v1/timeline-tag" ‖ timeline_id) ‖ segment_seq_be32`.
  - It is injective in `segment_seq`, and retransmissions are byte-identical.
- *Tests:* `vectors/crypto/packet_valid.json`; the Rust implementation reproduces it.

**E-02 (GAP-003, ACCEPTED, ADR-0010): `payload_len` semantics**

- *Proposed:* `payload_len` is the ciphertext length only, without the 16-byte tag or the
  64-byte signature.
- This matches the V13 rate arithmetic. Packet length = 180 + `payload_len`.

**E-03 (GAP-004, ACCEPTED, ADR-0011): addendum TLV profile**

- *Proposed:* the codes `0x80–0x9F` are allocated to the pinned registry profile
  `esp-addendum-v1`:
  - descriptor, close, error, registry digest, bindings;
  - SOS, dummy types and filler;
  - semantic objects with `affect_scope`.
- Receivers without the pin ignore these codes.

**E-04 (GAP-005, ACCEPTED, ADR-0012): session descriptor**

- The binary descriptor travels inside the Noise IK handshake payloads.
- It carries: profile, SF level, nonce mode, PQ mode, DP level, replay windows, declared
  rates, maximum payload, clock tolerance, pinned registries and per-type decoder policy.
- Negotiation never upgrades or downgrades silently.

**E-05 (GAP-006, GAP-025, GAP-026, ACCEPTED, ADR-0013): bindings and `noise_h`**

- Objects that must sign the final transcript (receiver capability, identity proof) travel in
  the first transport messages, not inside the handshake.
- `noise_h = BLAKE2b-256("esp/v1/noise-h" ‖ h)`, because the BLAKE2b Noise hash is 64 bytes
  and V13 reserves 32.
- *Tests:* identical `noise_h` in the Python and Rust implementations
  (`tests/interop/test_rust_python.py`).

**E-06 (GAP-007, ACCEPTED, ADR-0014): anchor coordinates 0x50**

- *Layout:* `type_code u8 ‖ anchor_set_id[16] ‖ similarity_kind u8 ‖ m u16 ‖ float32_be[m]`.
- `similarity_kind` values:
  - 0 = cosine;
  - 1 = normalized least-squares projection;
  - 2 = RBF.
- Coordinates appear in anchor-set order.

**E-07 (GAP-008, ACCEPTED, ADR-0015): canonical signed TLVs**

- Optional arrays are omitted, not zero-filled. `valence_bounds` is present exactly when EMO is
  accepted.
- Every signature covers `domain ‖ code ‖ length ‖ body`.

**E-08 (GAP-009, ACCEPTED, ADR-0016): sequence exhaustion**

- Senders must close the session before `2^32−1`, and receivers reject wrap-around.

**E-09 (GAP-011, ACCEPTED, ADR-0017): unassigned header bits**

- Capability bits 12–14 must be zero. Bits 0–11 are ignored on receive until the registry
  assigns them.

**E-10 (FINDING): INT8_SYM rounding**

- *V13 writes* `round(x/s)`.
- *Proposed:* round half to even (IEEE default), using the transmitted binary32 scale.
- *Tests:* byte-exact INT8 vectors in both implementations.

## Consent, privacy, sessions

**E-11 (GAP-012, ACCEPTED, ADR-0018): DP reference profiles**

- Tabulated values:
  - `L1_BALANCED_REF` (ε 0.5, σ ≈ 24.42);
  - `L1_PRIVATE_REF` (ε 0.1, σ ≈ 122.13);
  - C = 1, δ per release;
  - RDP accountant and α grid.
- *Finding:* the float Gaussian sampler is documented as a limitation. It is not a
  discrete-Gaussian DP guarantee.

**E-12 (GAP-013, ACCEPTED, ADR-0019): clock tolerance**

- `Δ_clock` defaults to 2 s for L1 and 250 ms for I2I.

**E-13 (GAP-027, ACCEPTED, ADR-0025): strict SF levels**

- SF levels are checked per packet.
- Custom type-set profiles (e.g. MEB-HANDOVER) carry `sf_level = 0` and are validated against
  their pinned set.

**E-14 (GAP-028, ACCEPTED, ADR-0026): SOS**

- SOS is addendum TLV `0x86` with body `0x01` on CONTROL. It has no EMO/KNO content.

**E-15 (GAP-029, ACCEPTED, ADR-0027): metadata protection profile**

- The profile is `esp-metadata-protection-v1`, with these parts:
  - a constant header bitmap with dummy latents;
  - dummy and mask bitmaps only inside the AEAD (`0x87`);
  - filler padding (`0x88`);
  - decoys;
  - `TIMING_OBF`, which obfuscates timing only and is not DP.
- One-sided configuration refuses the session.

**E-22 (GAP-019, ACCEPTED, ADR-0023): transparency log profile**

- The key-rotation and DP-ledger transparency log is a Merkle log with RFC 9162 structure
  (leaf and node hashing, inclusion and consistency proofs).
- Witnesses co-sign signed tree heads, and receivers require a witness quorum.
- Who operates the log and the witnesses is still open; the maintainer decides this in
  ADR-0023.

**E-23 (GAP-018, ACCEPTED, ADR-0022): XCF `GATED_CEK` gate protocol**

- `access_material = gate_id ‖ wrap_nonce ‖ AEAD(gate_secret, CEK)`.
- Release checks signature, tombstone, capability and types, then re-wraps the CEK with HPKE
  to a session-bound key.
- An optional guardian quorum holds Shamir shares of the gate secret.
- A tombstone is signed by the lineage master.
- Golden capsules: `vectors/xcf/capsules.json`.

**E-16 (FINDING, capability scope and in-flight packets)**

- A capability-scope revocation ignores `revoke_from_seq`.
- Frames already in flight on another stream are therefore rejected after the revocation
  arrives.
- *Proposed:* state this explicitly. Senders who want earlier frames delivered should wait for
  transport acknowledgement before revoking (the reference exposes `drain()`).

## Semantics and decoders

**E-17 (GAP-001, ACCEPTED, ADR-0008): `affect_scope`**

- Every affect object states its scope:
  - `content`;
  - `self_declared`;
  - `inferred_subject` (L2+ only);
  - `machine_relay`.
- The L1 EMO default is content-side.

**E-18 (GAP-030, FINDING): emotion episodes**

- Episodes carry their own required `affect_scope`. Without it, a frame could assert
  subject-side affect through an episode alone.

**E-19 (GAP-014, GAP-022, FINDING): decoder companion**

- Absence `⊥_t` is distinct from zero.
- A per-type policy (STRICT_REFUSE, GRACEFUL, PRIOR_IMPUTE) is declared in the session profile.
- Silent ⊥→0 is `ESP_DECODER_POLICY_FAILED` (0x0601); refusal is 0x0602; a budget throttle is
  0x0603.
- The error codes form the registry `esp-error-codes-v1`.

**E-20 (GAP-024, FINDING): PQ declaration**

- The descriptor field `pq_mode` exists. v1 permits only `CLASSICAL_ONLY` and never claims
  post-quantum protection.
- `esp.session.pq.assess()` is the only permitted statement about quantum resistance. A hybrid
  outer channel (TLS 1.3 `X25519MLKEM768`) is reported only when it was verifiably negotiated;
  the inner ESP session remains classical-only. A repository-wide claim lint enforces this.
- *Finding:* with aioquic 1.3.0 and Python 3.12 the hybrid group is neither offered nor
  observable, so a hybrid outer channel cannot currently be verified in the reference stack.

**E-24 (GAP-017, ACCEPTED, ADR-0021): Typed Hive reference profile**

- *Proposed:* the 0x70–0x73 layouts as in ADR-0021 (grant 153+9n, contribution 92+p, exit
  52+p, collective intent 169 bytes).
- Grant and CIC signatures use the ADR-0015 canonical form; the CIC carries a
  FROST(Ed25519, SHA-512) signature (RFC 9591) that verifies as plain Ed25519.
- Contribution commitment: `BLAKE2b-256("esp/v1/hive-contribution" ‖ episode_id ‖ x ‖ r)` with
  `x = type u8 ‖ round u32 ‖ float32_be[d]`; `member_ref_root` is an RFC 9162 Merkle root.
- EMO is released only as a DP histogram over anchor bins; EMO coupling is always 0.
- Key setup without a trusted dealer: Pedersen DKG with Schnorr proofs of knowledge (FROST
  KeyGen), domain `esp/v1/hive-frost-dkg`, challenge bound to participant id and episode.
- MLS binding (implemented): Hive members form an RFC 9420 group (ciphersuite 0x0001).
  - `mls_epoch` in HIVE_CONTRIBUTION is the current MLS epoch; stale or future epochs are
    refused.
  - The per-round secret is `MLS-Exporter("esp/v1/hive-round", episode_id ‖ u8 type ‖ u32
    round, 32)`. It keys every pairwise secure-aggregation seed, so a removed member cannot
    take part.
  - Without an MLS group, the reference mode (`mls_epoch` = round) stays valid.
- Anonymous credentials (implemented): `esp-hive-bbs-nym-v1` uses blind BBS signatures with
  per-verifier pseudonyms (BLS12-381-SHA-256) instead of Semaphore V4. Drafts:
  draft-irtf-cfrg-bbs-signatures-12, -bbs-blind-signatures-02 and
  -bbs-per-verifier-linkability-03.
  - The issuer blind-signs `class:<episode class>`.
  - The pseudonym context is `"esp/v1/hive-episode" ‖ episode_id`, and
    `member_ref = BLAKE2b-256("esp/v1/hive-bbs-nym" ‖ pseudonym)`.
  - Each member has one pseudonym per episode, so double joins are refused. Pseudonyms of
    different episodes cannot be linked.
- *Still open:* credential revocation and expiry.
- *Tests:* `vectors/hive/tlvs.json`, `tests/unit/hive/`.

**E-25 (FINDING, ADR-0028): machine and agent profiles**

- Custom type-set profiles can require `EMO_MASKED=1` and consent flags such as `NO_REPLAY`
  on every data packet. Both endpoints enforce this before decoding.
- Agent state travels as a signed opaque-latent descriptor (0x98) and agent events (0x99). It
  is never labelled TAOSS without a passed leakage audit.

**E-26 (GAP-016, ACCEPTED, ADR-0030): replay-pattern watermark**

- *V13:* "Replay segments include vendor-side watermark TLVs" names no TLV code, body or
  verification rule.
- *Proposed:* addendum TLV `0x89 REPLAY_WATERMARK` as the last TLV of every replay segment (a
  packet carrying `RECALL_FRAME` 0x51).
- Layout: `vendor_id[16] ‖ epoch u32 ‖ index u32 ‖ scheduled_offset_ns u64 ‖ tag[16]`, with
  `tag = BLAKE2b-128(vendor key, "esp/v1/replay-watermark" ‖ timeline_id ‖ epoch ‖ index ‖
  offset ‖ BLAKE2b-256(payload before the watermark))`.
- Replay timing follows a vendor-keyed schedule (period plus keyed jitter):
  - epochs count from 0 without gaps and start on a declared grid;
  - indices are contiguous;
  - the header timestamp equals the schedule;
  - arrival stays within a declared tolerance.
- Replay requires `ALLOW_REPLAY`. Receivers without a watermark policy refuse replay segments,
  and a watermark on a live segment is refused. Error code `REPLAY_WATERMARK_INVALID`
  (0x0401).
- *Tests:* `vectors/replay/watermark.json`, `tests/unit/xcf/test_watermark.py`,
  `tests/integration/test_replay_watermark.py`.

**E-27 (GAP-015, FINDING): hardening constraint values**

- *Proposed:* a pinned profile `esp-covert-hardening-v1` carries the per-coordinate TEM band,
  the per-type gating-sparsity bands and the randomized-quantization strength `σ_t` (in units
  of the INT8 step).
- *Forbidden TEM codebook patterns* on the transmitted INT8 codes:
  - an all-zero frame;
  - a repeating phase with period 2–4 held for at least 8 frames;
  - a constant non-zero code delta held for at least 8 frames.
  
  A constant TEM (a paused stream) stays allowed.
- Values are derived per encoder by a documented calibration on honest streams. The reference
  values (σ = 0.5 step) come from the synthetic reference encoder and are marked EXPERIMENTAL.
- *Tests:* `tests/unit/audit/test_hardening_profile.py`,
  `artifacts/research/hardening_calibration.json`.

**E-28 (FINDING, ADR-0034): neural companion profile**

- *V13* defines `f_decode` but no source-side contract.
- *Proposed:* one `NeuralAdapter` contract for live devices and recorded datasets, with these
  profiles:
  - `L3-LIVE`;
  - `L4-REPLAY`, which needs a declaration of dataset, version, license and consent;
  - `L4-LIVE`, refused in v1.
- The mapping profile `esp-neural-mapping-v1` never populates EMO or KNO from neural
  features. The type-set profile is `esp-typeset-neural-v1`: INT required, KNO not allowed,
  EMO always masked.
- *Tests:* `tests/milestone/test_m18.py` on FALCON H1 (DANDI 000954).

**E-29 (GAP-019, ACCEPTED, ADR-0023): transparency log witnesses**

- *Mechanism implemented (C2SP-compatible).* The log publishes each tree as a
  c2sp.org/tlog-checkpoint (origin, size, RFC 6962 root). It is signed as a
  c2sp.org/signed-note by the log key, whose name equals the origin.
- Independent witnesses add Ed25519 cosignature/v1 lines (c2sp.org/tlog-cosignature).
- Verifiers require a quorum of distinct known witnesses; the log key never counts.
- The ESP `esp/v1/tree-head` format stays valid for the same tree.
- Operator: the maintainer runs the reference log; at least 3 independent witnesses;
  quorum 2-of-3 for L1 and 3-of-5 for L2+ (ADR-0023).
- *Tests:* `tests/unit/test_c2sp.py` (signed-note and sumdb/note vectors byte-exact).

## Repository roles

**E-21 (GAP-020): repositories**

- V13 names the Emotional Movie Search Engine repository as "the official implementation
  repository".
- *Proposed:*
  - The Emotional Movie Search Engine is the first **L1 application**.
  - `Vigilant-CRS/Experience-Semantic-Protocol_TAOSS` is the **reference implementation**:
    wire format, consent, conformance suite and vectors (CC BY 4.0), independent Rust
    implementation.

## Still open (not yet proposed as errata)

- **GAP-023:** real ExperienceBench corpora.
