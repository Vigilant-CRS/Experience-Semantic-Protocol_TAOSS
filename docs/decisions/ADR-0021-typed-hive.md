<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ADR-0021: Typed Hive reference profile (MLS, FROST, secure aggregation)

- Status: PROPOSED (implemented as a research-track reference; awaiting maintainer review)
- Resolves: GAP-017 (partially; see "Not implemented")
- Work package: WP-070 · Milestone: M15

## Context

V13 fixes the four Typed-Hive TLVs (0x70–0x73), the lifecycle, the normative INT, EMO and
exit rules, and the Friedkin–Johnsen bounded-influence model. It delegates four things to
"registry-pinned companion profiles":

- the secure-aggregation transport;
- the group transport (MLS);
- the anonymous-credential / nullifier suite (Semaphore V4 named as reference);
- DKG for the FROST group key.

The master plan's decision log reserves ADR-0021 for these reference choices.

## Decision

### Wire layouts

Big-endian integers, canonical binary32 floats, per-type arrays in LSB-first bit order of
`hive_types`. The value part follows `t u8 ‖ length u32`.

| TLV | Value layout | Length |
|---|---|---|
| `HIVE_GRANT` 0x70 | `capability_id[16] episode_id[16] hive_types u16 emergence_types u16 n_types u8 privacy_mode u8 membership_mode u8 lambda_max f32[n] epsilon_member f32[n] delta_member f32 op_id u8[n] min_group u16 quorum_min u16 rule_id u8 exit_policy u8 membership_root[32] valid_until_ns u64 sig[64]` | 153 + 9n |
| `HIVE_CONTRIBUTION` 0x71 | `episode_id[16] member_ref[32] mls_epoch u64 contribution_commitment[32] proof_len u32 proof` | 92 + proof_len |
| `HIVE_EXIT` 0x72 | `episode_id[16] member_ref[32] proof_len u32 proof` | 52 + proof_len |
| `COLLECTIVE_INTENT` 0x73 | `episode_id[16] capsule_cid[32] rule_id u8 epsilon_used f32 n_contributors u32 member_ref_root[32] group_key_id[16] frost_sig[64]` | 169 |

**Signatures** use the ADR-0015 canonical form `domain ‖ t ‖ length ‖ fields`:

- The grant is signed by `sk_M` under `esp/v1/hive-grant`.
- The CIC is FROST-signed under `esp/v1/collective-intent`. The signature verifies as a plain
  Ed25519 signature under the group key.
- `group_key_id = BLAKE2b-256("esp/v1/hive-group-key" ‖ PK)[:16]`.
- `member_ref_root` is the RFC 9162 Merkle root over the sorted accepted `member_ref`s.

**Parsing.** Parsers reject truncation, length overflow and trailing bytes. Proofs are bounded
by the profile maximum of 16 KiB.

### Registries (`esp-hive-operators-v1`, `esp-hive-rules-v1`)

**Operators:**

| ID | Operator | Types |
|---|---|---|
| 1 | covariance intersection | KNO, CTX |
| 2 | inverse variance (only with declared independence) | KNO, CTX |
| 3 | social choice | INT |
| 4 | EMO DP histogram | EMO only |
| 5 | provenance union | CTX |
| 6 | SEN composition | SEN |
| 7 | TEM phase order | TEM |

EMO has no centroid operator, and any other operator for EMO is rejected.

**Rules:**

- 1 = binary majority (ties keep the status quo; not DP, so `epsilon_used = 0`);
- 2 = exponential mechanism.

### Normative checks in the reference

**Grant narrowing.** The grant must:

- reference the base capability and be signed by the same master key;
- keep `hive_types ⊆ types_allowed`;
- not outlive the base capability;
- keep `Σ epsilon_member ≤ dp_epsilon_ceiling`. Linear composition across types is
  deliberately conservative.

A widening grant is rejected, never clipped.

**EMO mixing = 0** is enforced at three layers: the grant (wire), the episode configuration and
the dynamics. Machines never author EMO.

**Member consent is narrowing too.** The episode's per-type coupling, operator, epsilon, delta,
minimum group, quorum/rule and exit policy must all be within each member's grant. A member
participates only in the types both the grant and the episode declare, so KNO without EMO works.

**Contribution commitment.**

```
BLAKE2b-256("esp/v1/hive-contribution" ‖ episode_id ‖ canonical(x) ‖ r)
```

- `canonical(x) = type u8 ‖ round u32 ‖ float32_be[d]`;
- `r` is 32 fresh random bytes;
- `mls_epoch` carries the round number.

**CIC validity.** A CIC is valid only if all of these hold:

- the FROST signature verifies under the group key;
- `n_contributors ≥ quorum_min` and equals the voter set;
- `member_ref_root` matches the voter set;
- `capsule_cid` is the CID of the sealed decision capsule;
- the proposal's target is not a natural person.

A CIC is advisory. An exit during the ratification window invalidates the pending CIC.

**Audit.**

- whole-minus-sum Ψ with a Gaussian MI estimator (`gaussian-mi-v1`);
- a time-shuffle null and an episode bootstrap with a Bonferroni lower bound;
- held-out episodes only, bound to a preregistration digest fixed at Discovery;
- admissibility conditions (i)–(v) of V13, with flags `no-emergence`, `monoculture:*`,
  `autonomy-breach:*`, `captured:*`, `privacy:*` and `emo-mixing`.

Only a passing episode is sealed as `esp-hive-capsule-v1`. Otherwise the record is sealed as
`esp-collective-capsule-v1`, as XCF `DIRECT_HPKE` to an archive key.

### Companion profile choices (GAP-017)

| Concern | Reference choice | Status in this repository |
|---|---|---|
| Threshold signature for the CIC | FROST(Ed25519, SHA-512), RFC 9591 | **Implemented** in pure Python (`esp.hive.frost`), byte-exact against RFC 9591 Appendix E.1; signatures verify with the `cryptography` Ed25519 verifier. Not constant time. |
| FROST key setup | Pedersen DKG with Schnorr proofs of knowledge (Komlo–Goldberg, FROST KeyGen) in `esp.hive.dkg`; RFC 9591 Appendix C trusted dealer kept for the RFC test vectors | Implemented. Complaints name the misbehaving participant; the protocol aborts (no robust recovery). Round-2 private channels are the caller's responsibility. |
| Secure aggregation | Bonawitz-style pairwise masks (X25519 + BLAKE2b PRG, fixed point mod 2^64) with distributed Gaussian noise `N(0, σ²/h)`, honest-contributor threshold `h`, RDP accounting | **Implemented as a reference.** No dropout recovery: a missing member aborts the round. Float Gaussian, not the distributed discrete Gaussian of Kairouz et al. (same limitation as errata E-11). |
| Group transport | MLS (RFC 9420) via `openmls` 0.9 (MIT), ciphersuite 0x0001 | **Implemented** (see *MLS binding* below). |
| Anonymous credentials / nullifiers | Semaphore V4 (V13 reference) | **Implemented with BBS instead** (`esp-hive-bbs-nym-v1`, see below): blind BBS credentials with per-episode pseudonyms, via `zkryptium` (IRTF CFRG drafts). The transparent test suite `esp-hive-transparent-test-v0` remains for tests only and still reports "anonymity NOT PROVIDED". |

## MLS binding (GAP-017, implemented)

- **Library:** `openmls` 0.9.0 with `openmls_rust_crypto` 0.6 and
  `openmls_basic_credential` 0.6, all MIT-licensed. MLS is never re-implemented in this
  repository.
- **Ciphersuite:** `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (0x0001), the RFC 9420
  mandatory-to-implement suite.
- **Process model:** one `esp-rs mls --name <id>` process per member, speaking JSON lines on
  stdin/stdout. Its signature keys, HPKE keys and group state never leave that process.
  `esp.hive.mls.HiveGroup` is only the delivery service: it relays opaque key packages,
  commits and welcomes, and refuses if members disagree on the epoch or the round secret.
- **Operations:**
  - create, add (Welcome), remove (exit), self-update (post-compromise security);
  - every operation is a commit and starts a new epoch;
  - key packages, commits and welcomes are authenticated by MLS, and tampered ones are
    refused.
- **Epoch binding:** with an MLS group bound to an `Episode`, a `HIVE_CONTRIBUTION` must
  carry the group's *current* MLS epoch in `mls_epoch`. Stale and future epochs are refused.
  Without a group (reference mode), `mls_epoch` stays the round number, and the golden
  vectors are unchanged.
- **Round secret:** `MLS-Exporter("esp/v1/hive-round", episode_id ‖ u8 type ‖ u32 round,
  32)`. Every pairwise Bonawitz seed is BLAKE2b-*keyed* with it (person `esp-hive-mls`). So
  masking needs both the pairwise X25519 secret and current-epoch membership.
  - A removed member's process refuses to export, so it cannot take part in later rounds.
  - Members still cannot unmask each other, because the exporter secret alone is not enough.
- **Tests:** `rust/esp-rs/src/mls.rs` (6 unit tests) and `tests/interop/test_hive_mls.py`
  (6 member processes, exit, self-update, tampering, stale/future epochs, an episode over
  MLS). All mutants are killed; skipping key-package validation cannot even be expressed,
  because openmls requires `validate` to obtain a `KeyPackage`.
- MLS basic credentials show member names to the other members of the MLS group. The
  Hive's anonymity towards the episode verifier comes from the BBS suite below.
- **Supply chain:** `cargo deny check advisories` reports one finding, RUSTSEC-2026-0173:
  `proc-macro-error2` is unmaintained. It is a compile-time macro crate, reached via
  libcrux/hpke-rs in `openmls_rust_crypto`, and runs no code in the binary. No upgrade
  exists. It is the single, documented exception in `rust/esp-rs/deny.toml`, to be
  re-checked when hpke-rs updates libcrux.

## Anonymous credentials (GAP-017, implemented)

- **Library:** `zkryptium` 0.7.1 (Apache-2.0), features `bbsplus`, `bbsplus_blind` and
  `bbsplus_nym`. It is labelled experimental by its authors. No pairing or proof arithmetic
  is written here; `rust/esp-rs/src/credential.rs` only calls the library.
- **Drafts and ciphersuite:**
  - `draft-irtf-cfrg-bbs-signatures-12` (the current revision);
  - `draft-irtf-cfrg-bbs-blind-signatures-02` (the library's revision; the current one is -03);
  - `draft-irtf-cfrg-bbs-per-verifier-linkability-03` (current);
  - ciphersuite BLS12-381-SHA-256.
- **Issuance is blind.**
  1. The member commits to a random pseudonym secret.
  2. The issuer verifies the commitment proof and signs it, together with the public
     attribute `class:<episode class>` and the header `esp/v1/hive-credential`, adding its
     own entropy.
  3. The member verifies the signature and derives the final pseudonym secret.

  The issuer never learns that secret.
- **Joining and acting in an episode:**
  - The member proves possession of the credential and discloses only the class attribute.
  - The pseudonym is bound to `context_id = "esp/v1/hive-episode" ‖ episode_id`.
  - The presentation header is the object's authorization domain plus its signed fields, so
    one proof authorizes exactly one join, contribution or exit object.
  - Wire: `member_ref = BLAKE2b-256("esp/v1/hive-bbs-nym" ‖ pseudonym)` and
    `proof = pseudonym[48] ‖ bbs_proof`.
  - The membership root `BLAKE2b-256("esp/v1/hive-bbs-issuer" ‖ len ‖ issuer_pk ‖ class)`
    binds the trusted issuer and the class.
- **Properties:**
  - The pseudonym is deterministic per member and episode, so a second join with the same
    credential is refused as a duplicate.
  - Pseudonyms of different episodes are unlinkable.
  - Proofs are re-randomized on every presentation.
- **Tests:**
  - Rust (`credential.rs`):
    - draft vectors byte-exact: `signature001` (deterministic signing), and the nym secret
      and pseudonym of `nymProof001`;
    - the official `nymProof001` proof verifies, and tampering, another context or a false
      disclosed message fail;
    - full blind issuance with per-context pseudonyms;
    - a forged commitment is refused.
  - Python (`tests/interop/test_hive_anoncred.py`):
    - five members join anonymously and their contributions and exits are authorized;
    - a double join is refused, and pseudonyms differ across episodes;
    - tampered proofs are refused, as are proofs replayed onto another object or episode,
      swapped pseudonyms, a rogue issuer, the wrong class and a wrong membership root.
  - Mutation: 6 of 6 killed.
- **Limits:**
  - The library is experimental and not independently audited.
  - Blind issuance follows draft -02, not -03.
  - The issuer still learns *who* asks for a credential. Only the per-episode pseudonym is
    unlinkable, not the issuance event.
  - There is no credential revocation (an accumulator or status list would be needed).
  - Credentials carry no expiry attribute yet.

## Consequences

- All four TLVs have golden vectors (`vectors/hive/tlvs.json`), including invalid inputs that
  must be refused, and the conformance runner has a `hive` category.
- A synthetic episode with at least 5 members runs the full lifecycle (M15). This is **not**
  evidence about humans or collective cognition: H_Hive stays a horizon hypothesis.
- **Open for the maintainer:**
  - credential revocation and expiry for the BBS suite, and an audited BBS library;
  - robust DKG (recovery after complaints) and a pinned private-channel profile for DKG round 2;
  - the distributed discrete Gaussian;
  - a constant-time or audited FROST implementation (for example the Rust `frost-ed25519`
    crate) for production use.
