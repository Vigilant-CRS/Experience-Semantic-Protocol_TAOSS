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
| FROST key setup | RFC 9591 Appendix C trusted dealer | Implemented. **DKG is not implemented**; RFC 9591 does not specify one. |
| Secure aggregation | Bonawitz-style pairwise masks (X25519 + BLAKE2b PRG, fixed point mod 2^64) with distributed Gaussian noise `N(0, σ²/h)`, honest-contributor threshold `h`, RDP accounting | **Implemented as a reference.** No dropout recovery: a missing member aborts the round. Float Gaussian, not the distributed discrete Gaussian of Kairouz et al. (same limitation as errata E-11). |
| Group transport | MLS (RFC 9420), e.g. OpenMLS | **Not implemented.** `mls_epoch` carries the round number only. |
| Anonymous credentials / nullifiers | Semaphore V4 (V13 reference) | **Not implemented.** `CredentialSuite` is the plug-in interface. The shipped `esp-hive-transparent-test-v0` proves Merkle membership and one-per-episode uniqueness but reveals the credential key. It sets `provides_anonymity = False`, episodes refuse it in ANONYMOUS mode unless marked as a test, and reports then say "anonymity NOT PROVIDED". |

## Consequences

- All four TLVs have golden vectors (`vectors/hive/tlvs.json`), including invalid inputs that
  must be refused, and the conformance runner has a `hive` category.
- A synthetic episode with at least 5 members runs the full lifecycle (M15). This is **not**
  evidence about humans or collective cognition: H_Hive stays a horizon hypothesis.
- **Open for the maintainer:**
  - the MLS binding;
  - a Semaphore V4 (or equivalent) suite and issuer-unlinkable enrollment;
  - DKG;
  - the distributed discrete Gaussian;
  - a constant-time or audited FROST implementation (for example the Rust `frost-ed25519`
    crate) for production use.
