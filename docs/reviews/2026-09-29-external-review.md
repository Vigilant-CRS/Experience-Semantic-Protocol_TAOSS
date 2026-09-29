<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# External review 2026-09-29: findings and status

An independent review found 14 issues and provided 13 executable counterexamples. **All 13
reproduced** on `main` before the fix. Each one is now a regression test. Decisions:
[ADR-0033](../decisions/ADR-0033-review-hardening.md).

| # | Finding | Status | Regression test |
|---|---|---|---|
| F01 | XCF gate released a CEK for an unsigned, unrelated capability | fixed | `test_gate_checks_signature_owner_audience_and_recipient_key` (tampered, foreign issuer, wrong audience, unbound key, expired request, revoked) |
| F02 | Rotated key could issue fresh grants (`previously_accepted=True`) | fixed | `test_rotated_key_cannot_issue_a_fresh_grant` |
| F03 | Sender could mark un-noised latents as DP-protected | fixed | `test_sender_refuses_unprotected_dp_descriptor` |
| F04 | Two ledger instances overspent the DP ceiling together (ε 1.071 > 1.0) | fixed | `test_parallel_ledger_instances_cannot_overspend` |
| F05 | Several affect descriptors bypassed asymmetric valence bounds | fixed | `test_every_affect_descriptor_must_respect_asymmetric_bounds` |
| F06 | Receiver used the sender's payload limit; profile/SF of packets unchecked | fixed | `test_receiver_payload_limit_binds_sender_and_receiver`, `test_authenticated_packet_must_match_session_profile` |
| F07 | Un-negotiated addendum was interpreted | fixed | `test_unnegotiated_wire_extensions_abort_establishment` |
| F08 | Throttled DP packet could not be retransmitted | fixed | `test_throttled_dp_packet_can_be_retried_without_double_charge` |
| F09 | Receiver mis-audited variable DP costs | fixed | `test_variable_release_costs_use_cumulative_accounting` |
| F10 | Malformed control TLV raised into the receiver pump | fixed | `test_bad_controls_are_rejected_without_crashing_or_committing`, `test_controls_apply_atomically` |
| F11 | Send buffers grew for the whole session | fixed | `test_retransmit_cache_is_bounded_and_eviction_never_reuses_nonce` |
| F12 | Recall treated a missing ancestor as the chain end | fixed | `test_recall_fails_closed_on_missing_ancestor_or_policy` |
| F13 | Benchmark preprocessing saw test data | fixed | H2/drift fit on training units only |
| F14 | Rust peer did not enforce full consent | scoped and hardened | 8 Rust unit tests in `session.rs` (segments, expiry, profile, types, rights, norm, payload); live interop matrix green |
| — | Receiver consent state only in RAM (cross-session limit) | fixed | `tests/integration/test_consent_store.py` (sessions, restart, concurrency, monotonic counters, rollback) |

## Found afterwards by the M18 gate

- **Dependency audit covered only part of the dependencies.** `security_review.py` built the
  requirements for `pip-audit` from an output helper that keeps only the last 4000
  characters. Earlier "no known vulnerabilities" results therefore covered only the tail of
  the dependency list.
- **Fixed:** the export is now passed on in full, and an incomplete export is an error. The M11
  test asserts that every locked requirement is audited.
- **Result:** the full audit (105 packages) finds no known vulnerabilities.

## Still open from the review (documented, not bugs)

- **Guardian quorum.** The reference gate keeps all Shamir shares in one process. Separate
  guardian services are a deployment task.
- **Audience-set proofs.** The Merkle audience proof is supported by `evaluate()` and the
  gate. The endpoint data path does not yet carry a proof for `AUDIENCE_SET_ROOT` sessions.
- **Reference cryptography.** FROST/DKG are pure Python and not constant time. The DP
  sampler is float Gaussian (errata E-11).
- **Evidence.** The review's scientific assessment stands: no preregistered H1–H3 evidence
  yet. The reference encoder leaks masked emotion (R² ≈ 0.78).
