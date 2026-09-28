<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Threat model (V13 §9 T1–T12, §7 T13–T19) and implementation status

Every row names what this implementation does and where it is tested. The status
column uses one of four values:

- **mitigated**: implemented and tested.
- **partial**: some layers implemented.
- **out of scope**: V13 itself says the protocol cannot solve it.
- **later**: belongs to a later milestone.

The **manual threat-model review** before v1.0 (WP-044, M12) is **PENDING**. It needs
an independent reviewer and is not replaced by the automated checks.

| # | Threat | Mitigation here | Tests | Status |
|---|---|---|---|---|
| T1 | Replay attack | sliding window per timeline + deterministic AEAD nonces; byte-identical retransmission | `tests/unit/session/test_sequence_replay.py`, `tests/conformance` (replay vectors) | mitigated |
| T2 | Gradient inversion in collaborative training | no raw-gradient export anywhere; secure aggregation belongs to Typed Hive | — | later (M15) |
| T3 | Timing analysis | constant bitmap, padding, decoys at constant rate, `TIMING_OBF` (timing metadata only) | `tests/integration/test_metadata_protection.py` | mitigated |
| T4 | Anchor poisoning | registry digests pinned in the session descriptor, silent mutation refused, evolution rules | `tests/unit/ontology` | partial (multi-authority quorum: WP-077) |
| T5 | Model extraction | receiver rate limits, decode budgets | `tests/integration/test_receiver_threats.py` | partial |
| T6 | Side channels | constant-time primitives from `cryptography` / RustCrypto; NN inference is **not** constant-time (V13 open problem) | — | partial |
| T7 | Byzantine peers (Hive) | — | — | later (M15) |
| T8 | Membership inference | runtime DP (clip + Gaussian, RDP accountant, ledger); DP-SGD for training is not implemented | `tests/unit/privacy` | partial |
| T9 | Sender de-anonymization | per-session pseudonymous sender keys bound to the Noise transcript | `tests/unit/test_identity.py` | mitigated |
| T10 | Master-key compromise | rotation bindings, compromise fail-closed, transparency log with witnesses, Shamir custody, `notify_key_compromised` | `tests/unit/test_keys_revocation.py`, `tests/unit/test_custody.py` | mitigated |
| T11 | Adaptive adversary on TAOSS | leakage harness, audit suite, probe ladder, query-limited black-box probe, red-team sender | `tests/unit/audit`, `tests/failure_modes` | mitigated (empirical, no proof) |
| T12 | Coercion / lawful access | out of crypto scope (V13); revocation, deletion requests + attestations, regulatory guard, default deny | `tests/unit/test_keys_revocation.py`, `tests/unit/regulatory` | out of scope (partial support) |
| T13 | Malicious vector injection | NaN/Inf rejected by the codec, norm caps, valence pre-screen, quarantine before decoding | `tests/integration/test_receiver_threats.py`, `tests/failure_modes` | mitigated |
| T14 | Coerced consumption | local decoding, receiver consent (default deny) | `tests/integration/test_endpoint.py` | mitigated at protocol level |
| T15 | Decoder version drift | decoder archive + replay, explicit re-baseline | `tests/integration/test_receiver_threats.py` | mitigated |
| T16 | Decoder capacity exhaustion | token-bucket decode budget, session cost ceiling, throttle not crash | `tests/integration/test_receiver_threats.py` | mitigated |
| T17 | Linguistic atrophy | not technically mitigable (V13); text renderer for every frame | `tests/failure_modes` (documentation check) | out of scope |
| T18 | Forced experience embedding | mandatory trusted vendor-provenance chain (receiver option) | `tests/integration/test_receiver_threats.py` | mitigated |
| T19 | Latent inversion / over-recovery | anchor-only release and receivers, T19 inversion and attribute audits | `tests/unit/audit/test_mine_t19.py`, `tests/integration/test_receiver_threats.py` | mitigated (empirical) |

## Automated review

`uv run python scripts/security_review.py` runs:

1. a dependency audit (pip-audit via OSV; cargo-deny advisories);
2. a secret scan;
3. an unsafe-pattern scan (TLS verification off, `shell=True`, `pickle`, unsafe YAML,
   `eval`/`exec`, unrestricted `torch.load`, `0.0.0.0` binds, `assert` in `src/`),
   where every exception is listed with a justification;
4. parser fuzzing;
5. all `security`-marked protocol-invariant tests.
