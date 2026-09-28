<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Failure modes (V13 §22) and their regressions (WP-080)

| V13 failure mode | Detection in this implementation | Regression test |
|---|---|---|
| Type collapse | leakage harness: pairwise probes with CIs flag every collapsed pair (`esp.training.leakage`) | `tests/failure_modes/test_failure_modes.py::test_type_collapse_is_detected` |
| Encoder drift across versions | anchor regression: encode a public anchor set with both versions, Procrustes-aligned per-type compatibility; decoder drift archive (`esp.decoder.drift`) | `::test_encoder_drift_is_detected` |
| Anchor cultural bias | OOD anchor-shift family: relative degradation > 10 % is flagged (`esp.bench.tasks.ood_anchor_shift`) | `::test_anchor_shift_beyond_ten_percent_is_flagged` |
| Audit-adversary asymmetry | probe ladder + query-limited black-box probe: the audit reports the strongest family, a weaker auditor's miss is not a pass (`esp.audit`) | `::test_weak_auditor_miss_is_closed_by_the_ladder` |
| EMO reconstruction from visible types (stego) | covert-channel V-information audit fails the red-team sender; randomized quantization removes sub-step payloads | `::test_emo_stego_sender_fails_the_audit` |
| Receiver manipulation via crafted vectors | quarantine: NaN/Inf rejected by the codec, norm caps, valence pre-screen, decode budget (T13/T16) | `::test_crafted_vectors_never_reach_the_decoder` |
| Linguistic atrophy at scale | **not technically mitigable** (V13): no protocol-level detection or recovery; design guidance only (language stays a first-class renderer, text rendering of every frame) | `::test_non_technical_failure_modes_are_documented` |
| Coercion at scale | **not technically mitigable** (V13): mandated use for surveillance cannot be detected by the protocol; mitigations are legal and political. The implementation keeps revocation, receiver consent, default deny, the Art. 5(1)(f) guard and audit logs so that coercion cannot hide behind the protocol | `::test_non_technical_failure_modes_are_documented` |
