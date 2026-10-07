<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Result: typing plus erasure on dialogue data (DailyDialog)

- **Preregistration:** [prereg-dailydialog-erasure.md](prereg-dailydialog-erasure.md), public in
  commit `9eb1f7c` (2026-10-07 23:12 +0200).
- **Run:** a single confirmatory run on the blinded official test split (7,740 utterances,
  dialogue-level bootstrap with 10,000 resamples).
- **Raw output:** [`artifacts/research/dailydialog_erasure_study.json`](../../artifacts/research/dailydialog_erasure_study.json).

Leakage is the macro-AUROC of emotion predicted from the released parts while EMO is masked
(0.5 = chance). Utility is topic (CTX) and dialogue-act (INT) accuracy, non-inferiority margin
δ = 0.02. A hypothesis is supported only if leakage is lower (one-sided p < 0.05, Holm for the
secondaries) **and** both utilities are non-inferior.

| Test | Typing + LEACE | Comparator | p (leakage) | Utility non-inferior | Outcome |
|---|---:|---:|---:|---|---|
| **P1** vs LEACE on an untyped latent of the same size | **0.818** | 0.832 | 0.015 | yes | **supported** |
| S1 vs LEACE on the raw embedding | 0.818 | 0.841 | 0.009 | no (topic −0.036, act −0.033 at the 5 % quantile) | not supported |
| S2 vs learned adversarial filter | 0.818 | 0.890 | < 0.001 | yes | **supported** |
| S3 = P1 on dialogues unseen in training | 0.813 | 0.826 | 0.030 | yes | **supported** |
| S4 vs typing alone | 0.818 | 0.892 | < 0.001 | no (act −0.024) | not supported |

## What this means

- **Typing plus erasure is the best released representation we have tested at this size.** It
  leaks less emotion than erasure alone, and far less than typing alone or an adversarial filter,
  at the same topic and dialogue-act accuracy. The result also holds on unseen dialogues.
- **The effect is small and should be read with caution.** The leakage reduction against erasure
  alone is about 0.014 AUROC. On the validation data the sign was the other way (0.894 against
  0.884), and the preregistration expected P1 to fail. One confirmatory success with a small
  effect calls for replication.
- **Erasure has a utility cost.** Against the raw embedding with erasure, and against typing
  alone, the leakage is lower but the dialogue-act or topic accuracy falls beyond the margin.
- **Every method still leaks emotion strongly** (AUROC about 0.82 against 0.5). Masking plus
  erasure removes the linear signal; nonlinear leakage remains, and the audit stays mandatory.
- **Claims level:** this supports the design decision of ADR-0035 (masked-type erasure). It does
  not establish H2 as V13 states it across all baselines and datasets, so claims level 5 is not
  reached.
