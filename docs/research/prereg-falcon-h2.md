<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Preregistration: decoding attempted handwriting across days (FALCON H2)

Status: **registered before unblinding.** The machine-readable record is
[`research/prereg/falcon-h2.json`](../../research/prereg/falcon-h2.json). Its digest is checked by
the analysis script, which refuses to read labels unless this record is on `origin/main`.
The registration date and commit are those of the first public commit that contains this file.

## 1. Question and claim level

Can a decoder trained only on earlier recording days turn intracortical activity into the
handwritten text a participant attempted, on **later, held-out days**?

A positive result would support claims-ladder level 4 (`docs/CLAIMS.md`): *empirical models
predict selected states on held-out real data*, here *attempted handwriting*, mapped to INT by
`esp-neural-mapping-v1`. It says nothing about H1–H3, emotion, or experience transfer.

## 2. Data

- FALCON Benchmark H2, DANDI 000950, version 0.241029.1403, CC BY 4.0. Participant T5 of the
  BrainGate2 trial.
- 192 channels of binned threshold crossings at 20 ms.
- Splits: `held-in-calib` (training, 21 sessions), `held-in-minival` (21 sessions, same days),
  `held-out-calib` (5 later days, 3 trials each).
- Every file is pinned by SHA-256 in `datasets/neural.json`; the analysis verifies all pins
  first.

**Blinding.**
- *What was used before registration:* file names, array shapes, trial counts and the
  dry run (`--dry-run`).
- *What was not:* no cue (label) and no decoding result on H2.
- *Where the method came from:* it was developed on FALCON H1 only (exploratory,
  `artifacts/research/falcon_h1_methods.json`).

## 3. Pipeline (fixed)

1. **Trials.** The `trials` intervals. Exclusions: trials shorter than 1.0 s, and trials with
   an empty cue.
2. **Features.** `sqrt` of the counts, then causal exponential smoothing with τ = 2 bins.
3. **Unsupervised day normalisation** (per-channel z-score, std floored at 0.05). It never
   uses labels:
   - held-in days use their calib session;
   - each held-out session uses its own complete, unlabelled recording. This is transductive
     and declared as such: the released held-out sessions have only 3 trials, so no separate
     calibration block exists.
4. **Decoder (primary).** GRU-CTC with these settings:
   - architecture: 2 layers, hidden 256, dropout 0.3, 2× temporal downsampling;
   - training: AdamW (lr 1e-3, weight decay 1e-4), batch 16, gradient clip 1.0;
   - augmentation: white noise sd 0.1 and a per-trial offset sd 0.05;
   - early stopping on the last 3 trials of each held-in calib session (patience 15, at most
     150 epochs);
   - ensemble of seeds 0, 1 and 2, averaged log-probabilities, greedy CTC decoding.
   
   The alphabet is the set of characters in the held-in calib cues.
5. **Comparators.**
   - The same GRU-CTC without day normalisation (`gru_raw`).
   - A linear-CTC read-out with day normalisation (`linear_daynorm`).
   - A time-shuffled neural input (control).
   - The within-session permutation null, the chance reference.
6. **Determinism.** `torch.use_deterministic_algorithms(True)` and fixed seeds. The device,
   GPU, CUDA and library versions are recorded in the result.

## 4. Hypotheses and tests

**Primary (P1).** Score the frozen GRU-CTC with day normalisation on all held-out-calib
trials, using corpus character error rate (CER = total Levenshtein distance / total target
characters). Its CER is lower than the permutation null.

- Null distribution: within each held-out session, predictions are permuted across that
  session's trials. 10 000 permutations, seed 0.
- p = (1 + #{null CER ≤ observed}) / (1 + 10 000).
- **Supported if p < 0.05 and the observed CER is below the mean null CER.**

**Secondary.** Holm-corrected as a family, α = 0.05.

| ID | Statement | Test |
|---|---|---|
| S1 | within day (held-in-minival), the same decoder beats its permutation null | permutation test as P1 |
| S2 | day normalisation lowers held-out CER versus `gru_raw` | one-sided Wilcoxon signed-rank on per-trial CER |
| S3 | GRU-CTC lowers held-out CER versus `linear_daynorm` | one-sided Wilcoxon signed-rank on per-trial CER |

The time-shuffled CER is reported as a control and not tested.

## 5. What would count against the claim

- If P1 fails, claims level 4 is **not** reached with this dataset, and that is reported.
- If P1 holds but the time-shuffled control is also near the observed CER, the result is
  reported as uninterpretable.
- No re-analysis with other settings will be presented as confirmatory. Any further analysis
  is labelled exploratory.

## 6. Known limitations, stated in advance

- 5 held-out days × 3 trials is a small test set. The permutation null has at most
  3!⁵ = 7776 distinct values, so p cannot fall below about 1.3 × 10⁻⁴.
- One participant and one task. Generalisation to other people or devices is not tested.
- The held-out normalisation is transductive (see §3).

## 7. Reproduction

```bash
uv run python scripts/run_falcon_h2_study.py --dry-run
uv run python scripts/run_falcon_h2_study.py --unblind --prereg-commit <public commit> \
    --out artifacts/research/falcon_h2_study.json
```
