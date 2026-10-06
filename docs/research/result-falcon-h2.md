<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Result: decoding attempted handwriting across days (FALCON H2)

- **Preregistration:** [prereg-falcon-h2.md](prereg-falcon-h2.md), public in commit
  `656b7ff` (2026-10-06 07:14 +0200). Digest `b6e9942b…f266`.
- **Run:** a single confirmatory run after publication. The script checked that the
  preregistration was on `origin/main` and unchanged, and checked all data pins.
- **Raw output:** [`artifacts/research/falcon_h2_study.json`](../../artifacts/research/falcon_h2_study.json).
- **Hardware:** RTX 3070 Laptop, CUDA 12.6, torch 2.14.0. Deterministic algorithms; runtime
  73 min.

## Primary hypothesis (P1): supported

On later, held-out days, a GRU-CTC decoder trained only on earlier days, with unsupervised
per-day normalization, turned attempted handwriting into text with a corpus **character error
rate of 0.53**. The within-session permutation null gave 0.73 (10 000 permutations,
**p = 0.0005**). The criterion "p < 0.05 and CER below the mean null" is met.

## Secondary hypotheses (Holm-corrected, α = 0.05): all supported

| ID | Result |
|---|---|
| S1 | Within a day, CER is **0.06** against a null of 0.46 (p ≈ 1·10⁻⁴). |
| S2 | Day normalization lowers held-out CER: 0.53 with it, 0.85 without (Wilcoxon p ≈ 3·10⁻⁵). |
| S3 | The GRU beats a linear CTC read-out: 0.53 against 2.16 (p ≈ 3·10⁻⁵). |

The time-shuffled control has a CER of 0.93, far from the observed value. The result is
therefore interpretable under §5 of the preregistration.

## What this means, and what it does not

- **Claims level 4 is reached for this proxy.** An empirical model predicts a selected state,
  *attempted handwriting*, on held-out real data that was registered before it was seen. In
  ESP terms this state is INT (`esp-neural-mapping-v1`).
- **Within a day, decoding is good:** about 94 % of characters are correct.
- **Across days it degrades** to about 47 % correct characters. That is clearly above chance,
  but not yet usable text. Neural drift remains the main obstacle.
- **The test is narrow:**
  - one participant;
  - one task;
  - 5 later days with 3 trials each;
  - transductive normalization on the unlabelled recording of each test day.

  It shows nothing about other people, other devices, emotion, or experience transfer
  (H1–H3).
- Any further analysis of these data is exploratory.
