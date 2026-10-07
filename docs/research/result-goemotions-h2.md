<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Result: cross-type emotion leakage on real text (GoEmotions, H2)

- **Preregistration:** [prereg-goemotions-h2.md](prereg-goemotions-h2.md), public in commit
  `09bf3da` (2026-10-07 03:34 +0200). Digest `cbfaf9e3…b640`.
- **Run:** a single confirmatory run on the official test split (5,427 comments). The test
  split was blinded until then.
- **Raw output:** [`artifacts/research/goemotions_h2_study.json`](../../artifacts/research/goemotions_h2_study.json).
- **Hardware:** RTX 3070 Laptop, CUDA 12.6. Runtime 105 min.

Leakage is the macro-AUROC of the stronger probe predicting the rater-annotated emotions
from the *released* parts while EMO is masked. 0.5 means no information leaks. Utility is
subreddit (CTX) accuracy, with non-inferiority margin δ = 0.02.

| Test | TAOSS | Comparator | Outcome |
|---|---:|---:|---|
| **P1** TAOSS vs monolithic masking | **0.848** | 0.870 | **supported**: leakage lower (p < 0.001), utility non-inferior |
| S1 TAOSS vs LEACE | 0.848 | **0.678** | not supported (LEACE leaks far less) |
| S2 TAOSS vs learned adversarial filter | 0.848 | **0.832** | not supported (the filter leaks less) |
| S3 = P1 on unseen authors and threads (3,023 items) | 0.854 | 0.875 | **supported** |

## What this means

- **Typing helps a little.** Giving emotion its own trained block reduces the emotion
  information left in the other parts. Compared with simply masking a slice of an untyped
  latent, leakage falls by about 0.02 AUROC at the same utility. The result also holds for
  authors and threads never seen in training.
- **It is far from privacy.** All methods still leak emotion strongly (AUROC 0.68–0.87
  against 0.5). Dedicated erasure methods do better than TAOSS: LEACE removes much more
  linear emotion information, and an adversarial filter removes a little more.
- **Hypothesis H2 as V13 states it is not supported.** The plan requires beating all
  baselines. TAOSS beats naive masking but not LEACE or the learned filter. Claims level 5
  is **not** reached.
- **Design consequence.** ESP should treat typed heads and concept erasure as complementary:
  masking a type should be combined with erasure (for example LEACE) of that type from the
  released parts. The leakage audit stays mandatory, as the protocol already requires.
- This is one dataset of annotated text, which is content-side affect, not anyone's felt
  state. H1 and H3 still need real experience data.
