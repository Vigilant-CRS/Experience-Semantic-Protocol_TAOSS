<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Preregistration: does typed decomposition reduce emotion leakage on real text? (GoEmotions, H2)

Status: **registered before unblinding.**

- The machine-readable record is
  [`research/prereg/goemotions-h2.json`](../../research/prereg/goemotions-h2.json).
- Its digest is checked by `scripts/run_goemotions_study.py`. That script refuses to read
  test labels unless the record is on `origin/main` and unchanged.
- The registration date and commit are those of the first public commit that contains this
  file.

## 1. Question

V13 hypothesis **H2**: *typed decomposition reduces cross-type leakage versus baselines at
comparable utility.*

The concrete question: when a sender masks the emotion part (EMO), is less emotion information
recoverable from the parts it still releases? The released parts are KNO (content) and CTX
(community). We compare a typed (TAOSS) encoder against masking the same-sized slice of a
monolithic encoder, and against post-hoc erasure baselines. Utility must stay comparable.

A positive result would be the project's first confirmatory step on the claims-ladder level 5
track, for H2 only. It says nothing about H1, H3, brains, or experience transfer between
people.

## 2. Data

- **Dataset:** GoEmotions (Demszky et al., ACL 2020). It contains 58 011 English Reddit
  comments, annotated by raters with 27 emotion categories plus neutral. It is released by
  Google Research under **Apache-2.0** (checked on the official repository README and the
  dataset card).
- **Splits:** the official ones, 43 410 / 5 426 / 5 427 items. Every file is pinned by
  SHA-256 in `data/external/goemotions/MANIFEST.json` (git-ignored, never redistributed).
- **Typed mapping, stated honestly:**
  - **EMO:** the rater annotations of the text, i.e. content-side affect
    (`affect_scope = CONTENT`). They are *not* an inference about the writer.
  - **CTX:** the subreddit (483 communities in train).
  - **KNO:** the general content, i.e. the frozen sentence embedding the typed encoder must
    reconstruct.
- **Personal data:** these are public posts under the platform's terms, with no individual
  research consent. They are used for aggregate analysis only; nothing is re-identified,
  and texts are never published.
- **Split hygiene:** the official splits are random over comments. In the test split, 2 404 of
  5 427 items share an author or a thread with train. A secondary hypothesis (S3) repeats the
  primary test on the 3 023 test items whose author **and** thread are unseen.
- **Blinding:** before registration, test labels (emotions, subreddit) were never read. Only
  item counts, metadata-based unseen counts and the unlabelled test texts (for embedding) were
  used. Method development used train → dev only
  (`artifacts/research/goemotions_dev.json`).

## 3. Pipeline (fixed)

1. **Input.** `x` is the L2-normalised embedding from `sentence-transformers/all-MiniLM-L6-v2`
   at revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`, computed frozen.
2. **Encoder.** The same network for every method: MLP 384 → 256 → 112 with GELU, trained on
   train with AdamW (lr 1e-3, weight decay 1e-4), batch 512, 30 epochs, seeds 0, 1 and 2.
   - **TAOSS:** blocks KNO 64 | CTX 32 | EMO 16. Each head reads only its own block (a
     cosine-reconstruction decoder for KNO, softmax for CTX, multi-label sigmoid for EMO).
     - A covariance penalty between the released blocks and EMO, λ_cov = 3.
     - An adversary on the released blocks through gradient reversal, λ_adv = 3.
     - These settings were chosen on dev by the fixed rule: the lowest dev leakage among
       settings whose subreddit accuracy is within δ of the monolithic baseline.
   - **monolithic:** every head reads the full latent, with no penalties. Masking releases the
     first 96 dims.
3. **Released representation with EMO masked.**
   - TAOSS: KNO‖CTX.
   - monolithic: the first 96 dims.
   - **LEACE:** monolithic released, with the emotion multi-hot erased; fitted on train.
   - **learned filter:** monolithic released through `esp.bench.filter.learned_filter`;
     fitted on train.
   - **raw:** the embedding itself (descriptive only).
4. **Leakage.** Probes are trained on the train released representations:
   - a linear one-vs-rest logistic probe;
   - an MLP probe with one hidden layer of 256.

   Leakage = macro-AUROC of the stronger probe on test (chance 0.5). Item scores are averaged
   over the three seeds.
5. **Utility.**
   - Subreddit accuracy of the stronger probe on test.
   - Content fidelity (ridge R² of `x`): reported, not tested.

## 4. Hypotheses and tests

**Primary (P1):** TAOSS releases less emotion information than monolithic masking at
comparable utility.

- **Leakage test:** a one-sided paired bootstrap over test items (10 000 resamples, seed 0) on
  `AUROC_mono − AUROC_taoss`, with p = (1 + #{diff ≤ 0}) / (1 + 10 000).
- **Utility non-inferiority:** the 5 % bootstrap quantile of `acc_taoss − acc_mono` must
  exceed −δ, with δ = 0.02 absolute.
- **Supported if p < 0.05 and utility is non-inferior.**

**Secondary** (Holm-corrected as a family, α = 0.05; each also requires utility
non-inferiority):

| ID | Statement |
|---|---|
| S1 | TAOSS leaks less than LEACE on the monolithic released slice |
| S2 | TAOSS leaks less than the learned adversarial filter |
| S3 | P1 restricted to test items with unseen author and unseen thread |

## 5. Expectations, stated in advance

The outcome is genuinely uncertain, and the dev results already point to it:

| Dev split | Leakage (macro-AUROC, strongest probe) | Subreddit accuracy |
|---|---:|---:|
| raw embedding | 0.882 | 0.053 |
| monolithic masking | 0.871 | 0.058 |
| **TAOSS** (frozen setting) | **0.845** | 0.057 |
| learned filter | 0.836 | 0.056 |
| LEACE | 0.670 | 0.048 |

- **P1 on dev:** TAOSS leaks a little less than monolithic masking (−0.026 AUROC) at almost
  the same utility.
- **But masking is weak protection everywhere.** All methods leak far above chance (0.5),
  because emotion is entangled with content in real text. On synthetic data, the project's
  reference encoder already leaked masked emotion with R² ≈ 0.78.
- **S1 is expected to fail.** On dev, LEACE removes much more linear emotion information, at a
  utility cost still inside δ.
- **Utility is low for every method.** 483-way subreddit classification from a 384-dim
  sentence embedding is hard.

**A negative or partly negative result will be published exactly like a positive one.**

## 6. What would count against the claim

- If P1 fails, H2 is not supported on this dataset, and that is reported.
- If P1 holds but the effect is small (as on dev), it is reported as a small effect, not as
  privacy. The point of H2 in ESP is to *measure* leakage, never to assume it away.
- No re-analysis with other settings will be presented as confirmatory.

## 7. Known limitations

- One dataset, one language, one frozen base encoder, short comments.
- The emotion labels are rater annotations of text, not states of people.
- A post-hoc probe only bounds leakage from below. A stronger adversary could recover more.
- CTX (subreddit) is a coarse stand-in for "situation".

## 8. Reproduction

```bash
python scripts/run_goemotions_dev.py                       # development, train -> dev
python scripts/run_goemotions_study.py --dry-run           # counts; no test labels
python scripts/run_goemotions_study.py --unblind --prereg-commit <public commit> \
    --out artifacts/research/goemotions_h2_study.json
```

Both runs need the GPU environment with `sentence-transformers`, or CPU with the same
packages.
