<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Preregistration: does typing plus concept erasure leak less than erasure alone? (DailyDialog, H2 follow-up)

Status: **registered before unblinding.**

- The machine-readable record is
  [`research/prereg/dailydialog-erasure.json`](../../research/prereg/dailydialog-erasure.json).
- Its digest is checked by `scripts/run_dailydialog_erasure_study.py`. That script refuses to
  read test labels unless the record is on `origin/main` and unchanged, and every data file
  matches its pinned SHA-256.
- The registration date and commit are those of the first public commit that contains this
  file.

## 1. Question

The preregistered GoEmotions H2 study (`docs/research/result-goemotions-h2.md`) found that
typed heads leak less of a masked emotion type than naive masking. They still leak more than
LEACE or an adversarial filter.

The design consequence is ADR-0035 (`src/esp/privacy/erasure.py`): **when a type is masked,
the released types are also cleaned by a declared LEACE eraser fitted on training data.**

This study asks whether that combination is better than erasure alone. Specifically, when EMO
is masked, does a typed (TAOSS) encoder plus LEACE erasure of EMO leak less emotion from the
released parts (KNO+CTX+INT) than LEACE on an untyped latent of the same size? The utility of
the released types must not get worse.

A positive result would say typing adds protection beyond a standard erasure baseline. A
negative result would say that, on this data, the protection comes from erasure, and typing
adds nothing measurable.

Either way, this concerns H2 only, on text annotations. It says nothing about brains, felt
states, or experience transfer.

## 2. Data

### Dataset and license

- **Dataset:** DailyDialog (Li et al., IJCNLP 2017). It contains 13 118 multi-turn English
  dialogues written to resemble daily conversation. Annotators labelled every utterance with:
  - **emotion:** 7 classes (no emotion, anger, disgust, fear, happiness, sadness, surprise);
  - **dialog act:** 4 classes (inform, question, directive, commissive).

  Every dialogue also has one **topic** (10 classes).
- **License:** **CC BY-NC-SA 4.0**, as stated by the authors and on the dataset card. Use is
  non-commercial research. Data is never redistributed or committed.
- **Source:** the authors' original archive `ijcnlp_dailydialog.zip`.
  - The authors' site is offline, so it was retrieved from the Internet Archive snapshot of
    the authors' URL.
  - SHA-256 `c641e88cbf21fd7c1b57289387f9107d33fe8685a2b37fe8066b82776535ea89`, 4 475 921 bytes.
  - Every extracted file is pinned in `data/external/dailydialog/MANIFEST.json` (git-ignored);
    the registry entry is in `datasets/registry.json`.

### Splits

- The official train / validation / test segmentation: 11 118 / 1 000 / 1 000 dialogues.
- In utterances: 87 170 / 8 069 / 7 740.

### Typed mapping, stated honestly

| Type | Mapping | Note |
|---|---|---|
| **EMO** (masked) | the utterance emotion annotation | content-side (`affect_scope = CONTENT`), not a speaker's felt state |
| **INT** | the dialog act | |
| **CTX** | the dialogue topic | Taken from the corpus-wide `dialogues_topic.txt` by exact dialogue text. Dialogues whose text maps to conflicting topics get no topic and are excluded from CTX scoring (train: 2 854 of 87 170 utterances; validation: 185 of 8 069). |
| **KNO** | content: the frozen sentence embedding the encoder must reconstruct | |

### Personal data

The corpus is scripted dialogue collected from English-learning websites. It contains no
research participants and no account identifiers. It is used for aggregate analysis only;
texts are never published.

### Split hygiene

- DailyDialog's splits contain some dialogues whose exact text also occurs in train: 534 of
  the 8 069 validation utterances and 585 of the 7 740 test utterances.
- These were flagged from **text alone**, without reading labels.
- Secondary S3 repeats the primary test on the 7 155 test utterances in dialogues not seen in
  train.

### Blinding

- Before registration, test labels (emotion, act, topic) were never loaded. The loader only
  reads them with `unblind=True`, which the study script allows only behind the guard above.
- Before registration, only test counts, the text-only overlap flag, and unlabelled test texts
  (for the frozen embedding) were used.
- Development used train → validation only (`artifacts/research/erasure_dailydialog_dev.json`).
- Earlier GoEmotions development used train → dev only
  (`artifacts/research/erasure_goemotions_dev.json`). The GoEmotions test split, already used
  for the confirmatory H2 run, was not reused.

## 3. Pipeline (fixed)

The code is `src/esp/bench/dailydialog_erasure_study.py`: `analyse`, `run`, `CONFIG`.

1. **Input.** `x` is the L2-normalised embedding from `sentence-transformers/all-MiniLM-L6-v2`
   at revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`, computed frozen. It is the same as
   in GoEmotions.
2. **Encoder.** The same network for both encoder types: MLP 384 → 256 → 112 with GELU,
   trained on train with AdamW (lr 1e-3, weight decay 1e-4), batch 512, 20 epochs, seeds 0, 1
   and 2. The loss has four terms:
   - KNO: cosine reconstruction of `x`;
   - CTX: topic cross-entropy, on utterances with a topic;
   - INT: dialog-act cross-entropy;
   - EMO: emotion cross-entropy.

   **TAOSS (typed):**
   - Blocks are KNO 64 | CTX 16 | INT 16 | EMO 16, and each head reads only its own block.
   - A covariance penalty between the released blocks (96 dims) and EMO, **λ_cov = 1**.
   - An adversary on the released blocks through gradient reversal, **λ_adv = 1**.
   - These values were chosen on validation by the rule fixed before the run (section 5).

   **monolithic:** every head reads the full latent, with no penalties. Masking releases the
   first 96 dims.
3. **Released representations with EMO masked.**
   - **Each eraser** is `esp.privacy.erasure.LeaceEraser`, the protocol mechanism a sender
     runs.
     - It is fitted on train released vectors against the one-hot emotion annotation.
     - It is versioned by digest, with training-data id `dailydialog:train:seed<k>:<base>`.
   - **Each filter** is `esp.bench.filter.learned_filter`, fitted on train rows only, with the
     dialog act as its task.

   | Name | Released representation |
   |---|---|
   | `taoss_leace` (the mechanism) | TAOSS KNO‖CTX‖INT, then LEACE |
   | `mono_leace` | the monolithic 96-dim slice, then LEACE: erasure alone at the same size |
   | `raw_leace` | the frozen embedding, then LEACE: no encoder at all |
   | `mono_filter` | the monolithic slice through the learned filter |
   | `taoss` | TAOSS released blocks without erasure |
   | `mono` | the monolithic slice: descriptive only |
4. **Leakage.** Two probes are trained on the train released representations:
   - a linear softmax probe;
   - an MLP probe with one hidden layer of 256 (`ProbeConfig`: 20 epochs, batch 1024,
     lr 2e-3, weight decay 1e-4).

   Leakage = **macro-AUROC (one-vs-rest, 7 classes) of the stronger probe on test**, where
   chance is 0.5. Probe scores are averaged over the three seeds.

   LEACE guarantees chance for *linear* probes on the fitting distribution. The MLP probe
   measures the nonlinear residual, which is the quantity this study actually compares.
5. **Utility.**
   - **Topic (CTX) accuracy** and **dialog-act (INT) accuracy** of the stronger probe on test.
   - Content fidelity (ridge R² of `x`): reported, not tested.

## 4. Hypotheses and tests

All tests use a **cluster bootstrap over test dialogues**, because utterances of one dialogue
are not independent:

- 10 000 resamples of whole dialogues with replacement;
- seed 0 for leakage, seeds 1 and 2 for the CTX and INT differences;
- the probe choice (linear or MLP) is fixed on the full evaluation set.

**Primary (P1):** `taoss_leace` leaks less emotion than `mono_leace` at non-inferior utility.

- **Leakage test:** one-sided, on `AUROC_mono_leace − AUROC_taoss_leace`, with
  p = (1 + #{diff ≤ 0}) / (1 + 10 000).
- **Utility non-inferiority:** the 5 % bootstrap quantiles of `acc_taoss_leace − acc_mono_leace`
  must exceed −δ, with **δ = 0.02** absolute, for **both** CTX (topic) and INT (dialog act).
- **Supported if p < 0.05 and both utilities are non-inferior.**

**Secondary** (Holm-corrected as a family, α = 0.05; each also requires CTX and INT
non-inferiority):

| ID | Statement |
|---|---|
| S1 | `taoss_leace` leaks less than `raw_leace` (erasure on the raw embedding) |
| S2 | `taoss_leace` leaks less than `mono_filter` (learned adversarial filter) |
| S3 | P1 restricted to the test utterances in dialogues not seen in train |
| S4 | `taoss_leace` leaks less than `taoss` (erasure adds protection to typing) |

## 5. Development and expectations, stated in advance

### Selection rule

The rule was fixed before the validation run, in `scripts/run_dailydialog_erasure_dev.py`:
among the typed settings (λ_cov, λ_adv) ∈ {(0, 0), (1, 1), (3, 3)}, choose the lowest
validation leakage of `taoss_leace` whose CTX and INT accuracies are both within δ of
`mono_leace`.

The rule chose **(1, 1)**. The setting (3, 3) leaked least (0.836), but it **failed the utility
gate**: its CTX accuracy was 0.525 against 0.551, and its INT accuracy 0.694 against 0.715. It
was therefore not chosen. We register the rule's choice and do not override it.

### DailyDialog validation (train → validation, 3 seeds, EXPLORATORY)

| Variant | Leakage (macro-AUROC) | Topic accuracy | Act accuracy | Content R² |
|---|---:|---:|---:|---:|
| mono | 0.928 | 0.553 | 0.735 | 0.606 |
| mono_filter | 0.920 | 0.527 | 0.728 | 0.285 |
| **mono_leace** (P1 baseline) | **0.884** | 0.551 | 0.715 | 0.558 |
| raw_leace | 0.888 | 0.598 | 0.743 | 0.960 |
| taoss (1, 1) | 0.925 | 0.537 | 0.729 | 0.581 |
| **taoss_leace (1, 1)** (registered) | **0.894** | 0.538 | 0.712 | 0.540 |
| taoss (0, 0) | 0.929 | 0.557 | 0.739 | 0.602 |
| taoss_leace (0, 0) | 0.906 | 0.557 | 0.730 | 0.554 |
| taoss (3, 3) | 0.910 | 0.528 | 0.714 | 0.541 |
| taoss_leace (3, 3) | 0.836 | 0.525 | 0.694 | 0.498 |

### GoEmotions dev (train → dev, the frozen GoEmotions H2 encoder, 3 seeds, EXPLORATORY)

| Variant | Leakage | Subreddit accuracy | Content R² |
|---|---:|---:|---:|
| taoss | 0.844 | 0.057 | 0.560 |
| **taoss_leace** | **0.640** | 0.048 | 0.342 |
| taoss_filter | 0.787 | 0.048 | 0.291 |
| mono | 0.871 | 0.058 | 0.569 |
| mono_leace | 0.670 | 0.048 | 0.353 |
| mono_filter | 0.836 | 0.056 | 0.342 |
| raw_leace | 0.752 | 0.048 | 0.837 |

On GoEmotions, the *linear* probe after LEACE is at chance (0.49–0.50) for every erased
variant. All remaining leakage there is nonlinear.

### Honest expectations

- **P1 is expected to fail.** On DailyDialog validation, the registered `taoss_leace` leaks
  *more* than `mono_leace` (0.894 against 0.884), with slightly lower topic accuracy.
  - The GoEmotions dev advantage (−0.030) did not replicate at the setting the rule allowed.
  - Only the stronger penalty (3, 3) reduced leakage clearly, and it cost more utility than δ.
- **S1 is expected to fail.** Erasure on the raw embedding leaks about as little as
  `mono_leace` and keeps the best utility.
- **S2 is uncertain.** The learned filter barely reduced leakage on validation (0.920), so the
  leakage part is likely. However, the act accuracy of `taoss_leace` was 0.017 below the
  filter's, so INT non-inferiority (δ = 0.02) may fail.
- **S4 is uncertain for the same reason.** Erasure removed about 0.03 AUROC from the typed
  blocks, but it lowered act accuracy by 0.017 (0.729 to 0.712). The non-inferiority bound may
  fail.
- **The registered encoder trains EMO, INT and CTX jointly.** Erasing EMO also removes some
  act information. Several "support" outcomes therefore hinge on the INT utility check this
  preregistration adds.
- **Leakage stays far above chance (0.5) for every method.** In this corpus, emotion
  annotations are strongly entangled with content. Masking plus linear erasure is a partial
  measure, not privacy.

**A negative or partly negative result will be published exactly like a positive one.**

## 6. What would count against the claim

- If P1 fails, "typing adds protection beyond erasure" is not supported on DailyDialog. The
  ESP recommendation then rests on erasure itself, with typing justified by interface and
  audit reasons, not by leakage.
- If P1 holds with a small effect, it is reported as a small effect.
- No re-analysis with other settings (for example the (3, 3) penalty) will be presented as
  confirmatory. Any such analysis is labelled exploratory.

## 7. Known limitations

- One dataset, one language, one frozen base encoder, short scripted utterances.
- Emotion and act labels are annotations of text, not states of people.
- A post-hoc probe only bounds leakage from below. LEACE's guarantee is linear; nonlinear
  adversaries can recover more.
- The license (CC BY-NC-SA) restricts the data to non-commercial research use.
- 585 test utterances are in dialogues whose text also occurs in train. S3 addresses this.
- The emotion class distribution is highly imbalanced. "No emotion" makes up 82.8 % of train
  and 88.1 % of validation utterances, and "fear" only 0.17 % of train. Macro-AUROC weights
  every class equally, so rare classes with few test positives make it noisy. The cluster
  bootstrap carries that noise.

## 8. Reproduction

```bash
python scripts/run_dailydialog_erasure_dev.py                     # development, train -> validation
python scripts/run_dailydialog_erasure_study.py --dry-run         # counts; no test labels
python scripts/run_dailydialog_erasure_study.py --unblind --prereg-commit <public commit> \
    --out artifacts/research/dailydialog_erasure_study.json
```

All runs need `sentence-transformers` and `torch`. A GPU is optional.
