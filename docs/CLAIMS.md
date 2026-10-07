<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Claims: what this project may say today

Every public statement must match a level of the claims ladder (plan §59). No higher level is
claimed until the tests of every lower level pass.

<!-- claims-level: 4 -->
**Current level: 4. "Empirical models predict selected states on held-out data"**, shown for one
narrow proxy (attempted handwriting from public human intracortical data, preregistered).

| Level | Statement | Evidence | Reached |
|---|---|---|---|
| 0 | Specification exists. | V13 (`esp_v13.tex`), errata `docs/errata/V13-ERRATA.md` | ✅ |
| 1 | Implementation conforms to wire and consent tests. | M3 gate, golden vectors (`vectors/FROZEN-1.0.0.json`), Rust interop (M10) | ✅ |
| 2 | Semantic states transfer correctly in synthetic / manual ground-truth tests. | M2 and M5 gates (simulator oracle, two-process demo) | ✅ |
| 3 | Physiological and multimodal adapters operate reliably. | M6 gate (30-min soak, 0 lost samples, open-data readers match reference libraries), M7 gate | ✅ |
| 4 | Empirical models predict selected states on held-out data. | **preregistered and confirmed** on FALCON H2 (public human intracortical data): attempted handwriting decoded into text on later, unseen days, CER 0.53 against a null of 0.73 (p = 0.0005); within a day CER 0.06 ([result](research/result-falcon-h2.md), [preregistration](research/prereg-falcon-h2.md)). One participant, one task, small test set; within-day exploratory evidence on FALCON H1 (R² 0.89 / 0.35) | ✅ narrow |
| 5 | H1/H2/H3 supported by preregistered ExperienceBench. | Two preregistered H2 tests on real text. GoEmotions ([result](research/result-goemotions-h2.md)): typing alone beats naive masking but loses to LEACE and an adversarial filter. DailyDialog ([result](research/result-dailydialog-erasure.md)): **typing plus erasure** beats erasure alone at the same size and an adversarial filter at equal utility, but with a small effect (0.014 AUROC) and a utility cost against some baselines. H2 is not established across all baselines; H1 and H3 still need real experience data | ❌ (H2 partial) |
| 6 | Neural interface populates selected TAOSS fields in controlled experiments. | interface only (WP-045); needs hardware and ethics approval | ❌ |

Smoke benchmarks, the type-discovery frontier (`artifacts/research/type_frontier.json`) and
the hardening calibration are **exploratory**. They support no level-4+ statement.
