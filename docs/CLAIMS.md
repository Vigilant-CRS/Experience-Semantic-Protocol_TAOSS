<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Claims: what this project may say today

Every public statement must match a level of the claims ladder (plan §59). No higher level is
claimed until the tests of every lower level pass.

<!-- claims-level: 3 -->
**Current level: 3. "Physiological and multimodal adapters operate reliably."**

| Level | Statement | Evidence | Reached |
|---|---|---|---|
| 0 | Specification exists. | V13 (`esp_v13.tex`), errata `docs/errata/V13-ERRATA.md` | ✅ |
| 1 | Implementation conforms to wire and consent tests. | M3 gate, golden vectors (`vectors/FROZEN-1.0.0.json`), Rust interop (M10) | ✅ |
| 2 | Semantic states transfer correctly in synthetic / manual ground-truth tests. | M2 and M5 gates (simulator oracle, two-process demo) | ✅ |
| 3 | Physiological and multimodal adapters operate reliably. | M6 gate (30-min soak, 0 lost samples, open-data readers match reference libraries), M7 gate | ✅ |
| 4 | Empirical models predict selected states on held-out data. | exploratory on FALCON H1 (public human intracortical data): attempted arm velocity R² 0.89 within a day and 0.35 on later days with a GRU and unsupervised day normalization (`artifacts/research/falcon_h1_methods.json`). Confirmatory test **preregistered** on unseen data (FALCON H2 handwriting, `docs/research/prereg-falcon-h2.md`); level 4 is claimed only if its primary hypothesis holds | 🟡 preregistered, pending |
| 5 | H1/H2/H3 supported by preregistered ExperienceBench. | needs preregistered runs with all baselines on real corpora | ❌ |
| 6 | Neural interface populates selected TAOSS fields in controlled experiments. | interface only (WP-045); needs hardware and ethics approval | ❌ |

Smoke benchmarks, the type-discovery frontier (`artifacts/research/type_frontier.json`) and
the hardening calibration are **exploratory**. They support no level-4+ statement.
