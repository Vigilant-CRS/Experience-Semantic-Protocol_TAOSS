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
| 4 | Empirical models predict selected states on held-out data. | first step, exploratory: attempted arm velocity from public human intracortical data (FALCON H1) reaches R² 0.21 on held-out trials of the same day and about 0 across days without recalibration (`artifacts/research/neural_falcon_h1.json`). Not yet claimed: no preregistration, one dataset, one proxy target | 🟡 in progress |
| 5 | H1/H2/H3 supported by preregistered ExperienceBench. | needs preregistered runs with all baselines on real corpora | ❌ |
| 6 | Neural interface populates selected TAOSS fields in controlled experiments. | interface only (WP-045); needs hardware and ethics approval | ❌ |

Smoke benchmarks, the type-discovery frontier (`artifacts/research/type_frontier.json`) and
the hardening calibration are **exploratory**. They support no level-4+ statement.
