# Implementation Status

Evidence ledger for `docs/MASTER_IMPLEMENTATION_PLAN.md`. The plan is the
source of truth for each work package's status; this file records the
**evidence** (reproducible test commands) for every package that is
`IMPLEMENTED` or `VERIFIED`. `scripts/verify_plan_sync.py` checks that
both agree.

## Work packages

| WP | Status | Evidence (tests / command) |
|---|---|---|
| WP-000 | VERIFIED | `tests/milestone/test_m0.py`, `tests/unit/test_package.py`, `tests/unit/test_verify_plan_sync.py` · `make verify` · `uv run python scripts/run_milestone.py M0` |
| WP-001 | VERIFIED | `tests/unit/core/test_scalars_ids.py`, `tests/unit/core/test_taoss_types.py`, `tests/unit/core/test_model_clock_provenance.py`, `tests/property/test_core_properties.py` (12,000 oracle-checked objects + Hypothesis) · mutation check: range bound and -0.0 normalization mutants killed |
| WP-002 | VERIFIED | `tests/unit/observation/test_observation.py` (unit conversions incl. offsets, invalid values, dropout, missing clock, per-stream ordering, offset-uncertainty propagation, semantic neutrality) |
| WP-003 | VERIFIED | `tests/unit/semantics/test_evidence_claim.py` (golden: fear intensity 0.9 + confidence 0.4 lossless; no inference without provenance; confidence/probability independent of intensity; self report is own source) |
| WP-004 | VERIFIED | `tests/unit/semantics/test_affect_model.py` (critical: same mix / different absolute intensity stays distinct; mixed emotions without sum rule; V13 V/A/I + declared dimensions; affect_scope rules; readiness != commitment; self reports; episodes/traces) |
| WP-076 | IN_PROGRESS | `reuse lint` in `make verify`; DCO job in `.github/workflows/ci.yml`. Offen: SPDX-Header-Pflicht für neue Dateien in CI, Siegel-Prozess |

## Milestones

| Milestone | Verdict | Report |
|---|---|---|
| M0 | PASS | `artifacts/test-reports/M0.json` (commit c08c1fc) |
