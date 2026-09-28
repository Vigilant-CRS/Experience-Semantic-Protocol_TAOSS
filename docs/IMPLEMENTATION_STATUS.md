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
| WP-005 | VERIFIED | `tests/unit/semantics/test_bindings.py` (default deny; oracle property; canonical policy JSON) + protocol-object test `tests/unit/frame/test_frame.py::test_critical_share_emotion_without_its_cause` |
| WP-006 | VERIFIED | `tests/unit/calibration/test_calibration.py` (versioning, baseline updates, expired calibration, deterministic feature transform, same raw value/different baseline) |
| WP-007 | VERIFIED | `tests/unit/taoss/test_blocks.py` (V13 offsets; P_s P_t = 0, sum P_t = I, idempotent — exact; compose(split(x)) == x bit-exact via Hypothesis; no silent zero-fill for absent types) |
| WP-008 | VERIFIED | `tests/unit/ontology/test_registry.py` (duplicate ids rejected; semantic mutation requires new major version; deterministic, order-independent digest; deprecated anchors resolvable; aliases only grow; realizations per encoder with correct dimension) |
| WP-009 | VERIFIED | `tests/unit/ontology/test_basic8.py` (exactly eight canonical ids; stable V13 order; registry digest fixed by `vectors/ontology/esp-emo-v13-basic8-v1.registry.blake2b256`) |
| WP-010 | VERIFIED | `tests/unit/adapters/test_legacy_movie.py` (synthetic fixture: all tags resolve, reproducible mapping, retrieval L1-normalization isolated, malformed sources rejected). Real-data test ran locally on 2026-09-28 against legacy `config/ontology_v3` v3.0.0 with `ESP_LEGACY_MOVIE_ONTOLOGY=…`: 30 anchors, 151 aliases, 5 synonyms dropped with reasons; skipped in CI because the legacy ontology is proprietary |
| WP-011 | VERIFIED | `tests/unit/frame/test_frame.py` (canonical serialization + determinism; JSON Schema validation against `schemas/experience_frame.schema.json`; missing type ⊥ ≠ 0; masked type omission incl. descriptors/anchors/evidence refs; inferred subject affect rejected on L1) · `scripts/generate_schemas.py --check` in `make verify` |
| WP-012 | VERIFIED | `tests/unit/simulation/test_simulator.py` (byte-identical same-seed runs; per-stream seed isolation; exact keyframe interpolation; dropout and clock-drift fixtures; DSL validation) · example `examples/synthetic_sender_receiver/fear_at_work.yaml` |
| WP-013 | VERIFIED | `tests/unit/simulation/test_estimators.py` (Oracle reproduces ground truth exactly; RuleBased yields derived SENSORY features only, traceable to observations, no claim on missing modality; fusion keeps inputs incl. self report, reports conflicts, fused affect refused on L1) |
| WP-076 | IN_PROGRESS | `reuse lint` in `make verify`; DCO job in `.github/workflows/ci.yml`. Offen: SPDX-Header-Pflicht für neue Dateien in CI, Siegel-Prozess |

## Milestones

| Milestone | Verdict | Report |
|---|---|---|
| M0 | PASS | `artifacts/test-reports/M0.json` (commit c08c1fc) |
| M1 | PASS | `artifacts/test-reports/M1.json` (commit 6a98da0) |
| M2 | PASS | `artifacts/test-reports/M2.json` (commit 7d3baed) |
