# ADR-0002 — No sum normalization of human emotion intensities

- Status: ACCEPTED (2026-09-28; implemented in WP-004)

Category intensities are independent values in [0, 1] with no sum
constraint, no softmax and no winner-takes-all. A relative composition may
be *derived* on demand but is never stored (plan §§5, 9, 10).
Evidence: `tests/unit/semantics/test_affect_model.py`.
