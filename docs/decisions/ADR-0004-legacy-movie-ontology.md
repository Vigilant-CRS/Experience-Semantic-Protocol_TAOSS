# ADR-0004 — Legacy movie ontology only as vocabulary/mapping seed

- Status: ACCEPTED (2026-09-28; implemented in WP-010)

- The legacy ontology is proprietary. It is read at runtime from the legacy
  repository and not vendored (maintainer decision, 2026-09-28).
- Tags become namespaced anchors (`esp:emo:movie3-<tag>:v1`) in the
  vocabulary `esp-emo-movie-legacy-v3`.
- Family-level mapping to basic-8 is marked `NARROWER` or `APPROXIMATE`.
  Approximate mappings (love→trust, wonder→surprise, horror→fear,
  despair→sadness) need expert review before use in analyses.
- Legacy L1-normalized `emotion_sparse` weights are retrieval data. They can
  never become psychological intensities.
