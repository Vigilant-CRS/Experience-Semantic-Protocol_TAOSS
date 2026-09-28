<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Content-side affect and MPEG-7 (informative, WP-079)

ESP content affect (`affect_scope = content`) describes what a media segment *expresses*. The
mapping below is informative. Verify it against ISO/IEC 15938-5 (MPEG-7 MDS) before relying on
it in a product.

| ESP | MPEG-7 MDS (informative) | Notes |
|---|---|---|
| media segment reference (`media.<id>.<start>-<end>ms`) | `VideoSegment` / `AudioSegment` with `MediaTime` | time in milliseconds |
| `AffectiveDescriptor.valence`, `arousal` (content scope) | `Affective` description with an affect type and a score for the segment | ESP keeps continuous values; MPEG-7 scores are relative |
| `categories` (basic-8 anchors) | affect *type* vocabulary (classification scheme) | use the ESP anchor ids as the classification-scheme terms |
| `provenance` (producer, extractor refs) | `CreationInformation` / `Creator` (tool) | the extractors `g_audio`, `g_face`, `g_text` are tools, not annotators |
| `affect_scope` | no direct equivalent | must be preserved: content affect is never a viewer's state |

Legacy source: the Emotional Movie Search Engine is the first L1 data source. Its ontology
is proprietary and is read only at runtime (`esp.adapters.legacy_movie`, ADR-0004). Retrieval
weights stay separate from affect intensities.
