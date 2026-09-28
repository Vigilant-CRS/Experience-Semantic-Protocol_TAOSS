# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
from esp.core.clock import ClockStamp
from esp.core.provenance import Provenance, SourceKind

VOCAB = "esp-emo-v13-basic8-v1"

SELF = Provenance(source_kind=SourceKind.SELF_REPORT)
MODEL = Provenance(
    source_kind=SourceKind.MODEL_INFERENCE,
    producer_id="esp-emo-fusion",
    producer_version="1.0.0",
    source_refs=("obs_voice_193", "obs_eda_441"),
)
ANNOTATOR = Provenance(source_kind=SourceKind.HUMAN_ANNOTATION, producer_id="annotator-7")
NOW = ClockStamp(source_ns=1, monotonic_ns=1, clock_domain="host:monotonic", sequence=0)
