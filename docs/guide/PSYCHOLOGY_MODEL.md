<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Psychology model

ESP keeps three things apart that everyday language mixes (plan §4):

1. **Observation:** "ECG 112 bpm" (`Observation`). It is semantically neutral and has a unit, a
   device, a clock and a quality.
2. **Derived feature:** "physiological activation high relative to this person's baseline"
   (`FeatureValue`, `StandardizedFeature`).
3. **Interpretation:** "fear 0.75" (`EvidenceClaim`, `AffectiveDescriptor`). It is always
   attributed to a source and carries provenance.

## Self-report is its own evidence source

A self-report is what the person says about themselves. It is never overwritten by inference.
When inference disagrees, the disagreement is reported, not resolved.

```python
import uuid
from esp.core.clock import ClockStamp
from esp.core.provenance import AffectScope
from esp.semantics.self_report import Construct, SelfReport, SelfReportItem

stamp = ClockStamp(source_ns=1, monotonic_ns=1, clock_domain="demo", sequence=0)
report = SelfReport(
    id=uuid.uuid4(), instrument="likert5", vocabulary_id="esp-emo-v13-basic8-v1", timestamp=stamp,
    items=(
        SelfReportItem(kind=Construct.EMOTION_CATEGORY, label="fear", raw=4, scale_min=1, scale_max=5),
        SelfReportItem(kind=Construct.VALENCE, raw=1, scale_min=1, scale_max=5),
    ),
)
affect = report.to_affective_descriptor()
assert affect.affect_scope is AffectScope.SELF_DECLARED
assert affect.valence == -1.0  # raw 1 on 1..5 maps to -1
```

## `affect_scope`: whose affect is it?

| Scope | Meaning | Allowed where |
|---|---|---|
| `content` | what a film, text or scene expresses | L1 |
| `self_declared` | the person's own statement | L1 |
| `inferred_subject` | a model's inference about a person | L2 + consent + regulatory declaration |
| `machine_relay` | a machine relaying a human statement | L2, with references |

Emotion episodes (onset, peak, end) carry their own scope as well (GAP-030).

## Theory pluralism

EMO combines several descriptions:

- **categories:** the basic-8 anchors;
- **dimensions:** valence, arousal and intensity;
- **appraisals:** carried as bindings such as "elicited by";
- **episodes:** onset, peak and end over time.

INT keeps *readiness* (an urge) separate from *commitment* (a decision). None of these is
forced into another. V13's default profile is the basic-8 anchors plus V/A/I; everything else
is a compatible addendum.
