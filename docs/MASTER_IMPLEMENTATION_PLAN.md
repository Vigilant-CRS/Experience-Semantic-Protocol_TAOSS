---
document_id: TAOSS-ESP-MASTER-PLAN
title: "Experience Semantic Protocol / TAOSS — Master Implementation Plan"
version: "0.2.0"
status: "PLANNING_BASELINE_REV2"
date: "2026-09-28"
target_repository: "git@github.com:Vigilant-CRS/Experience-Semantic-Protocol_TAOSS.git"
first_l1_implementation: "https://github.com/Vigilant-CRS/Experience-Semantic-Protocol_Emotional-Movie-Search-Engine"
normative_source: "The Experience Semantic Protocol, V13, 2026-09-25"
language: "de"
maintainer: "Vigilant e.K."
license_model: "AGPL-3.0-or-later (Code) / CC-BY-SA-4.0 (Spec, Doku, Ontologie) / CC-BY-4.0 (Vektoren, Schemas)"
scope_target: "MAXIMAL — vollständige V13-Abdeckung L1 → L∞ (siehe §52c)"
---

# Experience Semantic Protocol / TAOSS — Master Implementation Plan

## 0. Zweck dieses Dokuments

Dieses Dokument ist die **Single Source of Truth** für die Implementierung des
Experience Semantic Protocol (ESP) und der Typed Approximately Orthogonal Semantic
Subspaces (TAOSS) im Repository:

```text
git@github.com:Vigilant-CRS/Experience-Semantic-Protocol_TAOSS.git
```

Es ist bewusst so geschrieben, dass ein Coding-LLM oder ein menschliches
Entwicklungsteam es **Arbeitspaket für Arbeitspaket** umsetzen kann.

Es erfüllt fünf Funktionen gleichzeitig:

1. technische Gesamtspezifikation,
2. psychologisch sauberes Daten- und Ontologiemodell,
3. Implementierungsreihenfolge,
4. Test- und Abnahmespezifikation,
5. Änderungs- und Entscheidungsprotokoll.

Dieses Dokument darf während der Implementierung **nicht zu einer veralteten
Roadmap werden**. Wenn die Implementierung aus nachvollziehbaren Gründen anders
erfolgt als hier beschrieben, muss der Plan im selben Pull Request aktualisiert
werden.

## 0.1 Änderungsprotokoll dieses Dokuments

| Version | Datum | Änderung |
|---|---|---|
| 0.1.0 | 2026-09-28 | Planungsbaseline (L1-Kern, WP-000 … WP-047, M0 … M12). |
| 0.2.0 | 2026-09-28 | Vollabgleich gegen V13 (alle Kapitel inkl. Part III/IV und Anhänge). Neu: §4.5 Content- vs. Subject-Affect, §52a Lizenz & Governance, §52b Lückenregister (GAP-001 … GAP-024), §52c V13-Abdeckungsmatrix, WP-048 … WP-085, Meilensteine M3a und M13 … M17, erweiterte Traceability, ADR-0005 … ADR-0024, Zielbild „maximale Ausbaustufe“. |

## 0.2 Ausbaustufe

Ziel ist die **maximale Ausbaustufe**: Jede implementierbare normative oder
empfohlene Aussage von V13 — von L1 bis L∞ (MEB, ESP-Agent, XCF, Typed Hive,
Trust Vector, Regulatorik) — erhält ein Arbeitspaket, einen Test und einen
Eintrag in der Abdeckungsmatrix (§52c). Was nicht ohne Hardware, Menschen
oder Ethikfreigabe implementierbar ist, wird trotzdem als Interface,
Simulator-Vertrag und Konformitätstest gebaut und explizit als `FUTURE` oder
`DEFERRED` markiert — nie stillschweigend weggelassen.

---

# 1. Verbindliche Arbeitsregeln für Coding-LLMs

## 1.1 Vor jedem Arbeitspaket

Der Coder MUSS:

1. dieses Dokument lesen;
2. das aktuelle Arbeitspaket identifizieren;
3. dessen Abhängigkeiten prüfen;
4. bestehende Implementierung und Tests prüfen;
5. die vorgesehenen Tests **vor** oder gleichzeitig mit der Implementierung
   anlegen;
6. keine normative Designentscheidung stillschweigend ändern.

## 1.2 Nach jedem Arbeitspaket

Der Coder MUSS:

1. alle Unit-Tests ausführen;
2. alle Integrations-Tests ausführen, die durch die Änderung betroffen sind;
3. den Meilenstein-Test ausführen, sofern das Arbeitspaket einen Meilenstein
   abschließt;
4. den Status in diesem Dokument aktualisieren;
5. geänderte Architekturentscheidungen dokumentieren;
6. neue Risiken oder offene Fragen ergänzen;
7. die Traceability Matrix aktualisieren;
8. Testberichte bzw. reproduzierbare Testbefehle hinterlegen.

## 1.3 Keine stillen Abweichungen

Wenn eine Umsetzung von diesem Plan abweichen muss:

```text
1. STOP
2. Abweichung beschreiben
3. Decision Record anlegen
4. Auswirkungen auf Spezifikation, Tests, Wire-Kompatibilität und Sicherheit prüfen
5. Masterplan aktualisieren
6. erst dann implementieren
```

Die Abweichung wird unter

```text
docs/decisions/ADR-XXXX-<short-title>.md
```

dokumentiert.

Eine Abweichung ist insbesondere verpflichtend zu dokumentieren, wenn sie betrifft:

- Wire Format,
- Kryptografie,
- Semantik eines TAOSS-Typs,
- Dimensionen,
- Ontologie-IDs,
- Consent-Semantik,
- Skalen oder Normalisierung,
- Zeitmodell,
- öffentliche API,
- Kompatibilität,
- Testschwellen,
- Datenaufbewahrung,
- Sicherheitsannahmen.

## 1.4 Statuswerte

Jedes Arbeitspaket verwendet genau einen Status:

```text
NOT_STARTED
IN_PROGRESS
BLOCKED
IMPLEMENTED
VERIFIED
DEFERRED
REJECTED
FUTURE
```

`FUTURE` bedeutet: nur Interface/Platzhalter, keine Funktionsbehauptung (§3.4).

`IMPLEMENTED` bedeutet nur, dass Code vorhanden ist.

`VERIFIED` bedeutet, dass alle definierten Abnahmetests bestanden sind.

---

# 2. Quellenhierarchie

Bei Widersprüchen gilt folgende Priorität:

1. **ESP V13 normative Aussagen**
2. dieses Masterdokument
3. freigegebene Architecture Decision Records
4. Companion Specifications
5. Implementierungsdetails
6. Experimente

V13 definiert unter anderem:

- sechs TAOSS-Typen:
  - Knowledge,
  - Intention,
  - Emotion,
  - Context,
  - Sensory,
  - Temporal;
- die L1-Dimensionierung:
  - Knowledge 240,
  - Intention 64,
  - Emotion 64,
  - Context 64,
  - Sensory 64,
  - Temporal 16,
  - Gesamt 512;
- Ontologie-Anker als interpretierbare, registry-gebundene Referenzen;
- einen 100-Byte-Wire-Header;
- typisierte TLV-Payloads;
- Capability- und Consent-Semantik;
- Revocation;
- pseudonyme Session-Identitäten;
- ExperienceBench mit H1, H2 und H3;
- BCI-freies L1;
- spätere physiologische und neurale Adapter als Erweiterung derselben
  semantischen Ebene.

---

# 3. Statusklassen für Spezifikationsbestandteile

Jede größere Designentscheidung wird mit einer Klasse versehen.

## 3.1 `V13_NORMATIVE`

Muss byte- oder semantikgenau mit V13 übereinstimmen.

Beispiele:

- TAOSS-6-Dimensionierung,
- Wire Header v1,
- Typcodes,
- Mask-Bit-Invariante,
- Capability-Grundsemantik,
- Nonce-Eindeutigkeit.

## 3.2 `V13_COMPATIBLE_ADDENDUM`

Nicht in V13 vollständig spezifiziert, aber kompatible Präzisierung.

Beispiele:

- psychologisch differenzierte Metadaten oberhalb des 64-dimensionalen
  Emotion-Latents,
- Evidence Claims,
- Semantic Bindings,
- Calibration Records,
- Transport-Mapping auf QUIC.

## 3.3 `EXPERIMENTAL`

Noch nicht Teil des Standards.

Beispiele:

- konkrete multimodale State-Estimatoren,
- EEG-Featuremodelle,
- neuronale Encoder-Architekturen,
- neue Anchor-Sets.

## 3.4 `FUTURE`

Nur Interface oder Platzhalter; keine aktuelle Funktionsbehauptung.

Beispiele:

- invasive Brain-Computer-Interface-Adapter,
- neuronale Stimulation,
- direkte subjektive Experience-Rekonstruktion.

---

# 4. Nicht verhandelbare Grundprinzipien

## 4.1 Kein Mind Reading Claim

Das System behauptet nicht:

- Gedanken direkt zu lesen,
- Bewusstsein zu übertragen,
- Qualia zu reproduzieren,
- Emotionen aus Physiologie sicher zu erkennen,
- Erinnerungen auszulesen.

Es transportiert:

> typisierte, provenance-behaftete und consent-gebundene semantische
> Repräsentationen von beobachteten, berichteten oder inferierten Zuständen.

## 4.2 Beobachtung ist nicht Interpretation

Folgende Ebenen müssen strukturell getrennt bleiben:

```text
Observation
    ↓
Feature
    ↓
Inference
    ↓
Semantic Estimate
    ↓
TAOSS Representation
    ↓
ESP Transmission
```

Beispiel:

```text
ECG: 112 bpm
```

ist eine Beobachtung.

```text
physiological activation: high
```

ist ein abgeleitetes Merkmal.

```text
fear intensity estimate: 0.75
```

ist eine Interpretation.

Diese Ebenen dürfen nicht miteinander verwechselt werden.

## 4.3 Self Report ist eine eigene Evidenzquelle

Wenn eine Person sagt:

```text
"I feel fear at intensity 0.8"
```

wird dies als eigene Quelle gespeichert und nicht mit einem Sensorurteil
überschrieben.

## 4.4 Psychologische Theoriepluralität

Der Standard soll **keine einzelne Emotionstheorie als Wahrheit festschreiben**.

Er standardisiert:

- Datenstruktur,
- Skalen,
- Provenance,
- Confidence,
- Zeit,
- Referenzvokabulare,
- Anchor-IDs,
- Beziehungen,
- Consent.

Profile dürfen unterschiedliche psychologische Vokabulare verwenden.

## 4.5 Content-Side vs. Subject-Side Affect (V13 §6.4 „L1 Affect Limitation“)

Klasse: `V13_NORMATIVE` (Grenze) + `V13_COMPATIBLE_ADDENDUM` (Kodierung, GAP-001).

V13 zieht eine **strukturelle** Grenze, die in v0.1.0 dieses Plans fehlte:

> L1-EMO ist ein **content-side affect proxy**: was ein Inhalt ausdrückt,
> nicht was eine Person fühlt. Die L1-Wire trägt Content-Affect; die L2+-Wire
> trägt Subject-Affect unter zusätzlichen Consent-Anforderungen.
> Implementierungen **MUST NOT** beide auf demselben Kanal verwechseln.

Zugleich erlaubt V13 §L1 („Collaborative tools“) explizit
**sender-authored / self-declared affect** auf L1, verbietet aber automatische
Inferenz über Gegenüber aus biometrischen Daten in Arbeits- und
Bildungskontexten (EU AI Act Art. 5(1)(f), V13 §Regulatory).

Daraus folgt ein verbindliches Feld `affect_scope` für jede EMO-Aussage:

| `affect_scope` | Bedeutung | Erlaubtes Profil | Zusatzbedingungen |
|---|---|---|---|
| `CONTENT` | Affekt, den ein Artefakt/eine Szene ausdrückt | L1 (`profile=0x01`) | keine Personeninferenz aus Biometrie |
| `SELF_DECLARED` | vom Sender selbst berichteter eigener Zustand | L1 | nur `source_kind=self_report`, kein Sensor-Override |
| `INFERRED_SUBJECT` | aus Beobachtungen einer Person inferierter Zustand | nur L2+ (`profile≥0x02`) | L2-Consent, Regime-Deklaration (WP-078), Art.-5(1)(f)-Guard |
| `MACHINE_RELAY` | von einer Maschine weitergeleiteter menschlicher EMO-Vektor | L2+ | menschliche Provenienz + Capability (V13 §MEB) |

Harte Regeln:

1. Ein Frame mit `profile=0x01` und `affect_scope=INFERRED_SUBJECT` ist
   ungültig und wird vor Decoder-Aufruf verworfen.
2. Maschinell erzeugte Pakete dürfen **niemals** EMO autorieren (V13 §MEB,
   `T_mach = T \ {EMO}`), nur `MACHINE_RELAY` mit menschlicher Provenienz.
3. `affect_scope` ist Teil der signierten, verschlüsselten Payload
   (Addendum-TLV, GAP-004), nie Klartext-Header.
4. Innerhalb einer Session darf `affect_scope` für EMO nicht wechseln, ohne
   Neuaushandlung (verhindert „Kanalverwechslung“).
5. `source_kind=synthetic_ground_truth` (Simulator, §19.1) darf nur
   `SELF_DECLARED` (simulierter Self Report) oder `CONTENT` tragen, nie
   `INFERRED_SUBJECT` oder `MACHINE_RELAY` (v0.2.1).

---

# 5. Warum das bestehende Movie-ESP nicht 1:1 übernommen wird

Das bestehende Emotional-Movie-Search-Engine-Repository enthält eine
retrieval-orientierte Ontologie.

Dort ist `emotion_sparse`:

```text
24 Emotionstags + 6 Viewer-Impact-Tags = 30 Dimensionen
```

und der Sparse Vector ist für Retrieval auf:

```text
L1-Norm = 1
```

normiert.

Diese Normierung ist sinnvoll für Ähnlichkeitssuche, aber **nicht als
psychologisches Zustandsmodell**.

Beispiel:

```text
fear       0.8
sadness    0.7
tenderness 0.6
```

und

```text
fear       0.2
sadness    0.175
tenderness 0.15
```

würden nach Summennormierung nahezu dieselbe Komposition erhalten.

Die absolute Intensität wäre verloren.

Daher gilt:

> Die Movie-ESP-Ontologie wird als Seed für Vocabulary, Synonyme und
> Retrieval-Mapping verwendet, aber ihre L1-Normierung wird nicht als
> psychologische Zustandsrepräsentation übernommen.

---

# 6. Zielarchitektur

```text
┌────────────────────────────────────────────────────────────────────┐
│                         Acquisition Layer                          │
│                                                                    │
│ text │ speech │ camera │ behavior │ wearables │ EEG │ future BCI │
└───────────────────────────────┬────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│                       Observation Layer                            │
│ raw measurements + timestamps + quality + device provenance       │
└───────────────────────────────┬────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│                     Calibration Layer                              │
│ personal baseline │ device calibration │ time alignment           │
└───────────────────────────────┬────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│                    Feature / Evidence Layer                        │
│ physiological │ linguistic │ visual │ behavioral │ self-report    │
└───────────────────────────────┬────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│                    State Estimation Layer                          │
│ values + uncertainty + confidence + source attribution            │
└───────────────────────────────┬────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│                           TAOSS                                    │
│ KNO │ INT │ EMO │ CTX │ SEN │ TEM                                 │
│ 240 │ 64  │ 64  │ 64  │ 64  │ 16                                  │
└───────────────────────────────┬────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│                 Ontology + Semantic Bindings                       │
│ anchors │ vocabulary │ relations │ registry │ versions             │
└───────────────────────────────┬────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│               Consent / Privacy / Provenance                       │
│ masking │ capabilities │ revocation │ DP │ audit                   │
└───────────────────────────────┬────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│                      ESP Application Protocol                      │
│ V13 wire envelope │ sessions │ bundles │ control messages          │
└───────────────────────────────┬────────────────────────────────────┘
                                │
                                ▼
┌────────────────────────────────────────────────────────────────────┐
│                   Transport Profile                                │
│ QUIC + TLS 1.3 │ reliable streams │ optional QUIC datagrams        │
└────────────────────────────────────────────────────────────────────┘
```

---

# 7. Die sechs TAOSS-Typen

## 7.1 Knowledge — KNO

Trägt semantisches Wissen:

- Fakten,
- Konzepte,
- Relationen,
- deklarative Inhalte,
- erkannte Objekte und Zustände,
- Hypothesen mit Unsicherheit.

Nicht automatisch:

- persönliche Emotion,
- Ziel,
- Handlungstendenz.

L1-Dimension:

```text
240
```

## 7.2 Intention — INT

Trägt:

- Ziele,
- gewünschte Zustände,
- Planabsichten,
- Handlungsvorbereitung,
- Action Readiness,
- committed intention.

Wichtige interne Unterscheidung:

```text
action_readiness != committed_intention
```

Beispiel:

Eine Person kann einen starken Fluchtimpuls besitzen, ohne beschlossen zu
haben wegzulaufen.

L1-Dimension:

```text
64
```

## 7.3 Emotion — EMO

Trägt:

- affektiven latenten Zustand,
- Anchor-Beziehungen,
- emotionale Intensitäten,
- dimensionsbasierte Beschreibung,
- subjektive Feeling-Metadaten,
- Unsicherheit.

L1-Dimension:

```text
64
```

## 7.4 Context — CTX

Trägt:

- Situation,
- soziale Konstellation,
- Ort,
- Rolle,
- Aufgabenrahmen,
- relevante Umgebungsbedingungen.

L1-Dimension:

```text
64
```

## 7.5 Sensory — SEN

Trägt:

- Wahrnehmungscharakteristik,
- visuelle,
- auditive,
- taktile,
- propriozeptive,
- interozeptive Repräsentationen.

Wichtig:

```text
gemessene Herzrate != wahrgenommenes Herzklopfen
```

Die gemessene Herzrate ist Observation.

Das subjektiv wahrgenommene Herzklopfen kann SEN sein.

L1-Dimension:

```text
64
```

## 7.6 Temporal — TEM

Trägt:

- Phase,
- Rhythmus,
- Kontinuität,
- Verlauf,
- Episodenstruktur,
- Timing.

L1-Dimension:

```text
16
```

---

# 8. Psychologisches Modell von EMO

## 8.1 Ziel

EMO muss zugleich:

- psychologisch nicht naiv,
- maschinenlesbar,
- interoperabel,
- kulturell erweiterbar,
- testbar,
- consent-fähig

sein.

Daher verwendet ESP eine **hybride Repräsentation**.

## 8.2 Vier parallele Repräsentationsebenen

### Ebene A — Subsymbolic Latent

```text
E_EMO ∈ R^64
```

Dies ist die reichhaltigste maschinenlesbare Darstellung.

Sie ist nicht direkt menschlich interpretierbar.

### Ebene B — Ontological Anchor Coordinates

Beispiele:

```text
joy
trust
fear
surprise
sadness
anger
disgust
anticipation
```

Ein Anchor-Wert ist eine Ähnlichkeit oder Projektion auf einen
registry-definierten Referenzpunkt.

Anchor-Koordinaten sind **nicht identisch mit subjektiver Intensität**.

### Ebene C — Descriptive Dimensions

V13 Default:

```text
valence  ∈ [-1, +1]
arousal  ∈ [0, 1]
intensity ∈ [0, 1]
```

Profile dürfen zusätzliche Dimensionen deklarieren, beispielsweise:

```text
dominance/control
predictability
agency
```

Die zusätzlichen Dimensionen sind `V13_COMPATIBLE_ADDENDUM`.

### Ebene D — Named Subjective / Annotated Categories

Beispiel:

```yaml
categories:
  fear:
    intensity: 0.82
    confidence: 0.93
  sadness:
    intensity: 0.64
    confidence: 0.88
  tenderness:
    intensity: 0.55
    confidence: 0.72
```

Mehrere Kategorien dürfen gleichzeitig hohe Werte besitzen.

---

# 9. Intensität, Confidence, Wahrscheinlichkeit und Anchor Similarity

Diese vier Größen dürfen niemals zusammengeworfen werden.

## 9.1 Intensity

```text
0.0 = nicht vorhanden / nicht erlebt
1.0 = für diese Skala maximal stark
```

Die Werte verschiedener Emotionen sind **unabhängig**.

Es gibt keine Summenbedingung.

Erlaubt:

```text
fear = 0.9
sadness = 0.8
anger = 0.7
```

## 9.2 Confidence

Confidence beantwortet:

> Wie sicher ist die Quelle oder das Modell, dass diese Beschreibung korrekt ist?

Beispiel:

```text
fear intensity = 0.90
confidence      = 0.42
```

Das bedeutet:

Starke Angst wird geschätzt, aber die Interpretation ist unsicher.

## 9.3 Model Probability

Wenn ein Klassifikator eine Wahrscheinlichkeit liefert, wird sie separat gespeichert:

```text
model_probability = 0.67
```

Sie ist nicht automatisch Intensität.

## 9.4 Anchor Similarity

```text
anchor_similarity = similarity(E_EMO, anchor)
```

ist eine geometrische Beziehung im latenten Raum.

Auch diese ist nicht automatisch subjektive Intensität.

## 9.5 Optional abgeleitete Komposition

Nur wenn eine Anwendung eine relative Mischung benötigt:

\[
composition_i = intensity_i / \sum_j intensity_j
\]

Diese Komposition ist:

- abgeleitet,
- optional,
- niemals die primäre Speicherung.

---

# 10. Mixed Emotions und Ambivalenz

Das Modell muss folgende Zustände ohne Informationsverlust repräsentieren können:

```text
joy high + sadness high
love high + fear high
relief high + grief high
anger high + attachment high
```

Keine Softmax-Normalisierung über Kategorien.

Keine Winner-Takes-All-Klassifikation.

Keine Verpflichtung, nur eine Emotion auszugeben.

---

# 11. Emotion Episode

Eine Emotion wird nicht nur als Punkt, sondern optional als Episode modelliert.

```yaml
episode:
  id: UUID
  onset_ns: ...
  peak_ns: ...
  end_ns: ...
  rise_time_ms: ...
  decay_half_life_ms: ...
  persistence: 0.74
  volatility: 0.31
  recurrence: 0.44
```

Zeitverläufe werden mit TEM verbunden.

---

# 12. Appraisal-Modell

Psychologisch relevante Appraisals können beispielsweise umfassen:

- novelty,
- unexpectedness,
- intrinsic pleasantness,
- goal relevance,
- goal conduciveness,
- coping potential,
- control,
- self agency,
- other agency,
- norm compatibility.

Diese Information wird **nicht blind vollständig in EMO kopiert**.

Grund:

Ein Appraisal kann Informationen aus Knowledge, Context und Intention enthalten,
die bei Freigabe von EMO nicht automatisch offengelegt werden dürfen.

---

# 13. Semantic Bindings

## 13.1 Motivation

Beispiel:

```text
Emotion: fear
Context: manager
Knowledge: possible dismissal
Intention: keep job
```

Die Beziehung zwischen diesen Elementen ist semantisch wichtig, aber
datenschutzsensitiv.

Daher wird eine relationale Schicht eingeführt.

## 13.2 Datenmodell

```yaml
binding:
  binding_id: UUID
  relation: elicited_by
  source:
    type: EMO
    ref: emotion_episode_17
  target:
    type: KNO
    ref: possible_dismissal
  confidence: 0.84
  provenance: ...
  consent_scope: ...
```

Mögliche Relationsklassen:

```text
elicited_by
directed_at
caused_by
goal_related_to
appraised_as
temporally_follows
temporally_overlaps
sensory_source_of
contextualized_by
supports
contradicts
```

## 13.3 Consent

Bindings sind separat maskierbar.

Damit kann eine Person:

```text
fear teilen
```

ohne:

```text
Grund der Angst teilen
```

zu müssen.

---

# 14. Evidence Model

Jede interpretierte semantische Aussage kann optional auf Evidenz verweisen.

```yaml
evidence_claim:
  id: UUID
  claim_type: emotion_category
  claim: fear
  value: 0.82
  confidence: 0.71
  source_kind: inferred
  estimator_id: esp-emo-fusion-v1
  source_refs:
    - obs_voice_193
    - obs_eda_441
    - self_report_22
  calibration_profile: cal-17
  timestamp_ns: ...
```

`source_kind`:

```text
self_report
human_annotation
sensor_observation
model_inference
derived
synthetic_ground_truth
```

---

# 15. Observation Model

Ein Sensorwert ist ein `Observation`.

```yaml
observation:
  id: UUID
  modality: ecg
  channel: heart_rate
  value: 112
  unit: bpm
  source_device: ...
  timestamp:
    monotonic_ns: ...
    wall_clock_ns: ...
    uncertainty_ns: ...
  quality:
    signal_quality: 0.92
    dropout: false
  calibration_ref: ...
```

Observation ist semantisch neutral.

---

# 16. Personal Calibration

Physiologische Signale variieren stark zwischen Personen.

Daher darf ein Modell nicht ausschließlich absolute Rohwerte interpretieren.

```yaml
calibration_profile:
  id: UUID
  subject_id: pseudonymous
  created_at: ...
  valid_from: ...
  baseline:
    resting_hr:
      median: ...
      mad: ...
    hrv:
      ...
    eda:
      ...
  device_calibrations:
    ...
  model_version: ...
```

Mögliche Features:

```text
raw value
baseline delta
robust z-score
personal percentile
trend
derivative
```

Keine Calibration Information darf still als biometrische Identität missbraucht
werden.

---

# 17. Zeitmodell

Jeder relevante Datensatz benötigt:

```text
source timestamp
monotonic timestamp
clock domain
clock offset estimate
timestamp uncertainty
sequence number
```

Ein gemeinsames Zeitmodell ist essenziell für:

- Audio,
- Video,
- Electroencephalography,
- Electrocardiography,
- Electrodermal Activity,
- Events,
- Self Reports,
- Stimuli.

Für Labordaten wird Lab Streaming Layer unterstützt.

---

# 18. Acquisition Adapter Interface

```python
class ObservationSource(Protocol):
    async def start(self) -> None: ...
    async def read(self) -> list[Observation]: ...
    async def stop(self) -> None: ...
    def metadata(self) -> SourceMetadata: ...
```

Pflichtadapter:

```text
SyntheticObservationSource
ReplayObservationSource
ManualSelfReportSource
TextSource
AudioSource
VideoSource
BrainFlowSource
LSLSource
```

Spätere Adapter:

```text
WearableSource
EyeTrackerSource
EEGSource
FutureBCISource
```

---

# 19. Tests ohne Implantat

## 19.1 Synthetic Ground Truth

Ein Simulator erzeugt bekannte Experience States.

```yaml
episode:
  ground_truth:
    EMO:
      fear:
        intensity: 0.80
    INT:
      avoid:
        intensity: 0.70
```

Er erzeugt dazu künstliche Observations.

Zweck:

- Softwaretests,
- End-to-End-Tests,
- Regression,
- Consent,
- Timing,
- Transport.

Nicht Zweck:

- psychologische Validierung.

## 19.2 Wizard-of-Oz / Manual Ground Truth

Nutzer gibt aktuelle Zustände explizit an.

Beispiel:

```text
fear = 4 / 5
sadness = 2 / 5
avoid tendency = 5 / 5
```

Diese Quelle wird als Self Report markiert.

## 19.3 Replay echter Datensätze

Unterstützte Importziele:

- CSV,
- Parquet,
- European Data Format,
- BrainVision,
- Extensible Data Format,
- Brain Imaging Data Structure-kompatible Metadaten.

## 19.4 Nicht-invasive Sensorik

Tests mit:

- Webcam,
- Mikrofon,
- Phone Motion,
- Heart Rate / Photoplethysmography,
- Electrodermal Activity,
- Respiration,
- Eye Tracking,
- optional Electroencephalography.

---

# 20. State Estimation

## 20.1 Interface

```python
class StateEstimator(Protocol):
    def estimate(
        self,
        observations: Sequence[Observation],
        context: EstimationContext
    ) -> SemanticEstimate:
        ...
```

## 20.2 Pflichtimplementierungen

```text
OracleEstimator
RuleBasedEstimator
LinearEstimator
FusionEstimator
```

Später:

```text
TorchEstimator
SequenceEstimator
PersonalizedEstimator
```

## 20.3 OracleEstimator

Nimmt bekannte Ground Truth entgegen.

Er ist der wichtigste Referenzbaustein für deterministische End-to-End-Tests.

---

# 21. Fusion

Fusion darf Quellenkonflikte nicht unsichtbar machen.

Beispiel:

```yaml
self_report:
  fear: 0.8

voice_model:
  fear: 0.6

physiology_model:
  fear: 0.3
```

Die Rohschätzungen bleiben provenance-behaftet erhalten.

Ein optionaler FusionEstimator erzeugt:

```yaml
fused:
  fear:
    intensity: 0.67
    confidence: 0.72
```

Die konkrete Fusion ist experimentell und versioniert.

---

# 22. TAOSS Encoder

## 22.1 V13 Dimensionen

```text
Knowledge   240
Intention    64
Emotion      64
Context      64
Sensory      64
Temporal     16
----------------
Total       512
```

## 22.2 Kerninvarianten

Für Projektionen:

\[
P_s P_t = 0 \quad s \neq t
\]

und:

\[
\sum_t P_t = I
\]

Blockunterstützung ist exakt disjunkt.

Semantische Unabhängigkeit ist **nicht** dadurch garantiert.

Sie wird empirisch getestet.

## 22.3 Decorrelating Training

Referenzpfad gemäß V13:

- typed task losses,
- covariance penalty,
- adversarial reconstruction,
- gradient reversal,
- held-out leakage audit.

---

# 23. Ontology Registry

## 23.1 Anchor

```yaml
anchor:
  id: "esp:emo:fear:v1"
  type: EMO
  label: fear
  vocabulary_id: "esp-emo-core-v1"
  references:
    - ...
  version: 1
  status: active
```

## 23.2 Encoder Realization

Ein Anchor besitzt keine universell identische Koordinate.

Jeder Encoder registriert eine Realisierung:

```yaml
encoder_realization:
  anchor_id: "esp:emo:fear:v1"
  encoder_id: "encoder-x@1.2.0"
  vector: [...]
  validity_region: ...
  validation_report: ...
```

## 23.3 Registry Regeln

- IDs unveränderlich.
- Semantik einer bestehenden ID darf nicht neu definiert werden.
- Bedeutungsänderung erzeugt neue ID oder neue Major-Version.
- Deprecated Anchors bleiben resolvierbar.
- Registry besitzt kanonische Serialisierung und Digest.

---

# 24. EMO Vocabulary Profiles

Pflichtprofile:

## 24.1 `esp-emo-v13-basic8-v1`

V13-kompatible acht Default-Anker:

```text
joy
trust
fear
surprise
sadness
anger
disgust
anticipation
```

## 24.2 `esp-emo-movie-legacy-v3`

Adapter für das bestehende Movie-ESP.

Beinhaltet unter anderem:

```text
ecstasy
joy
contentment
love
tenderness
warmth
awe
wonder
curiosity
...
```

Wichtig:

Dieses Profil importiert Begriffe, aber nicht die retrieval-spezifische
L1-Summennormierung als psychologisches Modell.

## 24.3 `esp-emo-custom-*`

Registrierte Erweiterungsprofile.

---

# 25. ExperienceFrame

Kanonisches logisches Objekt:

```yaml
experience_frame:
  schema_version: "1.0"
  frame_id: UUID
  timeline_id: UUID
  sequence: 123
  timestamp:
    monotonic_ns: ...
    wall_clock_ns: ...
    uncertainty_ns: ...

  types:
    KNO:
      latent: [...]
      anchors: [...]
    INT:
      latent: [...]
      anchors: [...]
    EMO:
      latent: [...]
      anchors: [...]
      descriptors: ...
    CTX:
      latent: [...]
      anchors: [...]
    SEN:
      latent: [...]
      anchors: [...]
    TEM:
      latent: [...]
      anchors: [...]

  bindings: [...]

  provenance:
    encoder_id: ...
    model_digest: ...
    evidence_refs: [...]

  consent:
    capability_id: ...
```

Dieses Objekt ist die logische Ebene.

Die Wire-Serialisierung ist separat.

---

# 26. V13 Wire Format

Klasse:

```text
V13_NORMATIVE
```

Der feste Header umfasst 100 Byte.

Pflichtfelder:

```text
magic
version_major
version_minor
profile
semantic_fidelity_level
reserved
types_bitmap
consent_flags
privacy_flags
capabilities
timestamp_ns
timeline_id
segment_seq
dt_ms
phase
sender_id
payload_len
nonce
```

Danach:

```text
AEAD ciphertext
16-byte auth tag
64-byte Ed25519 signature
```

---

# 27. Typed Latent TLV Codes

V13 v1:

```text
0x60 Knowledge
0x61 Intention
0x62 Emotion
0x63 Context
0x64 Sensory
0x65 Temporal
```

Control objects sind gemäß V13 Registry zu implementieren.

Unbekannte Codes dürfen nicht still neu interpretiert werden.

---

# 28. Masking Invariant

Für Emotion gilt:

```text
EMO type bit = 1
EMO_MASKED   = 1
```

ist **ungültig**.

Masking bedeutet:

> Der Typ befindet sich nicht im entschlüsselbaren Payload.

UI-Verbergen reicht nicht.

Dieses Prinzip wird für neue maskierbare Companion-Objekte fortgeführt.

---

# 29. Kryptografie

V13-Referenz:

- Noise IK für Session Establishment,
- X25519,
- ChaCha20-Poly1305,
- Ed25519,
- BLAKE2b,
- per-session pseudonymous signing keys,
- strict nonce uniqueness.

Keine eigene Kryptografie erfinden.

## 29.1 Nonce-Invariante

Unter einem Session Key darf niemals dasselbe Nonce für zwei verschiedene
Plaintexts verwendet werden.

Bei verlorenem Sequence State:

```text
session MUST terminate
fresh session MUST be established
```

---

# 30. Transportstrategie

ESP ersetzt nicht TCP.

ESP ist ein Application Protocol.

Referenzstack:

```text
ESP
 ↓
QUIC
 ↓
TLS 1.3 security context
 ↓
UDP / IP
```

QUIC bietet:

- parallele Streams,
- Flow Control,
- Connection Migration,
- geringe Verbindungs-Latenz.

Für Echtzeitdaten kann die QUIC Datagram Extension verwendet werden.

---

# 31. Stream Mapping

## 31.1 Control Stream — zuverlässig

Transportiert:

```text
HELLO
PROFILE_NEGOTIATION
CAPABILITY
CONSENT
REVOCATION
REGISTRY_DIGEST
KEY_ROTATION
SESSION_CLOSE
```

## 31.2 State Stream — zuverlässig oder profilabhängig

Transportiert ExperienceFrames, bei denen Reihenfolge und Zuverlässigkeit
wichtiger als niedrigste Latenz sind.

## 31.3 Real-Time State Datagram — optional

Für hochfrequente Zustände, bei denen ein veralteter Frame keinen Wert mehr hat.

Beispiel:

```text
50 Hz low-latency state update
```

Verlorene Pakete werden nicht zwingend retransmittiert.

## 31.4 Bulk Stream

Für:

- Registry Snapshots,
- Anchor Sets,
- Bundles,
- Benchmark Data,
- Model Metadata.

## 31.5 Emergency Control

PANIC oder Revocation dürfen nicht als unzuverlässige Datagram-Nachricht
implementiert werden.

---

# 32. Session State Machine

```text
DISCONNECTED
    ↓
TRANSPORT_CONNECTING
    ↓
CRYPTO_ESTABLISHED
    ↓
PROFILE_NEGOTIATION
    ↓
CAPABILITY_NEGOTIATION
    ↓
CONSENT_ESTABLISHED
    ↓
ACTIVE
    ├── CONSENT_UPDATE
    ├── REKEY
    ├── PROFILE_DOWNGRADE
    └── REVOCATION
    ↓
CLOSING
    ↓
CLOSED
```

Keine ExperienceFrames vor `CONSENT_ESTABLISHED`.

---

# 33. Consent

Consent ist ein kryptografisch prüfbarer Capability-Zustand.

Er umfasst unter anderem:

- erlaubte Typen,
- Empfänger,
- Gültigkeitszeitraum,
- Replay-Erlaubnis,
- Store-Erlaubnis,
- maximale Segmente,
- Differential-Privacy-Budget.

Receiver Consent ist ebenfalls zu berücksichtigen.

---

# 34. Revocation

Revocation kann mindestens:

- zukünftige Verwendung verbieten,
- Löschen gespeicherter Daten anfordern,
- Löschen abgeleiteter Daten anfordern,
- Session terminieren.

Wichtig:

Ein Löschwunsch ist nicht dasselbe wie kryptografisch beweisbare Löschung.

Deletion Attestation bleibt eine behauptete bzw. attestierte Operation und muss
als solche benannt werden.

---

# 35. Receiver Safety

Der Empfänger definiert:

- erlaubte TAOSS-Typen,
- Normgrenzen,
- Rate Limits,
- gegebenenfalls Valence Bounds,
- maximale Profile.

Nicht autorisierte Frames werden **vor Decoder-Aufruf** verworfen.

---

# 36. Privacy Layers

Getrennt betrachten:

1. Content Confidentiality,
2. Identity Linkability,
3. Type Presence Leakage,
4. Timing Leakage,
5. Cross-Type Semantic Leakage,
6. Training Data Leakage,
7. Endpoint Side Channels.

Keines davon darf mit einem einzelnen Wort wie "encrypted" als gelöst gelten.

---

# 37. Differential Privacy

Differential Privacy wird als eigene optionale Schicht umgesetzt.

Sie darf nicht mit:

- Verschlüsselung,
- Anonymisierung,
- Consent,
- Disentanglement

verwechselt werden.

Privacy Accounting ist reproduzierbar zu implementieren und zu testen.

---

# 38. Cross-Type Leakage Audit

Für jedes gerichtete Paar:

```text
KNO → INT
KNO → EMO
...
TEM → SEN
```

werden Leakage-Probes trainiert.

Zusätzlich:

```text
all visible types → each masked type
```

um synergistische Leakage zu messen.

Bericht:

```text
pairwise leakage matrix
worst pair
joint masked target leakage
baseline comparison
confidence interval
```

---

# 39. ExperienceBench

Mindestens:

1. Typed Retrieval,
2. Intent Transfer,
3. Context Preservation,
4. Temporal Reconstruction,
5. Cross-Type Leakage,
6. Out-of-Distribution Anchor Shift,
7. Encoder Drift,
8. Human Interpretability,
9. Consent Granularity.

Pflichtbaselines entsprechend V13:

- text-only model,
- multimodal embedding,
- monolithic 512-dimensional embedding + fixed post-hoc masking,
- learned selective-privacy baseline,
- TAOSS without adversarial decorrelation.

---

# 40. H1, H2, H3

## H1 — Consent Granularity

TAOSS soll deutlich feinere effektive Consent Policies ermöglichen, ohne
dominierenden Utility-Verlust.

## H2 — Cross-Type Leakage

TAOSS soll empirisch Cross-Type Leakage reduzieren.

Bestätigung erfordert auch einen starken learned privacy comparator.

## H3 — Downstream Utility

Mindestens eine definierte L1-Aufgabe muss gegenüber den erforderlichen
Baselines gewinnen.

Causal Controls:

```text
true latent
zero latent
shuffled latent
moment-matched random latent
```

---

# 41. Datensplit-Regeln

Frames derselben korrelierten Quelle dürfen nicht auf Train und Test verteilt
werden.

Split Unit:

```text
subject
> session/timeline
> source media item
```

je nachdem, welche höchste Ebene verfügbar ist.

Preprocessing wird ausschließlich auf Training Data fitten.

---

# 42. Human Studies

Human-Subject-Experimente sind nicht für die ersten Softwaremeilensteine nötig.

Sobald echte psychologische Validierung durchgeführt wird:

- informierte Einwilligung,
- Ethikfreigabe,
- Recht auf Abbruch,
- Stimulus Screening,
- sichere Datenaufbewahrung,
- klare Trennung von Forschung und klinischer Diagnostik.

Keine medizinischen Claims ohne entsprechende Evidenz und regulatorische Basis.

---

# 43. BCI-freie Hauptdemo

Die erste vollständige Demo verwendet **keine neuronalen Daten**.

Sender:

```text
self-report
manual intent
manual context
synthetic / optional physiological signals
```

Receiver erhält TAOSS über ESP.

**Affect-Scope der Demo (§4.5):** Alle EMO-Werte der BCI-freien Demo sind
`affect_scope=SELF_DECLARED` (Self Report) oder `CONTENT` (Medienszene).
Synthetische physiologische Signale dürfen in M5 **keinen** EMO-Wert
erzeugen; sie speisen nur Observations/Features. Inferierter Subjekt-Affekt
erscheint frühestens in M7 unter Profil L2.

Demonstration:

```text
Sender:
  KNO allowed
  INT allowed
  EMO masked
  CTX allowed

Receiver:
  KNO present
  INT present
  EMO absent
  CTX present
```

Zusätzlich wird ein Leakage Audit ausgeführt.

---

# 44. Physiologie-Demo

Nach erfolgreicher BCI-freier Demo:

```text
BrainFlow Synthetic Board
       ↓
Observation Layer
       ↓
Calibration
       ↓
Feature Extraction
       ↓
State Estimator
       ↓
TAOSS
       ↓
ESP
       ↓
Receiver
```

Danach:

```text
BrainFlow Playback Board
```

mit realen aufgezeichneten Daten.

---

# 45. Lab Streaming Layer

Lab Streaming Layer wird für multimodale Laborsynchronisierung unterstützt.

Gespeichert werden:

- Sample Timestamps,
- Clock Offset Measurements,
- Stream Metadata,
- Timing Uncertainty.

Extensible Data Format wird als bevorzugtes multimodales Replayformat
unterstützt.

---

# 46. BrainFlow

Pflichtintegration zunächst:

```text
Synthetic Board
Playback File Board
Streaming Board
```

Erst danach reale Hardware.

Dadurch kann die gesamte Pipeline ohne Hardware entwickelt werden.

---

# 47. Future Neural Adapter

Interface:

```python
class NeuralObservationSource(ObservationSource):
    ...
```

Es produziert **Observation**, nicht direkt "Thought".

Erste zulässige Features können sein:

- spectral features,
- event-related potentials,
- attention-related features,
- motor imagery features,
- workload-related features.

Nicht zulässig als unqualifizierter Claim:

```text
arbitrary thought decoded
```

---

# 48. Repository-Struktur

```text
Experience-Semantic-Protocol_TAOSS/
│
├── README.md
├── LICENSE                  # AGPL-3.0-or-later (Code-Hauptlizenz, §52a)
├── LICENSES/                # REUSE: AGPL-3.0-or-later, CC-BY-SA-4.0, CC-BY-4.0
├── REUSE.toml               # Pfad → Lizenz-Zuordnung (maschinenprüfbar)
├── NOTICE                   # Pflicht-Namensnennung (AGPL §7(b))
├── TRADEMARKS.md            # Namens- und Konformitätssiegel-Richtlinie (AGPL §7(e))
├── PATENTS.md               # Patent-Nichtangriffszusage (ADR-0006, PROPOSED)
├── CITATION.cff
├── SECURITY.md
├── CONTRIBUTING.md
├── CHANGELOG.md
├── pyproject.toml
├── Makefile
│
├── docs/
│   ├── MASTER_IMPLEMENTATION_PLAN.md
│   ├── ARCHITECTURE.md
│   ├── PSYCHOLOGY_MODEL.md
│   ├── WIRE_PROTOCOL.md
│   ├── TRANSPORT.md
│   ├── SECURITY_MODEL.md
│   ├── CONSENT.md
│   ├── TESTING.md
│   ├── EXPERIENCEBENCH.md
│   ├── IMPLEMENTATION_STATUS.md
│   ├── LICENSING.md
│   ├── REGULATORY.md            # EU AI Act / GDPR Mapping (WP-078)
│   ├── WHAT_ESP_IS_NOT.md
│   ├── companion/               # Companion Specs, die V13-Lücken schließen (§52b)
│   │   ├── CS-SESSION-CONTROL.md
│   │   ├── CS-ADDENDUM-TLV.md
│   │   ├── CS-ANCHOR-COORDS.md
│   │   ├── CS-NONCE-DERIVATION.md
│   │   ├── CS-DECODER.md
│   │   └── ...
│   ├── errata/
│   │   └── V13-ERRATA.md        # Rückmeldungen an die Spec (V13.1)
│   └── decisions/
│       └── ADR-0001-...
│
├── schemas/
│   ├── observation.schema.json
│   ├── evidence_claim.schema.json
│   ├── experience_frame.schema.json
│   ├── semantic_binding.schema.json
│   ├── anchor.schema.json
│   ├── registry.schema.json
│   ├── calibration.schema.json
│   └── consent.schema.json
│
├── src/esp/
│   ├── core/
│   ├── observation/
│   ├── evidence/
│   ├── calibration/
│   ├── ontology/
│   ├── taoss/
│   ├── estimators/
│   ├── simulation/
│   ├── codec/
│   ├── crypto/
│   ├── session/
│   ├── transport/
│   ├── consent/
│   ├── privacy/
│   ├── adapters/
│   │   ├── brainflow/
│   │   ├── lsl/
│   │   ├── replay/
│   │   └── self_report/
│   └── cli/
│
├── ontology/
│   ├── registries/
│   ├── emo/
│   ├── int/
│   ├── ctx/
│   ├── sen/
│   ├── tem/
│   └── legacy_movie/
│
├── tests/
│   ├── unit/
│   ├── property/
│   ├── integration/
│   ├── conformance/
│   ├── interoperability/
│   ├── security/
│   ├── fuzz/
│   ├── regression/
│   └── milestone/
│
├── vectors/
│   ├── wire/
│   ├── crypto/
│   ├── consent/
│   ├── ontology/
│   └── malformed/
│
├── benchmarks/
│   ├── experiencebench/
│   ├── latency/
│   ├── bandwidth/
│   └── leakage/
│
├── examples/
│   ├── synthetic_sender_receiver/
│   ├── consent_masking/
│   ├── physiology_replay/
│   └── lsl_multistream/
│
├── scripts/
│   ├── verify_plan_sync.py
│   ├── run_milestone.py
│   ├── generate_test_vectors.py
│   └── benchmark.py
│
└── artifacts/
    └── test-reports/
```

---

# 49. Coding Standards

Referenzsprache:

```text
Python 3.12+
```

Zweite unabhängige Implementierung später:

```text
Rust
```

Python Tooling:

```text
pytest
hypothesis
ruff
mypy
coverage
```

Keine untypisierten Public APIs ohne Begründung.

Keine versteckten globalen Zustände für:

- Session Sequence,
- Nonces,
- Consent,
- Calibration.

---

# 50. Reproduzierbarkeit

Jeder Benchmark Run speichert:

```text
git commit
config digest
model digest
dataset digest
random seeds
hardware
software versions
command line
timestamp
```

---

# 51. Masterplan-Synchronisierung

`scripts/verify_plan_sync.py` muss mindestens prüfen:

1. jedes Arbeitspaket besitzt Status;
2. jedes `VERIFIED` Arbeitspaket besitzt Testreferenz;
3. jeder abgeschlossene Meilenstein besitzt Testreport;
4. jede registrierte Abweichung besitzt ADR;
5. Wire-Versionen stimmen zwischen Code, Schema und Dokumentation überein;
6. Ontology Registry Digests sind aktuell;
7. keine TODO-Markierung in einem `VERIFIED` Paket verbleibt.

CI darf bei Inkonsistenz fehlschlagen.

---

# 52. Standardbefehle

Das Repository soll folgende Befehle bereitstellen:

```bash
make setup
make lint
make typecheck
make unit
make integration
make property
make security
make fuzz-smoke
make conformance
make benchmark-smoke
make verify-plan
make verify
```

`make verify` ist die lokale Gesamtprüfung vor einem Pull Request.

---

# 52a. Lizenz, Governance und Offenheit des Kerns

Klasse: `PROJECT_NORMATIVE` (ADR-0005, ADR-0006, ADR-0007).

> Hinweis: Dieses Kapitel ist eine technische Lizenzarchitektur, keine
> Rechtsberatung. Vor v1.0 (WP-047) ist eine anwaltliche Prüfung Pflicht
> (WP-084).

## 52a.1 Ziel

1. **Der Kern bleibt für immer frei** — auch wenn Dritte ihn kommerziell
   nutzen, verändern, als Dienst betreiben oder in Produkte einbauen.
2. **Namensnennung ist Pflicht** — Urheber und Projekt müssen in jeder
   Weitergabe und jeder Nutzeroberfläche sichtbar bleiben.
3. **Kommerzielle Nutzung ist ausdrücklich erlaubt** — Produkte, Dienste,
   Hardware, Beratung, Zertifizierung.
4. **Das Protokoll bleibt ein offener Standard** — jede Person darf ESP
   unabhängig nach der Spezifikation implementieren.
5. **Niemand kann den Kern nachträglich proprietär machen** — auch Vigilant
   selbst nicht.

## 52a.2 Lizenzmatrix

| Bereich | Pfade | Lizenz | Begründung |
|---|---|---|---|
| Referenzimplementierung (Kern) | `src/**`, `rust/**`, `scripts/**`, `benchmarks/**`, `examples/**`, `tests/**` | **AGPL-3.0-or-later** | starkes Copyleft inkl. Netzwerkklausel (§13): Wer den veränderten Kern als Dienst betreibt, muss den Quellcode den Nutzern anbieten. |
| Spezifikation, Companion Specs, Doku | `docs/**`, `spec/**` | **CC BY-SA 4.0** | Namensnennung + Weitergabe unter gleichen Bedingungen; abgeleitete Spezifikationen bleiben offen. |
| Ontologie, Anker-Sets, Vokabulare | `ontology/**` | **CC BY-SA 4.0** | Anker-Inventare sind Gemeingut des Standards; Forks bleiben offen. |
| Testvektoren, JSON-Schemas, Registry-Snapshots | `vectors/**`, `schemas/**` | **CC BY 4.0** | Interoperabilität: auch unabhängige (ggf. proprietäre) Implementierungen müssen gegen dieselben Vektoren testen können; Namensnennung bleibt Pflicht. |
| Namen und Siegel | „Experience Semantic Protocol“, „TAOSS“, „ESP-Conformant“ | **Markenrichtlinie** (`TRADEMARKS.md`) | Verhindert, dass nicht konforme Forks sich als ESP ausgeben. |

Die Zuordnung ist maschinenlesbar in `REUSE.toml` hinterlegt (REUSE-Spec 3.x)
und wird von CI mit `reuse lint` geprüft.

## 52a.3 Mechanismen, die „Kern bleibt frei“ tragen

1. **AGPL-3.0-or-later statt MPL/Apache:** Änderungen am Kern müssen auch
   bei SaaS-Betrieb offengelegt werden (§13). Wer den Kern als Bibliothek in
   sein Programm einbindet, gibt das Gesamtwerk unter AGPL weiter.
2. **DCO statt CLA:** Beiträge werden per `Signed-off-by` (Developer
   Certificate of Origin 1.1) eingebracht. Es gibt **keine
   Rechteübertragung** an Vigilant. Damit kann niemand — auch nicht der
   Maintainer — die Codebasis ohne Zustimmung aller Mitwirkenden proprietär
   umlizenzieren (ADR-0005).
3. **Pflicht-Namensnennung via AGPL §7(b):** Die Datei `NOTICE` ist ein
   zusätzlicher Begriff nach §7(b): Die dort genannten Urheber- und
   Projekthinweise müssen in Quelltext, Binärverteilungen und in den
   „Appropriate Legal Notices“ jeder interaktiven Oberfläche erhalten
   bleiben.
4. **Markenschutz via AGPL §7(e):** Die Lizenz gewährt keine Rechte an den
   Namen. `TRADEMARKS.md` erlaubt die Bezeichnung „ESP-Conformant“ nur für
   Implementierungen, die die öffentliche Conformance-Suite (WP-039) mit
   veröffentlichtem Report bestehen.
5. **Patent-Nichtangriffszusage (`PATENTS.md`, ADR-0006, PROPOSED):**
   Vigilant verpflichtet sich, keine eigenen Patente gegen konforme
   Implementierungen der Spezifikation durchzusetzen (Muster:
   W3C-Royalty-Free-Policy). Zusätzlich greift die Patentlizenz aus
   AGPL-3.0 §11 für den Code.
6. **Offene Spezifikation:** Die Spezifikation ist CC BY-SA; die
   Implementierung eines Protokolls nach Spezifikation ist kein abgeleitetes
   Werk des Codes. Unabhängige Clean-Room-Implementierungen sind zulässig und
   erwünscht (WP-040 ist selbst eine davon).

## 52a.4 Was kommerziell erlaubt ist

| Szenario | Erlaubt? | Pflicht |
|---|---|---|
| Kern unverändert in eigenem Dienst betreiben | ja | NOTICE anzeigen; Quelle des Kerns anbieten |
| Kern verändert als Dienst betreiben | ja | geänderten Kern-Quelltext Nutzern anbieten (AGPL §13) |
| Kern als Bibliothek in eigenes Produkt einbinden | ja | Gesamtwerk unter AGPL weitergeben |
| Eigenes, separates Programm, das nur **über das ESP-Protokoll** mit einem AGPL-Kern spricht | ja | keine Copyleft-Pflicht für das separate Programm (Kommunikation über Wire-Protokoll) |
| Eigene unabhängige Implementierung nach Spezifikation | ja | Namensnennung Spec (CC BY-SA); „ESP-Conformant“ nur nach bestandener Conformance-Suite |
| Hardware, Sensorik, Beratung, Zertifizierung, Hosting | ja | — |
| Proprietäre Version **des Kerns** | **nein** | — |

## 52a.5 Pflichtartefakte

```text
LICENSE                          AGPL-3.0-or-later (Volltext)
LICENSES/AGPL-3.0-or-later.txt
LICENSES/CC-BY-SA-4.0.txt
LICENSES/CC-BY-4.0.txt
REUSE.toml                       Pfad → Lizenz
NOTICE                           Pflicht-Namensnennung (§7(b))
TRADEMARKS.md                    Namen, Siegel, Konformitätsbedingungen (§7(e))
PATENTS.md                       Patent-Nichtangriffszusage (PROPOSED)
CONTRIBUTING.md                  DCO 1.1, kein CLA
docs/LICENSING.md                diese Matrix + FAQ „darf ich kommerziell …?“
```

Jede Quelldatei beginnt mit:

```text
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: AGPL-3.0-or-later
```

---

# 52b. V13-Lückenregister (Gap Register)

Klasse: `V13_COMPATIBLE_ADDENDUM`, sofern nicht anders angegeben.

Jede Lücke ist eine Stelle, an der V13 nicht byte-genau, nicht deterministisch
oder nicht vollständig genug ist, um sie ohne Designentscheidung zu
implementieren — oder an der der Plan v0.1.0 V13 widersprach. Jede Lücke
bekommt: Companion Spec (CS) oder ADR, betroffene WPs und einen Errata-Eintrag
an die Spezifikation (`docs/errata/V13-ERRATA.md`, WP-085).

**Regel:** Kein WP, das eine offene Lücke berührt, darf `VERIFIED` werden,
bevor die Lücke `RESOLVED` ist.

| ID | Lücke | V13-Stelle | Schwere | Auflösung | WPs | Status |
|---|---|---|---|---|---|---|
| GAP-001 | Plan v0.1.0 verwechselte L1-Content-Affect mit Subject-Affect (Self-Report-Demo, Physiologie → EMO). | §6.4 Affect-Box, §15, §23 | **kritisch** | §4.5 `affect_scope`; ADR-0008 | WP-004, WP-025, WP-030, WP-078 | RESOLVED_IN_PLAN |
| GAP-002 | Exakte Nonce-Ableitung („HKDF-derived … timeline_id‖segment_seq“) ohne KDF, Salt, Info, Länge. 16+4 Byte Eingang vs. 12 Byte Nonce. | §Crypto, App. A | hoch | CS-NONCE-DERIVATION: `nonce = BLAKE2b-96(key=k_nonce, "esp/v1/nonce" ‖ timeline_id ‖ segment_seq_be32)`, `k_nonce` aus Noise-Split via HKDF-BLAKE2b, `info="esp/v1/nonce-key"`. Empfänger liest Nonce aus Header, prüft aber im deterministischen Profil Gleichheit. ADR-0009 | WP-016, WP-017 | RESOLVED |
| GAP-003 | Semantik von `payload_len`: Ciphertext mit oder ohne Tag? | App. A | hoch | V13 §L2–L3 Wire-Rate-Rechnung (448+65+180) impliziert: **ohne** Tag und ohne Signatur. ADR-0010 fixiert `payload_len = len(ciphertext)`; Tag (16) und Signatur (64) folgen fest. | WP-014 | RESOLVED |
| GAP-004 | Addendum-Objekte (Bindings, Evidence Claims, Deskriptoren, `affect_scope`, Episoden) haben keinen Wire-Code; V13 erlaubt freie Codes nur über registry-gepinntes Profil. | §Typed TLV Registry | hoch | CS-ADDENDUM-TLV: Profil `esp-addendum-v1`, per `TLV_TYPE_PROFILE (0x11)` mit `registry_digest` angemeldet; Codes `0x80`–`0x9F` (ADR-0011). Unbekannte → ignorieren, nie uminterpretieren. ADR-0011 | WP-005, WP-011, WP-049 | RESOLVED |
| GAP-005 | Control-Nachrichten (HELLO, PROFILE_NEGOTIATION, REGISTRY_DIGEST, KEY_ROTATION, SESSION_CLOSE) und „session descriptor“ (Replay-Fenster, Raten, DP-Profil, Registry-Versionen) ohne Wire-Format. | §Replay, §DP-TLV, §Hive-Lifecycle | hoch | CS-SESSION-CONTROL: Session-Descriptor als kanonisches Objekt im Noise-Payload + Control-TLVs im Addendum-Profil. ADR-0012 | WP-024, WP-048 | RESOLVED |
| GAP-006 | Format der Cross-Signatur „Responder publishes X25519 static key cross-signed with Ed25519“ und Bindung `sender_id` ↔ Noise-Session unspezifiziert. | §Identity Binding | hoch | CS-SESSION-CONTROL §Identity: `sig = Ed25519(sk_R, "esp/v1/static-binding" ‖ x25519_pk ‖ valid_until_ns)`; `sender_id`-Bindung über `noise_h` im Identity Proof (0x20). ADR-0013 | WP-018, WP-052 | RESOLVED |
| GAP-007 | `TLV_ANCHOR_COORDS (0x50)` nur mit Verweis auf „Anchor Coordinate Companion Specification“, kein Layout. | §Ontology Grounding | mittel | CS-ANCHOR-COORDS: `type_code u8 ‖ anchor_set_id[16] ‖ similarity_kind u8 ‖ m u16 ‖ float32_be[m]`. ADR-0014 | WP-050 | OPEN |
| GAP-008 | Kanonische Serialisierung für ReceiverCapability: variable Arrays (`max_norm[n_types]`, `valence_bounds` „if EMO accepted“) — Weglassen oder Nullen? | §Receiver Capabilities, §Consent | mittel | V13 §Consent: „field is omitted from the canonical capability“ → `valence_bounds` nur bei EMO-Bit; Golden Vectors für beide Fälle. ADR-0015 | WP-051 | RESOLVED |
| GAP-009 | Wrap/Erschöpfung von `segment_seq` (u32) nicht geregelt. | App. A, App. C „sequence wrap“ | mittel | Sender MUSS die Session vor `2^32−1` beenden und neu aufbauen; Empfänger lehnt Wrap ab. ADR-0016 | WP-017 | RESOLVED |
| GAP-010 | Transport: V13 kennt kein QUIC; Plan wählt QUIC + Noise IK (Doppelverschlüsselung). | §Wire | niedrig | ADR-0001 bestätigt: Transport-Abstraktion; In-Memory- und TCP-Transport für M3/M4-Tests, QUIC (aioquic) als Referenzadapter. Noise-IK bleibt Ende-zu-Ende-Schicht unabhängig vom Transport-TLS. | WP-023 | RESOLVED |
| GAP-011 | Bits 0–11 im Feld `capabilities` („I2I and feature flags“) nicht einzeln belegt. | App. A | mittel | Alle v1-Bits 0–14 MUST zero, bis ein Registry-Eintrag sie belegt; Erweiterungen über `TLV_CAPABILITIES_EXT (0x10)`. ADR-0017 | WP-014, WP-061 | RESOLVED |
| GAP-012 | Referenzparameter der DP-Profile (`L1_BALANCED_REF` σ≈24.42, `L1_PRIVATE_REF` σ≈122.13 bei C=1, δ=10⁻⁶?) über mehrere Absätze verteilt, δ und α-Gitter nicht als Tabelle. | §DP | mittel | Registry-Eintrag `esp-dp-ref-v1` mit C, σ, δ, α-Gitter, Accountant; Golden Vectors für ε. ADR-0018 | WP-055 | RESOLVED |
| GAP-013 | `Δ_clock` (Uhrentoleranz im Accept-Prädikat) ohne Default. | §Consent Accept | mittel | Profil-Default 2 s (L1), 250 ms (I2I). ADR-0019 | WP-019 | RESOLVED |
| GAP-014 | Fehlercodes (z. B. `ESP_DECODER_POLICY_FAILED`) werden genannt, aber es gibt kein Fehlercode-Register. | §Decoder | mittel | CS-DECODER + `src/esp/core/errors.py` Register mit stabilen numerischen Codes. ADR-0020 | WP-059 | OPEN |
| GAP-015 | TEM-Pattern-Constraints („forbidden codebook patterns“) und Gating-Sparsity-Band nicht parametrisiert. | §Covert Channel | mittel | Profil-Parameter in `esp-covert-hardening-v1`, Defaults per Experiment (WP-057) ermittelt, danach eingefroren. | WP-057 | OPEN |
| GAP-016 | „Replay-pattern watermarking … vendor-side watermark TLVs“ ohne TLV-Code. | §Covert Channel | niedrig | Addendum-Profil-Code; bis dahin `DEFERRED`. | WP-057 | OPEN |
| GAP-017 | Secure-Aggregation, MLS-Profil, anonyme Credentials, DKG für FROST explizit an Companion-Profile delegiert. | §Typed Hive | mittel | Referenzwahl ADR-0021: MLS (RFC 9420) via OpenMLS/Bindings, FROST (RFC 9591) via `frost-ed25519`, Secure Aggregation nach Bonawitz et al. als Simulator zuerst. | WP-070 | OPEN |
| GAP-018 | XCF `GATED_CEK`: Gate-Protokoll, Guardian-Quorum und `access_material`-Layout nicht spezifiziert. | §XCF | mittel | CS-XCF-GATE, Referenz-Gate-Service (lokal) + Threshold-Variante. ADR-0022 | WP-068 | OPEN |
| GAP-019 | Transparenzlog für Key-Rotation/DP-Ledger (RFC 9162-artig) ohne Profil. | §Forward Secrecy, §Consent | mittel | Referenz: lokaler Merkle-Log nach RFC 9162-Struktur + Witness-Signaturen; externer Betrieb später. ADR-0023 | WP-053 | OPEN |
| GAP-020 | Repository-Rollen: V13 nennt das Movie-Engine-Repo „official implementation repository“; TAOSS-Repo ist dort nicht genannt. | Präambel, §L1, §V12→V13 | niedrig | V13-Errata: TAOSS-Repo als „reference implementation (wire/conformance)“ eintragen. | WP-085 | OPEN |
| GAP-021 | Emotionstheorie-Pluralismus des Plans (Kategorien, Appraisal, Episode) geht über V13-Default (8 Anker + V/A/I) hinaus. | §6.4 EMO-Struktur | niedrig | bleibt `V13_COMPATIBLE_ADDENDUM`; nie im V13-Default-Profil Pflicht. | WP-004 | RESOLVED_IN_PLAN |
| GAP-022 | Decoder-Referenz-Companion „planned“: keine Referenzarchitektur, aber Pflichten (⊥-Handling, Policy pro Typ). | §Decoder | mittel | CS-DECODER + Referenz-Renderer (Text, Vektor, Visualisierung). | WP-059 | OPEN |
| GAP-023 | ExperienceBench-Korpora: V13 nennt Aufgaben, aber keine Datensätze/Lizenzen. | §ExperienceBench | hoch (für H1–H3) | Datensatz-Register mit Lizenzprüfung; Smoke-Korpus synthetisch; echte Korpora nur mit geklärter Lizenz. ADR-0024 | WP-034 … WP-037, WP-083 | OPEN |
| GAP-024 | Hybrid-PQ-Profil: V13 verlangt Deklaration classical-only vs. hybrid, aber kein Feld. | §Crypto PQ | niedrig | Session-Descriptor-Feld `pq_mode ∈ {CLASSICAL_ONLY, HYBRID_OUTER, HYBRID_NOISE}`; v1 = CLASSICAL_ONLY, nie als PQ beworben. | WP-048, WP-075 | OPEN |
| GAP-025 | V13 §7.6 sagt, die ReceiverCapability stehe im ersten Responder-Handshake-Payload, bindet sie aber an `noise_h`. Der finale Transkript-Hash deckt genau dieses Payload ab (zirkulär). Gleiches gilt für Identity Proof und Session-Binding. | §7.6, §9.4 | hoch | ADR-0013 Amendment: Übertragung in der jeweils ersten Noise-Transportnachricht nach dem Handshake, vor jedem ESP-Anwendungspaket | WP-018, WP-051, WP-052 | RESOLVED |
| GAP-026 | `noise_h[32]` in 0x20/0x21 vs. 64-Byte-Handshake-Hash von `Noise_IK_25519_ChaChaPoly_BLAKE2b` (HASHLEN = 64). | §9.4, §7.6 | hoch | ADR-0013 Amendment: `noise_h = BLAKE2b-256("esp/v1/noise-h" ‖ h)` | WP-018, WP-051, WP-052 | RESOLVED |
| GAP-027 | SF-Level: V13 nennt Pflicht- und Optionaltypen, sagt aber nicht, ob sie pro Paket gelten und welchen `sf_level` Custom-Typ-Sets (MEB-HANDOVER ohne KNO) tragen. | §8.6, §17 | mittel | ADR-0025: strikt pro Paket; Custom-Sets registriert, `sf_level=0` | WP-063, WP-066 | RESOLVED |
| GAP-028 | SOS: "1-bit INT shortcut without EMO/KNO" ohne Kodierung. | §16 | niedrig | ADR-0026 (PROPOSED): Addendum-TLV 0x86 = 0x01 auf CONTROL | WP-064 | RESOLVED_IN_IMPLEMENTATION |
| GAP-029 | Constant-Bitmap/Dummy-Inhalte ohne Kodierung: Empfänger kann Dummies nicht von echten Inhalten unterscheiden; `EMO_MASKED` im Klartext leakt selbst. | §8.3 | mittel | ADR-0027 (PROPOSED): Registry-Profil `esp-metadata-protection-v1`, TLV 0x87 (dummy/mask bitmaps im AEAD), 0x88 Filler | WP-062 | RESOLVED_IN_IMPLEMENTATION |
| GAP-030 | `EmotionEpisode` trägt kein `affect_scope` (M1-Gate verlangt es für alle EMO-Objekte). | §6.4, Plan §4.5 | mittel | Mitigation (WP-078): unter einer Regulatory Declaration nur zusammen mit einem Affect-Descriptor im selben EMO-Block zulässig; Feld `affect_scope` am Episode-Objekt noch offen (Schema-/Vektor-Änderung) | WP-078, WP-050 | OPEN |

---

# 52c. V13-Abdeckungsmatrix

Jeder V13-Abschnitt mit implementierbarem Gehalt ist einem WP zugeordnet.
`verify_plan_sync.py` (WP-000/§51) prüft, dass jede Zeile ein existierendes WP
referenziert.

| V13-Abschnitt | Inhalt | WPs | Ausbaustufe |
|---|---|---|---|
| §3 Scope, L1→L∞ Staging | Profile L1…L∞ | WP-063 | v1 |
| §5.1 TAOSS Definition | Blöcke, Projektionen | WP-007 | v1 |
| §5.3 Type Discovery Frontier | K∈{3…12}, V-Leak-Frontier | WP-074 | Research |
| §5.4 Ontology Grounding | Anchor Identity/Realization, π_t | WP-008, WP-009, WP-050, WP-077 | v1 |
| §6 Encoder, Objectives | Heads, Loss, Stabilität | WP-031, WP-032, WP-073 | v1-exp |
| §6.4 Affect Content-Side | Grenze, g_audio/g_face/g_text | §4.5, WP-079 | v1 |
| §7 Decoder Side | ⊥ vs 0, Policies, Kompatibilität, Renderer | WP-059 | v1 |
| §7.5 Receiver Threats T13–T19 | Norm-Caps, Rate, Provenance, Inversion-Audit | WP-060, WP-054, WP-058 | v1 |
| §7.6 Receiver Capabilities | 0x21, Default-Deny, Enforcement-Klassen | WP-051 | v1 |
| §8 Wire Header | 100 Byte | WP-014 | v1 |
| §8.4 Typed TLV + Quantisierung | 0x60–0x65, F32/F16/INT8_SYM | WP-015, WP-056 | v1 |
| §8.4 Control TLVs | 0x10, 0x11, 0x20–0x24, 0x30, 0x40–0x42, 0x50–0x52 | WP-016 … WP-020, WP-050 … WP-055, WP-061, WP-064, WP-068 | v1 |
| §8.5 Capabilities Ext | 0x10 | WP-061 | v1 |
| §8.6 SF-Level | SF0…SF7 | WP-063 | v1 |
| §8.7 Bundle Mode | 0x01 | WP-061 | v1 |
| §8.3 Metadata-Leak-Mitigation | Constant Bitmap, Decoy, Onion | WP-062 | v1 |
| §9.1 Threat Model | T1…T19 | WP-044, WP-080 | v1 |
| §9.2 Crypto | Noise IK, AEAD-AAD=Header, Signatur | WP-016 | v1 |
| §9.3/9.4 Identity, Unlinkability | Session-Pseudonyme, 0x20, Timeline-Rotation | WP-018, WP-052 | v1 |
| §9.5 Adaptive Replay Window | W_back/W_fwd-Formeln | WP-065 | v1 |
| §9.6 Forward Secrecy, Key Lifecycle | 0x41, 0x42, Lineage, Custody, Recovery | WP-053 | v1 |
| §9.7 Consent Capability | 0x22, Accept-Prädikat, Ledger | WP-019, WP-051, WP-055 | v1 |
| §9.7 Revocation / Deletion | 0x23, 0x24 | WP-020 | v1 |
| §9.8 Covert Channel Budget | V-Information, Hardening, Pass-Kriterium, temporal | WP-057 | v1-audit |
| §10 Stabilität Fusion (Theorem) | Lipschitz, Spektral-Clip | WP-073 | v1-exp |
| §11 Disentanglement-Konjektur | Audit statt Beweis | WP-033, WP-058 | Research |
| §12 DP typed adjacency | ∼F, ∼S, ∼U, Local DP, Rate, 0x30 | WP-055 | v1 |
| §13 Audit Suite | KSG, MINE, HSIC, dCor, Probes, Bootstrap | WP-058 | v1-audit |
| §14 H1/H2/H3, ExperienceBench | 9 Tasks, Baselines, Präregistrierung | WP-034 … WP-038, WP-083 | Research |
| §15 L1 Use Cases | Retrieval, Director's Cut, Collab-Tools, LLM-Augmentation | WP-079, WP-067 | v1-demo |
| §16 L2–L3 | Decoder Interface Boundary, I2I-Envelopes, Rate-Semantik, Turn/SOS/PANIC | WP-045, WP-063, WP-064 | v1 / FUTURE |
| §17 MEB | T_mach, Adapter, Alignment, Domain-Profile, M2H-Defaults | WP-066 | v1-ext |
| §18 ESP-Agent | Opaque-Latent-Deskriptor, Agenten-Governance | WP-067 | v1-ext |
| §19.1 XCF | 148-Byte-Header, HPKE, GATED_CEK, CID, Tombstones | WP-068 | v2 |
| §19.3 Recall Path | 0x51, NO_REPLAY-Lineage | WP-068 | v2 |
| §19.4 Experience Legacy | Policy-Objekte | WP-071 | FUTURE |
| §20 Typed Hive | 0x70–0x73, Emergenz-Audit, FJ-Update, EMO λ=0 | WP-070 | v2-research |
| §21 Open Problems | OP-Register | §58 | — |
| §22 Failure Modes | Regressionstests pro Failure Mode | WP-080 | v1 |
| §23 Regulatory (EU) | Art. 5(1)(f), Art. 9, DPIA, Regime-Deklaration | WP-078 | v1 |
| §24 Known Limitations | Doku, Claims Ladder | WP-046, §59 | v1 |
| §25 Standardization Path | Registry-Governance, Errata | WP-077, WP-085 | v1 |
| App. A Wire Format | Bit-Belegungen, Mask-Invariante | WP-014, WP-019 | v1 |
| App. B Ref-Impl-Sketch | Encoder-Skeleton | WP-031 | v1-exp |
| App. C Test Vectors | 8 Vektorklassen | WP-021, WP-058, WP-055 | v1 |
| App. E Trust Vector | τ ∈ [0,1]^5, Recall-Admissibility | WP-069 | v2 |

---

# 53. Arbeitspakete

---

## WP-000 — Repository Bootstrap

**Status:** `VERIFIED`

### Ziel

Reproduzierbares Entwicklungsrepository.

### Implementieren

- `pyproject.toml`
- Package `esp`
- Teststruktur
- Ruff
- mypy
- pytest
- Hypothesis
- Coverage
- GitHub Actions
- Makefile
- pre-commit
- deterministische Seeds

### Pflichtdateien

```text
README.md
SECURITY.md
CONTRIBUTING.md          # inkl. DCO-Pflicht (Signed-off-by), kein CLA
LICENSE                  # AGPL-3.0-or-later
LICENSES/*.txt           # alle verwendeten Lizenztexte (REUSE)
REUSE.toml
NOTICE
TRADEMARKS.md
PATENTS.md
docs/MASTER_IMPLEMENTATION_PLAN.md
docs/IMPLEMENTATION_STATUS.md
```

Zusätzliche Abnahme: `reuse lint` grün; jede Quelldatei trägt
`SPDX-License-Identifier` und `SPDX-FileCopyrightText`; CI prüft DCO-Sign-off
jedes Commits.

### Tests

```bash
python -c "import esp; print(esp.__version__)"
make lint
make typecheck
make unit
```

### Abnahme

Fresh clone → install → Tests grün.

---

## WP-001 — Core Types and Validation

**Status:** `VERIFIED`

### Implementieren

- Version types
- UUID wrappers
- timestamps
- confidence
- intensity
- probabilities
- type enums
- provenance
- validation errors

### Unit Tests

- Range checks
- missing required fields
- immutable identifiers
- canonical equality
- serialization roundtrip

### Property Tests

Mindestens 10.000 generierte gültige und ungültige Objekte.

---

## WP-002 — Observation Model

**Status:** `VERIFIED`

### Implementieren

`Observation`, `SignalQuality`, `ClockStamp`, `DeviceMetadata`.

### Tests

- Unit conversions
- invalid values
- dropout flags
- missing clocks
- timestamp ordering
- uncertainty propagation basics

---

## WP-003 — Evidence Claim Model

**Status:** `VERIFIED`

### Implementieren

`EvidenceClaim`, `SourceKind`, estimator provenance, references.

### Tests

- no inference without provenance,
- confidence independent from intensity,
- model probability independent from intensity.

### Golden Test

```text
fear intensity .9 + confidence .4
```

muss verlustfrei roundtrippen.

---

## WP-004 — Psychological Semantic Model

**Status:** `VERIFIED`

### Implementieren

- AffectiveDescriptor
- independent category intensities
- V13 valence/arousal/intensity
- optional additional dimensions
- mixed emotions
- traces
- action-readiness representation
- self report objects

### Kritischer Test

Zwei Zustände mit identischer relativer Mischung, aber unterschiedlicher
absoluter Intensität dürfen nach Roundtrip **nicht identisch** sein.

### Testfall

State A:

```text
fear=.8 sadness=.7 tenderness=.6
```

State B:

```text
fear=.2 sadness=.175 tenderness=.15
```

Erwartung:

```text
A != B
```

---

## WP-005 — Semantic Bindings

**Status:** `VERIFIED`

### Implementieren

- relation registry,
- typed endpoints,
- confidence,
- provenance,
- consent scope.

### Kritischer Privacy Test

EMO darf übertragen werden, während:

```text
elicited_by -> KNO
```

maskiert wird.

Empfänger darf dann Emotion, aber nicht Ursache rekonstruierbar im
Protokollobjekt erhalten.

---

## WP-006 — Calibration Model

**Status:** `VERIFIED`

### Implementieren

- subject pseudonym,
- personal baselines,
- device calibration,
- robust statistics,
- validity interval.

### Tests

- versioning,
- baseline updates,
- expired calibration,
- deterministic feature transform.

---

## WP-007 — TAOSS Block Model

**Status:** `VERIFIED`

### Implementieren

V13-Dimensionen und Blocklayout.

### Property Tests

\[
P_s P_t = 0
\]

für alle `s != t`.

\[
sum(P_t) = I
\]

### Roundtrip

```text
compose(split(x)) == x
```

innerhalb numerischer Toleranz.

---

## WP-008 — Ontology Registry Core

**Status:** `VERIFIED`

### Implementieren

- Anchor
- AnchorSet
- Vocabulary
- EncoderRealization
- ValidityRegion
- deprecation
- aliases
- canonical registry digest

### Tests

- duplicate IDs rejected,
- semantic mutation requires version bump,
- deterministic digest,
- deprecated anchor resolvable.

### Präzisierung (v0.2.1, kompatibel mit §23.3)

- Labels und Aliase müssen nur unter **aktiven** Ankern eines Vokabulars
  eindeutig sein. Eine neue Major-Version (`…:v2`) setzt voraus, dass `…:v1`
  deprecated ist; `…:v1` bleibt per ID auflösbar, Label-Auflösung liefert v2.
- Logisches JSON serialisiert TAOSS-Typen per Name (`"EMO"`), nie per Bitnummer.
- Registry-Snapshots sind nach ID sortiert; die V13-Reihenfolge eines
  Anker-Sets lebt ausschließlich im `AnchorSet`.

---

## WP-009 — V13 Emotion Anchor Profile

**Status:** `VERIFIED`

### Implementieren

`esp-emo-v13-basic8-v1`.

### Tests

- exactly eight canonical IDs,
- stable ordering,
- registry digest fixed by golden vector.

---

## WP-010 — Legacy Movie Ontology Adapter

**Status:** `VERIFIED`

### Quelle

Bestehendes Emotional-Movie-Search-Engine-Repository:

```text
https://github.com/Vigilant-CRS/Experience-Semantic-Protocol_Emotional-Movie-Search-Engine
```

V13 (§L1, §V12→V13) nennt dieses Repository die **erste L1-Implementierung**
und den offiziellen Implementierungs-Track. Das TAOSS-Repository ist die
**Referenzimplementierung (Wire/Conformance)** desselben Tracks (GAP-020).
Importierte Werte sind `affect_scope=CONTENT` (§4.5).

### Implementieren

- Import emotions,
- impact tags,
- synonyms,
- mappings,
- source version metadata.

### Verbot

Keine automatische Übernahme von:

```text
emotion_sparse L1 = 1
```

in menschliche AffectiveState-Intensitäten.

### Tests

- all legacy tags resolve,
- mapping reproducible,
- retrieval normalization clearly isolated.

---

## WP-011 — ExperienceFrame

**Status:** `VERIFIED`

### Implementieren

Gesamtobjekt inkl.:

- TAOSS types,
- descriptors,
- bindings,
- provenance,
- consent reference,
- timestamps.

### Tests

- canonical serialization,
- schema validation,
- missing type handling,
- masked type omission.

---

## WP-012 — Synthetic Experience Simulator

**Status:** `VERIFIED`

### DSL

YAML-basierte Episoden.

### Implementieren

- timeline,
- ground truth,
- observations,
- noise,
- dropout,
- clock drift,
- expected TAOSS state.

### Tests

- deterministic seed,
- reproducible episode,
- exact oracle target.

---

## WP-013 — State Estimator Interfaces

**Status:** `VERIFIED`

### Implementieren

- OracleEstimator
- RuleBasedEstimator
- FusionEstimator interface

### Tests

Oracle muss bekannte Ground Truth exakt reproduzieren.

---

## WP-014 — V13 Wire Header Codec

**Status:** `VERIFIED`

### Implementieren

Byte-exakt 100 Byte.

### Golden Vectors

Mindestens:

- minimal packet,
- all types,
- EMO masked,
- invalid reserved bit,
- max lengths.

### Tests

```text
encode(decode(bytes)) == bytes
```

für kanonische Pakete.

---

## WP-015 — TLV Codec

**Status:** `VERIFIED`

### Implementieren

V13 Typcodes und Control TLVs.

### Tests

- unknown TLV handling,
- truncated TLV,
- duplicate forbidden TLV,
- length overflow,
- endianness,
- float canonicalization.

---

## WP-016 — Cryptographic Envelope

**Status:** `VERIFIED`

### Implementieren

- ChaCha20-Poly1305,
- Ed25519,
- BLAKE2b,
- canonical signed objects,
- Noise IK integration.

### Tests

- official/library vectors where available,
- project golden vectors,
- tamper detection,
- wrong signature,
- wrong associated data.

### Critical Test

Header modification MUST fail authentication.

---

## WP-017 — Nonce and Replay State

**Status:** `VERIFIED`

### Implementieren

- deterministic or random nonce profile,
- sequence persistence,
- replay window,
- crash-state fail closed.

### Tests

- duplicate nonce rejected,
- same sequence + modified plaintext forbidden,
- retransmission uses identical ciphertext,
- lost sequence state terminates session,
- replay edge conditions.

---

## WP-018 — Session Pseudonymous Identity

**Status:** `VERIFIED`

### Implementieren

- master identity abstraction,
- fresh session Ed25519 identity,
- encrypted identity proof,
- session binding.

### Tests

- two sessions use different sender IDs,
- master key absent from clear header,
- replayed identity proof fails in another transcript.

---

## WP-019 — Capability and Consent Engine

**Status:** `VERIFIED`

### Implementieren

- sender capability,
- receiver capability,
- default deny,
- rights,
- time bounds,
- type mask.

### Property Test

Für zufällige Paket-/Capability-Kombinationen muss Acceptance exakt der
Policy Engine entsprechen.

### Kritischer Test

Frame vor Consent wird verworfen.

---

## WP-020 — Revocation Engine

**Status:** `VERIFIED`

### Implementieren

- future use revoke,
- delete request,
- derived data delete request,
- session termination,
- key lineage constraints.

### Tests

- revoked capability cannot send,
- successor may narrow but not widen prior rights,
- compromised key fails closed.

---

## WP-021 — V13 Conformance Vector Suite

**Status:** `VERIFIED`

### Vektoren

- wire,
- crypto,
- replay,
- capability,
- identity,
- privacy accounting,
- malformed.

### Abnahme

Vektoren sind:

- versioniert,
- deterministic,
- dokumentiert,
- maschinenlesbar.

---

## WP-022 — Fuzzing and Parser Hardening

**Status:** `VERIFIED`

### Ziele

Codec darf bei beliebigen Inputs nicht:

- crashen,
- hängen,
- unbounded memory allozieren,
- unsichere Ausnahmezustände erzeugen.

### Stufen

Smoke:

```text
100,000 generated malformed inputs
```

Full CI/nightly:

```text
>= 1,000,000
```

---

## WP-023 — QUIC Transport Adapter

**Status:** `VERIFIED`

### Implementieren

- connection,
- reliable control stream,
- reliable state stream,
- bulk stream,
- optional QUIC datagrams.

### Tests

Netzwerksimulation:

- latency,
- jitter,
- packet loss,
- reorder,
- connection migration,
- disconnect/reconnect.

### Metriken

```text
p50 latency
p95 latency
p99 latency
throughput
frame age at receiver
loss
reconstruction freshness
```

---

## WP-024 — Session Protocol over QUIC

**Status:** `VERIFIED`

### Implementieren

State machine aus Kapitel 32.

### Property Tests

Zufällige Eventsequenzen dürfen niemals erzeugen:

- data before consent,
- data after revocation,
- invalid transition,
- silent profile upgrade.

---

## WP-025 — BCI-Free End-to-End Demo

**Status:** `VERIFIED`

### Aufbau

```text
sender UI / CLI
 → ExperienceFrame
 → TAOSS
 → ESP
 → QUIC
 → receiver
```

### Pflichtdemo

1. Vollständiger Zustand.
2. EMO maskieren.
3. EMO tatsächlich aus Payload entfernt.
4. Binding separat maskieren.
5. Receiver zeigt Provenance.
6. Receiver zeigt keine maskierten Daten.

### Test

Packet capture + decoded application payload.

---

## WP-026 — BrainFlow Adapter

**Status:** `NOT_STARTED`

### Phase A

Synthetic Board.

### Phase B

Playback File Board.

### Phase C

Streaming Board.

### Tests

- 30-minute continuous synthetic stream,
- no memory growth beyond threshold,
- dropout behavior,
- timestamp monotonicity,
- replay determinism.

---

## WP-027 — Lab Streaming Layer Adapter

**Status:** `NOT_STARTED`

### Implementieren

- stream discovery,
- inlet,
- outlet,
- clock correction metadata,
- XDF replay integration.

### Tests

Mindestens drei parallele Streams:

```text
EEG synthetic
ECG synthetic
event markers
```

Prüfen:

- ordering,
- clock offset,
- dropout,
- replay.

---

## WP-028 — Physiological Feature Layer

**Status:** `NOT_STARTED`

### Implementieren

Zunächst keine Emotionserkennung.

Nur Features:

- heart rate,
- heart-rate variability,
- electrodermal features,
- respiration features,
- pupil/gaze features,
- optional EEG spectral features.

### Tests

Signal fixtures mit bekannten Eigenschaften.

---

## WP-029 — Personalized Calibration Pipeline

**Status:** `NOT_STARTED`

### Implementieren

- baseline collection,
- robust normalization,
- device correction,
- person-specific transform.

### Tests

Gleicher Rohwert bei unterschiedlichen Baselines darf unterschiedliche
standardisierte Features erzeugen.

---

## WP-030 — Multimodal State Estimation Baseline

**Status:** `NOT_STARTED`

### Inputs

- self report,
- text,
- voice features,
- physiology features,
- context.

### Output

provenance-behaftete Estimates.

### Kein Claim

Nicht "emotion detector".

### Tests

- missing modalities,
- contradictory modalities,
- low-quality source downweighting,
- confidence calibration.

---

## WP-031 — TAOSS Reference Encoder Skeleton

**Status:** `NOT_STARTED`

### Implementieren

V13 Architektur-Skeleton:

- modality encoders,
- fusion,
- six typed heads,
- running standardization,
- covariance penalty,
- adversarial reconstruction.

### Ziel

Architektur korrekt und trainierbar.

Noch keine H1/H2/H3-Behauptung.

---

## WP-032 — Training Harness

**Status:** `NOT_STARTED`

### Implementieren

- configs,
- deterministic runs,
- checkpointing,
- metrics,
- registry binding,
- experiment metadata.

### Tests

Tiny synthetic overfit test.

---

## WP-033 — Cross-Type Leakage Harness

**Status:** `NOT_STARTED`

### Implementieren

- pairwise probes,
- joint probes,
- fixed split discipline,
- confidence intervals,
- baselines.

### Output

Leakage Matrix.

---

## WP-034 — ExperienceBench Skeleton

**Status:** `NOT_STARTED`

### Implementieren

Alle neun Benchmarkfamilien als Plugin/API.

Smoke data erlaubt.

### Tests

Jede Benchmarkklasse muss mit synthetic fixture laufen.

---

## WP-035 — H1 Benchmark

**Status:** `NOT_STARTED`

### Implementieren

Consent/Utility/Leakage Pareto Frontier.

### Pflichtbaselines

gemäß V13.

---

## WP-036 — H2 Benchmark

**Status:** `NOT_STARTED`

### Implementieren

- naive block masking baseline,
- learned privacy filter,
- optional LEACE where applicable,
- pairwise and joint leakage.

### Abnahme

Keine H2-Aussage ohne alle Pflichtbaselines.

---

## WP-037 — H3 Benchmark

**Status:** `NOT_STARTED`

### Implementieren

- one preregistered primary task,
- required baselines,
- causal controls.

### Causal Controls

```text
true
zero
shuffled
moment matched
```

---

## WP-038 — Human Interpretability Study Harness

**Status:** `DEFERRED`

### Grund

Software kann vorbereitet werden.

Echte Human Study erst nach Ethikfreigabe.

### Implementieren später

- study protocol schemas,
- randomization,
- anonymized responses,
- consent form integration.

---

## WP-039 — Python Conformance CLI

**Status:** `NOT_STARTED`

### Kommando

```bash
esp-conformance run
```

### Prüft

- wire,
- crypto,
- consent,
- revocation,
- ontology,
- interop,
- malformed inputs.

---

## WP-040 — Independent Rust Codec

**Status:** `NOT_STARTED`

### Ziel

Keine gemeinsame Serialisierungscodebasis.

### Tests

```text
Python sender → Rust receiver
Rust sender → Python receiver
```

Byte-exakte Cross-Implementation-Vektoren.

---

## WP-041 — Independent Rust Session Client

**Status:** `NOT_STARTED`

### Ziel

Beweis, dass ESP ein Protokoll und nicht nur eine Python-Library ist.

---

## WP-042 — Interoperability Matrix

**Status:** `NOT_STARTED`

### Matrix

```text
Python ↔ Python
Python ↔ Rust
Rust ↔ Python
Rust ↔ Rust
```

für:

- packets,
- consent,
- revocation,
- streams,
- bundles.

---

## WP-043 — Performance and Rate Benchmarks

**Status:** `NOT_STARTED`

### Messen

- encode latency,
- crypto latency,
- network latency,
- decode latency,
- total latency,
- bandwidth,
- memory,
- CPU.

Profile:

```text
10 Hz
25 Hz
50 Hz
```

---

## WP-044 — Security Review Harness

**Status:** `NOT_STARTED`

### Automatisierte Checks

- dependency audit,
- secret scan,
- unsafe config scan,
- parser fuzz,
- protocol invariant tests.

### Manuell

Threat Model Review vor v1.0.

---

## WP-045 — Future Neural Adapter Interface

**Status:** `FUTURE`

### Implementieren

Nur Interface + simulator-compatible contract.

Keine invasive Hardware erforderlich.

---

## WP-046 — Documentation and Reference Examples

**Status:** `NOT_STARTED`

### Pflichtdokumente

- architecture,
- psychology model,
- protocol walkthrough,
- consent examples,
- security examples,
- "what ESP is not",
- adapter guide,
- conformance guide.

---

## WP-047 — Release Candidate

**Status:** `NOT_STARTED`

### Kriterien

- all required v1 packages VERIFIED,
- Python/Rust interop green,
- conformance green,
- security smoke green,
- docs complete,
- no unresolved critical ADR,
- versioned test vectors frozen.

---

# 53a. Arbeitspakete der maximalen Ausbaustufe (v0.2.0)

Die folgenden Pakete schließen die in §52b/§52c gefundenen Lücken. Die
Nummern sind fortlaufend; die **Meilenstein-Zuordnung** (§54) bestimmt die
Reihenfolge, nicht die Nummer.

---

## WP-048 — Companion Spec: Session Control & Session Descriptor

**Status:** `VERIFIED` · **Klasse:** `V13_COMPATIBLE_ADDENDUM` · **Löst:** GAP-005, GAP-024

### Implementieren

- `docs/companion/CS-SESSION-CONTROL.md` (CC BY-SA),
- kanonisches `SessionDescriptor`-Objekt: Profil (L1/L2/…), SF-Level,
  TAOSS-Profil-ID + Registry-Digest, Anchor-Set-IDs, `W_back`/`W_fwd`,
  vier Raten (Sensor, Latent-Update, Wire-Paket, Privacy-Release),
  DP-Profil, `pq_mode`, Decoder-Policy pro Typ, Hash der Sender- und
  Receiver-Capability,
- Control-TLVs (Addendum-Profil): HELLO, PROFILE_NEGOTIATION,
  REGISTRY_DIGEST, KEY_ROTATION, SESSION_CLOSE, ERROR,
- Bindung des Descriptor-Digests in das Noise-Transkript (V13 §9.7:
  Capabilities dürfen nicht mitten in der Session getauscht werden).

### Tests

- Descriptor-Roundtrip, kanonische Bytes, Golden Vector,
- Descriptor-Änderung ohne Re-Handshake → Session-Abbruch,
- stilles Profil-Upgrade unmöglich (Property-Test),
- `pq_mode=CLASSICAL_ONLY` erzwingt, dass keine UI/Doku „post-quantum“ sagt.

---

## WP-049 — Addendum-TLV-Profil `esp-addendum-v1`

**Status:** `VERIFIED` · **Löst:** GAP-004

### Implementieren

- `docs/companion/CS-ADDENDUM-TLV.md`,
- Registry-Eintrag + `TLV_TYPE_PROFILE (0x11)`-Anmeldung mit BLAKE2b-256-Digest,
- Codes für: `SEMANTIC_BINDING`, `EVIDENCE_CLAIM`, `AFFECT_DESCRIPTOR`
  (inkl. `affect_scope`), `EMOTION_EPISODE`, `SELF_REPORT`, Control-TLVs aus WP-048,
- jedes Objekt separat maskierbar (Masking = nicht in der Payload).

### Tests

- Empfänger ohne Addendum-Profil ignoriert Codes, interpretiert sie nie um,
- EMO übertragen, `elicited_by → KNO`-Binding maskiert: Binding-Bytes sind
  nachweislich nicht im Ciphertext-Plaintext (Kritischer Test WP-005),
- `affect_scope=INFERRED_SUBJECT` bei `profile=0x01` → Reject vor Decoder.

---

## WP-050 — `TLV_ANCHOR_COORDS (0x50)` + Anchor-Projektion π_t

**Status:** `IMPLEMENTED` · **Löst:** GAP-007

### Implementieren

- CS-ANCHOR-COORDS, Codec,
- π_t mit Cosinus, Projektionskoeffizient, RBF (profilwählbar),
- drei Modi (V13 §5.4): zusätzlich zu Latents, **statt** Latents
  (Interpretation-only), oder lokal beim Empfänger aus gepinntem Anchor-Set.

### Tests

- gleiche Latents + gleiches Anchor-Set → bitgleiche Koordinaten,
- Interpretation-only-Paket enthält keine Latent-TLVs,
- zwei Zustände mit identischen Koordinaten, aber verschiedenen Latents
  bleiben unterscheidbar (V13: „Anchors are not the latent state“).

---

## WP-051 — ReceiverCapability (0x21), Default-Deny und Accept-Prädikat

**Status:** `VERIFIED` · **Löst:** GAP-008, GAP-013

### Implementieren

- Codec 0x21 mit kanonischem Weglassen nicht anwendbarer Felder,
- Übergabe im ersten Noise-Responder-Payload, gebunden an `noise_h`,
- Default-Deny ohne Capability: nur KNO+CTX, profilgepinnte Norm-/Rate-Grenzen,
- vollständiges **Accept(p, c_S, c_R)**-Prädikat (V13 §9.7, 12 Bedingungen)
  als reine Funktion,
- Quarantäne-Puffer: Auth → Decrypt → minimales Parsen → Prädikat →
  erst dann Decoder/Persistenz/Side Effects,
- Enforcement-Klassen: L1-Default (SHOULD), L1-High-Stakes (MUST +
  Intermediär-Filter), L3+ (MUST, vor jeder Decoder-Arbeit).

### Tests

- Property-Test: für zufällige (Paket, c_S, c_R) entspricht Accept exakt
  der Referenzimplementierung des Prädikats,
- `max_segments` pro Empfänger überlebt Session-Neuaufbau,
- ohne Capability wird EMO abgelehnt,
- Instrumentierung beweist: kein Decoder-Aufruf bei abgelehntem Paket.

---

## WP-052 — Identity Proof (0x20) und Static-Key-Binding

**Status:** `VERIFIED` · **Löst:** GAP-006

### Implementieren

- `TLV_IDENTITY_PROOF` mit `Ed25519(sk_M, "esp/v1/identity-proof" ‖ pk_S ‖ noise_h ‖ epoch)`,
- höchstens einmal pro Session, nur an autorisierte Empfänger, nur mit Consent,
- Responder-Static-Key-Cross-Signatur (CS-SESSION-CONTROL §Identity),
- Timeline-Rotation-Policy: L1 ≤ 24 h, High-Stakes und I2I pro Session.

### Tests

- Identity Proof aus Session A in Session B → Reject (anderes `noise_h`),
- zweiter Identity Proof in derselben Session → Reject,
- Master-Key erscheint nie in Klartext-Bytes (Scan über alle Vektoren),
- Timeline-Lebensdauer-Überschreitung → erzwungene Rotation.

---

## WP-053 — Master-Key-Lebenszyklus, Rotation, Transparenzlog

**Status:** `VERIFIED` · **Löst:** GAP-019

### Implementieren

- Zustände `ACTIVE → ROTATED → REVOKED` mit Grund `COMPROMISED` (fail closed),
- `TLV_KEY_REVOKED (0x41)`: Modi `SELF` und `SUCCESSOR_BOUND`,
- `TLV_ROTATION_BINDING (0x42)`: `sig_new` Pflicht, `sig_old` modusabhängig,
  Evidence authentifiziert dasselbe Tupel,
- Lineage-Regel: Rechte nur vom aktiven Key erteilen; Rechte verringern darf
  Aussteller oder verifizierter, nicht kompromittierter Nachfolger,
- Rotationsmechanismen: Pre-Registered Successor, HW-Attested (Interface),
  Witness-Quorum,
- lokales Transparenzlog (Merkle-Baum nach RFC 9162-Struktur, signierte
  Tree Heads, Witness-Cosignaturen) für Rotationen und DP-Ledger-Checkpoints,
- Custody/Recovery-Policy-Objekt pro Profil (pre-registered / social k-of-n
  Shamir / custodial / none + kurze Expiry).

### Tests

- beliebiger frischer Key kann fremde Identität nicht „revoken“ (V13-Fix),
- Nachfolger darf verengen, nie erweitern,
- nach `COMPROMISED` terminieren alle Sessions, deren Identity Proof darauf wurzelt,
- „alter“ Grant, erstmals nach Rotation präsentiert, ohne Log-Inklusion → Reject,
- Merkle-Inklusions- und Konsistenzbeweise gegen Golden Vectors.

---

## WP-054 — Vendor Provenance Chain (0x40)

**Status:** `VERIFIED`

### Implementieren

- `TLV_VENDOR_PROVENANCE` mit `H_payload = BLAKE2b-256(canonical(L))`,
  L = TAOSS-geordnete Latent-TLVs inklusive Header,
- Ketten (Encoder → Aggregator → Re-Publisher), vollständige Kettenprüfung,
- optionaler C2PA-Binding-Export (Interface).

### Tests

- Manipulation eines Latent-Bytes bricht jede Provenance-Signatur,
- Provenance signiert nie sich selbst oder Geschwister-TLVs,
- Empfänger mit Provenance-Filter lehnt unbekannte Vendor-Keys ab.

---

## WP-055 — Laufzeit-DP: Clip, Noise, `TLV_DP_PARAMS (0x30)`, Ledger

**Status:** `VERIFIED` · **Löst:** GAP-012

### Implementieren

- Clip `Ẽ·min(1, C_t/‖Ẽ‖)` + Gauß-Rauschen auf standardisiertem Latent,
- Adjazenzen ∼F, ∼S (w = 50), ∼U; Sensitivität Δ₂ = 2C (replace-one),
- RDP-Accountant (optimal α) + analytic Gaussian (Balle–Wang) als Zweitweg,
- Multi-Typ-Komposition (`ρ = |V|·k·(2C)²·α/(2σ²)`), Aggregation-Mode (`k_eff = k/N`)
  vs. reines Bundling (`k_eff = k`),
- persistenter, monotoner **Privacy-Ledger pro `capability_id`**
  (übersteht Neustart und Session-Wechsel, Rollback-Erkennung),
- Empfänger-Audit: rechnet ε aus (C_t, σ_t, k) nach, lehnt bei Abweichung ab,
- Referenzprofile `L1_BALANCED_REF`, `L1_PRIVATE_REF` als Registry-Eintrag,
- Info-Rate-Obergrenze `d/2·log₂(1 + C²/(dσ²))` als Report-Metrik,
- Consent-Text-Guard: bei `DP_LEVEL=NONE` darf keine UI „differentially private“ sagen.

### Tests

- V13-Zahlen reproduzieren: σ≈24.42 ⇒ ε_tot,joint≈11.3 (|V|=5, k=100, δ=10⁻⁶),
  Info-Rate ≈1.2·10⁻³ bit/Typ/Frame,
- `n_types ≠ popcount(types_clipped)` → Reject; ε über Ceiling → Reject,
- DP_LEVEL≠NONE ohne 0x30 → Reject; DP_LEVEL=NONE mit 0x30 → Reject,
- Retransmission desselben privatisierten Samples verbraucht kein Budget,
- Ledger-Crash-Test: nach Neustart kein Budget-Rückfall.

---

## WP-056 — Quantisierung und Latent-Encodings

**Status:** `VERIFIED`

### Implementieren

- `F32_BE`, `F16_BE`, `INT8_SYM` (Byte −128 verboten, `scale` endlich > 0),
- Referenzquantisierer `s = max(‖x‖∞/127, 2⁻²⁴)`,
- Header-Bit `QUANTIZED` ⇔ alle Latent-TLVs `INT8_SYM` (beidseitig),
- Reihenfolge: DP → Quantisierung (Post-Processing),
- randomisierte Quantisierung für Covert-Hardening (WP-057).

### Tests

- exakte Körperlängen 8+4d / 8+2d / 8+d,
- Mischung von Encodings mit/ohne QUANTIZED-Bit → Reject,
- Rundungs-Golden-Vectors, NaN/Inf-Ablehnung, Float-Kanonisierung.

---

## WP-057 — Covert-Channel-Budget und Hardening

**Status:** `NOT_STARTED` · **Löst:** GAP-015, GAP-016

### Implementieren

- Leakage-Score als **fixed-null predictive V-information**
  `L = Ĥ₀(Z_M) − Ĥ_V(Z_M | Z_V, meta)`, Null-Modell einmal pro Ziel und Split,
- Probe-Leiter linear → MLP (spektral normiert) → beschränkter Transformer,
  plus temporale Leiter mit Fenster w,
- Pass-Kriterium: `L̂ ≤ η_cc` **und** `|Î_covert − Î_baseline| ≤ η_I`,
- Hardening: Norm-Caps, randomisierte Quantisierung, TEM-Pattern-Band,
  Gating-Sparsity-Band, Replay-Watermark (DEFERRED bis TLV-Code),
- **Red-Team-Sender**: absichtlich steganografischer Encoder (EMO in TEM
  versteckt) als Pflicht-Negativkontrolle.

### Tests

- Leiter-Monotonie: größere Familie meldet nie weniger Leakage,
- Red-Team-Sender wird vom Audit erkannt (Audit muss fehlschlagen),
- ehrlicher Sender besteht mit Konfidenzintervall.

---

## WP-058 — Audit Suite (V13 §13)

**Status:** `NOT_STARTED`

### Implementieren

- KSG-MI mit k ∈ {4…10}, Default 6; Surrogat (PCA ≤ 32 / Random Projection /
  π_t) für KNO-240, Surrogat wird geloggt; Voll-240-D nur Sanity,
- MINE als Zweitschätzer, HSIC (RBF), Distanzkorrelation,
- lineare + MLP-Probes; diskret: balanced accuracy ≤ 1/K + 0.02;
  kontinuierlich: R² ≤ 0.02,
- Cluster-/Block-Bootstrap B = 1000 auf Split-Einheit (IID-Frame verboten),
- Schätzer-Dissens-Trigger `ΔÎ > max(0.01 bit, 0.05·√(d_eff/N))`,
- Black-Box-Probe (query-limitierte Bayes-Optimierung),
- T19-Audits: Inversion, Attribut-Inferenz, utility-gematchter Vergleich mit Anchor-only,
- Report ohne Probe-Ergebnis gilt als Audit-Fehlschlag (No-Free-Lunch-Regel).

### Tests

- Referenz-Inputs mit bekannter MI (Gauß-Paare mit analytischer MI) ± Toleranz,
- Vektoren der Anhang-C-Klasse „Audit“.

---

## WP-059 — Decoder-Schicht und Decoder Companion Spec

**Status:** `NOT_STARTED` · **Löst:** GAP-014, GAP-022

### Implementieren

- `D_φ` mit ⊥_t (Abwesenheit) ≠ 0-Vektor; Typ-Profil `T_φ`,
- Policy pro Typ: STRICT_REFUSE / GRACEFUL / PRIOR_IMPUTE (mit Benachrichtigung),
  Profil muss deklarieren; stilles ⊥→0 → `ESP_DECODER_POLICY_FAILED`,
- Fehlercode-Register mit stabilen Zahlen,
- Ausgaberaum Y als getaggte Union (text / vector / media / action),
- Kompatibilitätsmetriken: Mittelwert, Quantil `Q_q`, Worst Case,
  Anchor-mediated (externe Klassifikatoren C_i),
- Referenz-Renderer: Text, Vektor-Visualisierung, maschinenlesbar,
  Mixed-Mode; Decoder-Transparenz-Panel (was ist da, was maskiert,
  welcher Renderer, was kann nicht rekonstruiert werden).

### Tests

- ⊥ und 0 erzeugen unterschiedliche Decoder-Pfade,
- Profil ohne Policy-Deklaration → Konfigurationsfehler,
- Kompatibilitätsmetrik auf synthetischem Referenzset reproduzierbar.

---

## WP-060 — Receiver-Threat-Mitigations T13–T19

**Status:** `NOT_STARTED`

### Implementieren

- T13: Norm-Caps, Valence-Bounds, Decoder-Pre-Screen,
- T14: lokales Decoding, bidirektionaler Consent (Empfänger kann ablehnen),
- T15: Decoder-Versionierung + Replay gegen archivierte Anker,
- T16: Rate-Limits, günstiger Pre-Screen, Ressourcenbudget pro Session,
- T18: Provenance-Pflicht (WP-054) in High-Stakes-Profilen,
- T19: Minimierung, Anchor-only-Modus, Inversion-Audit (WP-058).

### Tests

- Fuzz mit bösartigen Vektoren (Norm-Explosion, NaN, extreme Valenz),
- Decoder-Budget-Überschreitung → Drosselung statt Absturz.

---

## WP-061 — Bundle Mode (0x01), Capabilities-Ext (0x10), Type Profile (0x11)

**Status:** `VERIFIED` · **Löst:** GAP-011

### Implementieren

- `TLV_INNER_SEGMENT` mit N inneren Frames, amortisierter Overhead ~180/N,
- `TLV_CAPABILITIES_EXT` (MSB-first-Bitstring), Header-Bit 15,
- `TLV_TYPE_PROFILE` für alternative TAOSS-Profile (TAOSS-3/-8/-12),
  nie Uminterpretation von 0x60–0x65,
- v1: Capability-Bits 0–14 MUST zero.

### Tests

- Bundle mit N=1…64 roundtrippt, Replay-Fenster zählt korrekt,
- unbekannte Ext-Bits werden ignoriert, reservierte Header-Bits abgelehnt,
- TAOSS-12-Profil mit 12-Eintrag-DP-Arrays.

---

## WP-062 — Metadaten-Leak-Mitigations

**Status:** `VERIFIED` (ADR-0027 PROPOSED)

### Implementieren

- Constant-Bitmap-Padding (Dummy-Inhalte fester Größe für maskierte Typen),
- Decoy-Traffic mit konstanter Rate,
- `TIMING_OBF` für `dt_ms` (kein DP-Claim!),
- Onion/Mixnet-Hook (Interface).

### Tests

- Traffic-Analyse-Test: Beobachter kann EMO-Präsenz aus Paketgröße/-rate
  nicht besser als Zufall klassifizieren (bei aktivierter Mitigation),
- `TIMING_OBF` wird nirgends als Differential Privacy bezeichnet.

---

## WP-063 — Profile, SF-Level, I2I-Envelopes, Raten-Semantik

**Status:** `VERIFIED`

### Implementieren

- Profile-Byte (L1=0x01, L2=0x02, …), SF0…SF7 mit Pflicht-/Optionaltypen,
- Custom-Type-Set-Profile (z. B. `MEB-HANDOVER` ohne KNO),
- I2I-TRUSTED (EMO_MASKED initial, NO_STORE, NO_REPLAY, TIMING_OBF, DP=NONE erlaubt)
  und I2I-PRIVATE (DP Pflicht, Aggregation N=10),
- vier getrennte Raten und deren Dokumentationspflicht.

### Tests

- Paket verletzt SF-Pflichttypen → Reject,
- V13-Bandbreitenrechnung reproduzieren: 693 B/Release (SF5, INT8, DP=NONE),
  780 B mit 0x30, 139/277 kbit/s bei 25/50 Hz.

---

## WP-064 — Turn Token (0x52), SOS, PANIC

**Status:** `VERIFIED`

### Implementieren

- Holder/Moderator-Regel, strikt monotones `turn_seq`, `YIELD` ⇒ Holder = 0,
- SOS als 1-Bit-INT-Shortcut ohne EMO/KNO,
- PANIC: `TLV_REVOCATION_INTENT` + sofortige Key-Rotation, **nur** auf
  zuverlässigem Control-Stream.

### Tests

- Token von Nicht-Holder wird ignoriert, auch wenn wohlgeformt,
- PANIC unter 10 % Paketverlust erreicht Empfänger und stoppt Datenfluss.

---

## WP-065 — Adaptives Replay-Fenster

**Status:** `VERIFIED`

### Implementieren

- `W_back = min(8192, max(1024, ⌈2·RTT_p99·r_pkt⌉))`,
  `W_fwd = min(8192, max(128, ⌈jitter_p99·r_pkt⌉))`,
- Laufzeit-Schätzung von RTT/Jitter, Austausch im Session Descriptor,
- Replay-Cache für die Lebensdauer des Session-Keys.

### Tests

- Fenstergrenzen exakt (Golden), Sequenz-Wrap-Verbot (GAP-009),
  Timeline-Rotation, zellulare Jitter-Profile aus dem Netzemulator.

---

## WP-066 — Machine Experience Bridge (MEB)

**Status:** `NOT_STARTED` · **Klasse:** `V13_NORMATIVE` (Constraints) + `EXPERIMENTAL` (Alignment)

### Implementieren

- `T_mach ⊆ {KNO, INT, CTX, SEN, TEM}` — Maschinen autorisieren nie EMO,
- Machine Adapter `g_mach(S, U, M)` Interface + Simulator (z. B. Fahrzeug-Handover),
- Cross-Domain-Alignment `A_{m→h}`, `A_{h→m}` blockerhaltend, Cycle-Loss,
  η-Kompatibilitätsmetrik,
- Domain-Profile: Vehicle Handover, Robotic Skill Transfer, Surgical
  Assistance (NO_REPLAY), Drone Swarm (Bundle), Assistive Relay (L2+),
- M2H-Defaults: Angebot {KNO, CTX, TEM} ∩ Receiver-Capability; ohne
  Capability max. {KNO, CTX}; Maschinen-SEN nur mit Opt-in.

### Tests

- Maschinen-Paket mit EMO-Bit → Reject,
- `MEB-HANDOVER` ohne `EMO_MASKED=1` oder mit KNO → Reject,
- typübergreifender Adapter ohne Deklaration → Reject; mit Deklaration →
  Leakage-Audit wird erzwungen.

---

## WP-067 — ESP-Agent-Profil (LLM-/Agenten-Kommunikation)

**Status:** `NOT_STARTED` · **Ohne Hardware sofort baubar**

### Implementieren

- Opaque-Latent-Deskriptor (Pflichtfelder V13 §18.1): State Kind, Modell- und
  Versions-Digest, Layer/Tensor-Schema, Payload-Digest, Agenten-Identität,
  Empfänger-Capability, sichtbare Aktion/Commitment, Event-ID,
- Companion-Stream für Tensoren, Digest im ESP-Transkript gebunden,
- `g_agent`-Adapter, der Agentenzustand auf `T_mach` abbildet (z. B. Ziel →
  INT, Aufgabenkontext → CTX, Fakten → KNO) — erst nach Audit „TAOSS“ genannt,
- Referenzdemo: zwei LLM-Agenten tauschen INT/CTX/KNO über ESP unter
  Capability, mit Event-Audit-Log.

### Tests

- Opaque-Payload trägt nie TAOSS-Consent-Garantien im UI/Report,
- Kausal-Audit: Event-ID verknüpft Latent ↔ sichtbare Aktion,
- Agent ohne Capability für INT kann INT nicht senden.

---

## WP-068 — XCF Experience Capsules und Recall (0x51)

**Status:** `NOT_STARTED` · **Stufe:** v2

### Implementieren

- XCFv1-Header, exakt 148 Byte gepackt, Big Endian,
- CEK pro Kapsel, AEAD mit AAD = Header ‖ Key-Envelope,
- `PER_CAPSULE`-Tags via `HKDF-SHA512(salt=nonce, IKM=CEK, info="esp/xcf/v1/ref-tags")`
  + keyed BLAKE2b-128; `LINEAGE_PSEUDONYM`,
- pseudonyme Kapselsignatur, `capsule_sig` und CID nach V13-Formeln,
- `DIRECT_HPKE` (RFC 9180) und `GATED_CEK` mit Referenz-Gate-Service
  (lokal + Guardian-Quorum), Tombstones,
- Recall-Path: CID → Policy-Check → `RECALL_FRAME` → TEM-Rekonstruktion;
  `NO_REPLAY` irgendwo in der Lineage ⇒ Deny.

### Tests

- `sizeof(header) == 148`, Golden-Kapseln,
- `DIRECT_HPKE`-Profil darf nie „kryptografische Löschung“ bewerben,
- Gate-Secret zerstört ⇒ Neuempfänger kann nicht entschlüsseln,
- zwei unabhängige Kapseln haben unkorrelierte `policy_ref`-Tags.

---

## WP-069 — Trust Vector

**Status:** `NOT_STARTED` · **Stufe:** v2

### Implementieren

- τ = (τ_sig, τ_anchor, τ_drift, τ_privacy, τ_lineage) ∈ [0,1]⁵ mit
  V13-Formeln (MMD-Drift, Privacy-Rest, Lineage-Anteil, Tombstone ⇒ 0),
- optionaler Skalar T(c) **nur** zusammen mit dem Vektor,
- Recall-Zulässigkeit: T ≥ θ_T ∧ τ_sig = τ_lineage = 1.

### Tests

- gebrochene Signatur mit hohem Skalar → Recall verweigert,
- UI/API, die T ohne Vektor ausgibt → Testfehler.

---

## WP-070 — Typed Hive (0x70–0x73)

**Status:** `NOT_STARTED` · **Stufe:** v2-research · **Löst:** GAP-017

### Implementieren

- TLVs HIVE_GRANT, HIVE_CONTRIBUTION, HIVE_EXIT, COLLECTIVE_INTENT,
- Grant verengt nur die Basis-Capability; EMO-`lambda_max` = 0 für menschliche Zustände,
- Modi IDENTIFIED/ANONYMOUS (Nullifier, Credential-Proof-Interface),
- Commitment `BLAKE2b-256("esp/v1/hive-contribution" ‖ episode_id ‖ x ‖ r)`,
- Episode-Lebenszyklus (Discovery → Join → Rounds → Audit → Seal → Publish → Exit),
- Friedkin–Johnsen-Update mit beschränkter Kopplung, Emergenz-Audit
  (präregistriert), Mindestgruppengröße, Quorum + FROST-Signatur,
- EMO nur als DP-Histogramm über Anker-Bins, nie als Zentroid,
- Verbot: kein Collective Intent über natürliche Personen.

### Tests

- Grant, der Basisrechte erweitert → Reject,
- EMO-Mixing ≠ 0 → Reject,
- Runde mit zu wenigen ehrlichen Rauschbeiträgen bricht ab,
- CIC unter Quorum oder mit Personenziel → ungültig.

---

## WP-071 — Experience Legacy Profile

**Status:** `FUTURE`

### Implementieren

Nur Policy-Objekte und Validierung: Ex-ante-Policy, erlaubte Typen,
Empfängerklassen, Aktivierungsbedingungen, Aufbewahrung, Renderer-Rechte,
Erlaubnis maschineller Fortsetzung, Executor-/Witness-Quorum.
Posthume EMO-Synthese nur mit ausdrücklicher Vorab-Zustimmung.

---

## WP-072 — Master-Key-Custody-Adapter

**Status:** `VERIFIED`

### Implementieren

- Software-Custody (nur L1, mit Offenlegung an Nutzer),
- Hardware-Interfaces: TPM 2.0, PKCS#11, FIDO2/WebAuthn (optional),
- Social Recovery (Shamir k-of-n) als Referenz.

### Tests

- Software-Custody ohne Offenlegungs-Flag → Konfigurationsfehler,
- Shamir-Recovery-Roundtrip, Schwellen-Unterschreitung schlägt fehl.

---

## WP-073 — Encoder: Stabilitätsmechanismen und Certified-Stability-Mode

**Status:** `NOT_STARTED` · **Klasse:** `EXPERIMENTAL`

### Implementieren

- Running Standardization, Spektralnormierung, Gradient Penalty,
  Instance Noise, Multi-Capacity-Diskriminatoren, Early Stopping auf
  HSIC/MINE-Plateau, β-Annealing (erste 20 %), Encoder-only-Updates,
- Certified-Mode: expliziter Spektral-Clip auf R_max, unabhängige
  Operator-Norm-Verifikation (V13 §10, App. B),
- fehlende Modalitäten per Gates `g_m`.

### Tests

- Certified-Mode: gemessene Lipschitz-Schranke ≤ deklarierte Schranke,
- Tiny-Overfit mit allen Mechanismen aktiv.

---

## WP-074 — Type-Discovery-Frontier und Ablationen

**Status:** `NOT_STARTED` · **Klasse:** Research

TAOSS-3/-6/-8/-12 über `TLV_TYPE_PROFILE`, Frontier
`max Utility − λ_p·Leak_V`, EMO-default-masked-Ablation, covariance-only
vs. adversarial-only vs. beides, Pseudonyme an/aus.

---

## WP-075 — Post-Quantum-Deklaration und Hybrid-Pfad

**Status:** `NOT_STARTED` · **Löst:** GAP-024

- `pq_mode` im Session Descriptor, v1 `CLASSICAL_ONLY`,
- Hybrid-Outer-Channel-Adapter (TLS 1.3 mit X25519MLKEM768) als Option,
- Lint-Regel: kein „post-quantum“ in Doku/UI, solange `CLASSICAL_ONLY`.

---

## WP-076 — Lizenz- und Governance-Infrastruktur

**Status:** `IN_PROGRESS` · **Gehört zu:** M0

### Implementieren

Alle Artefakte aus §52a.5, `reuse lint` in CI, DCO-Check in CI,
SPDX-Header-Generator, `docs/LICENSING.md` mit Kommerz-FAQ,
Konformitätssiegel-Prozess (Report-Format, Veröffentlichung).

### Tests

- `reuse lint` grün,
- Commit ohne `Signed-off-by` → CI rot,
- neue Datei ohne SPDX-Header → CI rot.

---

## WP-077 — Registry-Governance und Registry-Service

**Status:** `NOT_STARTED`

- Registries für: Anchor-Sets, TAOSS-Profile, DP-Profile, Addendum-TLV-Codes,
  Fehlercodes, Decoder-Profile, Relationsklassen,
- kanonische Serialisierung + BLAKE2b-256-Digest, Signatur der Snapshots,
- Änderungsprozess (Proposal → Review → Freeze), Regulator-Beteiligung als Rolle,
- statischer Registry-Export (JSON + Digest) im Bulk-Stream.

---

## WP-078 — Regulatorik-Schicht (EU AI Act, GDPR)

**Status:** `VERIFIED` · **Löst:** GAP-001 (Durchsetzung)

### Implementieren

- Pflichtdeklaration pro Profil: Regime, Intended Use, Deployment-Kontext
  (workplace/education/medical/safety/other), Biometrie-Status der Inputs,
  `affect_scope` der Outputs — geloggt und auditierbar,
- **Art.-5(1)(f)-Guard:** `affect_scope=INFERRED_SUBJECT` ∧ Kontext
  workplace/education ∧ Input biometrisch ∧ keine medizinische/Sicherheits-Ausnahme
  ⇒ Pipeline startet nicht,
- High-Risk-Flag (Annex III) → Checkliste der Pflichten,
- GDPR-Mapping-Doku (Art. 4(11)/7, 5(1)(c), 5(2), 9, 17, 25, 35),
  DPIA-Vorlage, `docs/REGULATORY.md`.

### Tests

- Guard blockiert verbotene Kombination (Property-Test über alle Kombinationen),
- fehlende Regime-Deklaration → Start verweigert.

---

## WP-079 — Content-Side-Affect-Pipeline und Movie-Engine-Integration

**Status:** `NOT_STARTED`

- `A_t = α_a·g_audio + α_f·g_face + α_s·g_text` (α = softmax(w), Gauß-Glättung),
  Face-Gate: kein Gesicht ⇒ α_f = 0,
- Extraktoren austauschbar, Output immer `affect_scope=CONTENT`,
- Integration der Movie-Engine (WP-010) als L1-Datenquelle; MPEG-7-Mapping-Doku,
- Typed Retrieval (ExperienceBench Task 1) auf Movie-Korpus.

---

## WP-080 — Threat-Model- und Failure-Mode-Regressionen

**Status:** `NOT_STARTED`

Je ein Regressionstest pro V13-Failure-Mode: Type Collapse, Encoder Drift,
Anchor Cultural Bias, Audit-Adversary Asymmetry, EMO-Stego-Rekonstruktion,
Receiver Manipulation via crafted vectors; Coercion at Scale und Linguistic
Atrophy als dokumentierte, nicht technisch lösbare Risiken.

---

## WP-081 — Subject-Side-Affect-Pipeline (L2)

**Status:** `NOT_STARTED` · **Klasse:** `EXPERIMENTAL` · **Voraussetzung:** WP-078

Physiologie/Stimme → Features → `affect_scope=INFERRED_SUBJECT` nur unter
Profil L2, mit L2-Consent, Regime-Guard und Provenance. Keine Claims über
Validität ohne Stufe 4 der Claims Ladder.

---

## WP-082 — Sender-/Receiver-Inspector (Demo-Oberfläche)

**Status:** `IMPLEMENTED`

Web- oder TUI-Oberfläche für M5: Zustand eingeben (Self-Report, Intent,
Kontext), Consent-Schalter pro Typ und pro Binding, Live-Wire-Inspektor
(Header-Bits, Payload-Größe, Beweis „EMO nicht im Plaintext“),
Empfänger-Transparenzpanel (WP-059). AGPL-§13-Quelllink und NOTICE sichtbar.

---

## WP-083 — Datensatz-Register und Präregistrierung

**Status:** `NOT_STARTED` · **Löst:** GAP-023

- Register mit Lizenz, Einwilligungsstatus, Split-Einheit, Digest pro Datensatz,
- Präregistrierungs-Export (OSF-kompatibel) für H1/H2/H3: Hypothesen,
  Metriken, Schwellen, Baselines, Seeds, Multiplizitätskorrektur (Holm),
- Guard: Benchmark-Lauf ohne Präregistrierung wird als „exploratory“ markiert.

---

## WP-084 — Rechtsprüfung vor v1.0

**Status:** `NOT_STARTED` · **Extern**

Anwaltliche Prüfung von Lizenzmatrix, NOTICE-§7(b)-Formulierung,
Markenrichtlinie, Patentzusage, Regulatorik-Doku.

---

## WP-085 — V13-Errata und Spezifikations-Rückfluss

**Status:** `NOT_STARTED`

`docs/errata/V13-ERRATA.md`: jede RESOLVED-Lücke aus §52b als
Errata-Vorschlag für V13.1 (inkl. GAP-020 Repository-Rolle). Die Spec bleibt
Priorität 1 der Quellenhierarchie; Errata werden erst nach Übernahme in die
Spec normativ.


---

# 54. Meilensteine

---

## M0 — Repository Reproducible

Enthält:

```text
WP-000
```

### Test

Fresh checkout auf sauberer Umgebung.

```bash
make setup
make verify
```

### Gate

Keine manuelle Spezialkonfiguration.

---

## M1 — Psychological and Semantic Core

Enthält:

```text
WP-001 ... WP-011
```

### Ziel

Psychologisch sauberes, serialisierbares ExperienceFrame-Modell.

### Gate Tests

1. Mixed Emotion Test.
2. Intensity Preservation Test.
3. Confidence/Intensity Separation.
4. Observation/Inference Separation.
5. Binding Masking.
6. Legacy Movie Mapping.
7. TAOSS block invariants.

### Demo

```text
self report -> ExperienceFrame -> JSON -> ExperienceFrame
```

verlustfrei.

---

## M2 — Deterministic Simulation

Enthält:

```text
WP-012
WP-013
```

### Gate

1. 1.000 synthetic episodes.
2. identische Seeds erzeugen byte-/wertgleiche Ground Truth.
3. OracleEstimator reproduziert Targets.
4. clock drift/dropout fixtures funktionieren.

---

## M3 — Byte-Exact ESP v1

Enthält:

```text
WP-014 ... WP-022
```

### Gate

- wire golden vectors,
- crypto vectors,
- replay tests,
- consent tests,
- fuzz smoke.

### Kritischer Test

Ein einziges geändertes Header-Bit führt zu Authentifizierungsfehler.

---

## M4 — ESP over QUIC

Enthält:

```text
WP-023
WP-024
```

### Gate

Network emulator:

```text
0–200 ms latency
0–10% packet loss
0–50 ms jitter
reordering
```

System muss:

- Control Semantics erhalten,
- keine revoked data akzeptieren,
- Session State konsistent halten.

---

## M5 — BCI-Free Post-Linguistic Demo

Enthält:

```text
WP-025
```

### Gate

Zwei unabhängige Prozesse.

Testfolge:

1. Connect.
2. Negotiate.
3. Consent.
4. Share KNO+INT+CTX.
5. Mask EMO.
6. Wire inspect.
7. Verify EMO not present.
8. Add EMO consent.
9. Verify EMO appears.
10. Revoke EMO.
11. Verify future EMO rejected.

### Erfolg

Der Kernclaim:

> Semantic state can be exchanged under typed consent without using natural
> language as the transport representation.

ist praktisch demonstriert.

---

## M6 — Physiology-Ready Without Real Hardware

Enthält:

```text
WP-026
WP-027
WP-028
WP-029
```

### Gate

30-Minuten-Test:

```text
BrainFlow synthetic + LSL + event stream
```

Messen:

- dropped samples,
- clock error,
- memory,
- CPU,
- timestamp monotonicity.

Replay muss reproduzierbar sein.

---

## M7 — Multimodal Inference Baseline

Enthält:

```text
WP-030
```

### Gate

Synthetic + replay data.

Tests:

- missing sensor,
- conflicting evidence,
- poor signal quality,
- calibration differences.

Keine psychologische Validitätsbehauptung erforderlich.

---

## M8 — Trainable TAOSS

Enthält:

```text
WP-031
WP-032
WP-033
```

### Gate

Tiny dataset:

- training converges,
- types correct shape,
- gradients valid,
- leakage harness works,
- checkpoints reproducible.

---

## M9 — ExperienceBench Exploratory

Enthält:

```text
WP-034 ... WP-037
```

### Gate

Alle Benchmarks auf Smoke Dataset ausführbar.

Noch keine confirmatory Claims.

---

## M10 — Conformance and Independent Implementation

Enthält:

```text
WP-039 ... WP-042
```

### Gate

Python ↔ Rust Interoperability vollständig grün.

---

## M11 — Performance and Security Candidate

Enthält:

```text
WP-043
WP-044
```

### Gate

- performance report,
- fuzz full run,
- dependency audit,
- threat review,
- no unresolved critical security defects.

---

## M12 — Release Candidate 1.0

Enthält:

```text
WP-046
WP-047
```

### Gate

Alle v1-Pflichtarbeitspakete `VERIFIED`.

---

## 54a. Meilenstein-Zuordnung der neuen Pakete (v0.2.0)

Die neuen WPs werden in bestehende Meilensteine eingehängt oder bilden
neue. Die Gate-Tests der bestehenden Meilensteine gelten zusätzlich.

| Meilenstein | zusätzliche WPs | zusätzliche Gate-Bedingung |
|---|---|---|
| M0 | WP-076 | `reuse lint` grün, DCO-Check aktiv |
| M1 | WP-049 (Datenmodell-Teil), WP-050, WP-077 (lokal) | `affect_scope` in allen EMO-Objekten; Binding-Masking über Addendum-TLV |
| M2 | — | Simulator erzeugt nur `SELF_DECLARED`/`CONTENT`-EMO |
| M3 | WP-048, WP-051, WP-052, WP-054, WP-056, WP-061, WP-065 | alle v1-Control-TLVs mit Golden Vectors; GAP-002/003/005/006/008/009/011 `RESOLVED` |
| **M3a — Key Lifecycle & Runtime Privacy** (neu) | WP-053, WP-055, WP-072 | Rotation/Revocation-Lineage grün; DP-Zahlen aus V13 reproduziert; Ledger crash-fest |
| M4 | WP-062, WP-063, WP-064 | PANIC zuverlässig unter Verlust; SF-Validierung |
| M5 | WP-059, WP-060, WP-078, WP-082 | Demo mit Transparenzpanel; Art.-5(1)(f)-Guard aktiv |
| M7 | WP-081 | Subject-Affect nur unter L2 |
| M8 | WP-073, WP-074 (Smoke) | Certified-Mode-Check |
| M9 | WP-057, WP-058, WP-083 | Red-Team-Sender wird erkannt; Präregistrierungs-Guard |
| M10 | WP-085 | Errata veröffentlicht |
| M11 | WP-080 | alle Failure-Mode-Regressionen grün |
| M12 | WP-084 | Rechtsprüfung abgeschlossen |

---

## M13 — Machine & Agent Governance

Enthält:

```text
WP-066
WP-067
```

### Gate

- Maschinen können EMO nicht autorisieren (Negativtests),
- M2H-Defaults gegen Receiver-Capability geschnitten,
- zwei LLM-Agenten tauschen INT/CTX/KNO über ESP mit Event-Audit,
- Handover-Simulator mit `MEB-HANDOVER`-Profil.

**Ohne Hardware und ohne Human Subjects vollständig baubar.**

---

## M14 — Persistence & Recall (XCF)

Enthält:

```text
WP-068
WP-069
```

### Gate

- 148-Byte-Header byte-exakt, CID/Signatur-Golden-Vectors,
- Gate-Revocation verhindert Erstzugriff,
- Recall respektiert `NO_REPLAY` über die gesamte Lineage,
- Trust-Vector-Zulässigkeitsregel erzwungen.

---

## M15 — Typed Hive (Research Track)

Enthält:

```text
WP-070
```

### Gate

- alle vier Hive-TLVs mit Golden Vectors,
- simulierte Episode (≥ 5 synthetische Mitglieder) durchläuft den
  vollständigen Lebenszyklus,
- EMO-Mixing = 0 erzwungen, Quorum + FROST-Signatur verifiziert,
- Emergenz-Audit auf synthetischen Episoden ausführbar (keine Claims).

---

## M16 — Horizon Interfaces

Enthält:

```text
WP-045
WP-071
WP-075
```

### Gate

Nur Interfaces, Simulator-Verträge und Konformitätstests; keine
Funktionsbehauptung (Klasse `FUTURE`).

---

## M17 — Maximale Ausbaustufe erreicht

### Gate

- alle Zeilen der V13-Abdeckungsmatrix (§52c) verweisen auf WPs mit Status
  `VERIFIED`, `DEFERRED` (mit Grund) oder `FUTURE` (mit Interface),
- alle GAPs `RESOLVED` und als Errata eingereicht,
- Claims Ladder (§59) Stufe 3 erreicht; Stufe 4+ nur mit Evidenz.


---

# 55. Milestone-Testreports

Jeder Meilenstein erzeugt:

```text
artifacts/test-reports/M0.json
artifacts/test-reports/M1.json
...
```

Schema:

```yaml
milestone: M3
git_commit: ...
timestamp: ...
environment: ...
tests:
  passed: ...
  failed: ...
metrics:
  ...
artifacts:
  ...
verdict: PASS
```

Diese Reports sind reproduzierbare Evidenz, keine bloßen Screenshots.

---

# 56. Traceability Matrix

Die folgende Matrix muss während der Implementierung erweitert werden.

| Requirement | Source | Implementation | Test | Status |
|---|---|---|---|---|
| TAOSS 512-d split | V13 §5 | `src/esp/taoss` | WP-007 | NOT_STARTED |
| Anchor Registry | V13 §5.4 | `src/esp/ontology` | WP-008 | NOT_STARTED |
| Mixed emotion without sum normalization | Addendum | `src/esp/core` | WP-004 | NOT_STARTED |
| 100-byte header | V13 §8/App A | `src/esp/codec` | WP-014 | NOT_STARTED |
| EMO masking invariant | V13 App A | consent/codec | WP-019 | NOT_STARTED |
| Nonce uniqueness | V13 §9.2 | crypto/session | WP-017 | NOT_STARTED |
| Consent capability | V13 §9.7 | consent | WP-019 | NOT_STARTED |
| Revocation | V13 §9 | consent | WP-020 | NOT_STARTED |
| H1 | V13 §14 | ExperienceBench | WP-035 | NOT_STARTED |
| H2 | V13 §14 | ExperienceBench | WP-036 | NOT_STARTED |
| H3 | V13 §14 | ExperienceBench | WP-037 | NOT_STARTED |
| Python/Rust interop | V13 App C | conformance | WP-040-042 | NOT_STARTED |
| Content- vs. Subject-Affect (`affect_scope`) | V13 §6.4, §23 | core/consent | WP-004, WP-049, WP-078 | NOT_STARTED |
| Receiver Capability 0x21 + Default-Deny | V13 §7.6 | consent | WP-051 | NOT_STARTED |
| Accept(p, c_S, c_R) vor Decoder | V13 §9.7 | consent/session | WP-051 | NOT_STARTED |
| ⊥_t ≠ 0, Decoder-Policy pro Typ | V13 §7.2 | `src/esp/decoder` | WP-059 | NOT_STARTED |
| Identity Proof 0x20, `noise_h`-Bindung | V13 §9.4 | crypto/session | WP-052 | NOT_STARTED |
| Key Revoked 0x41 / Rotation Binding 0x42 / Lineage | V13 §8.4, §9.6 | `src/esp/keys` | WP-053 | NOT_STARTED |
| Vendor Provenance 0x40, H_payload | V13 §7.5 | `src/esp/provenance` | WP-054 | NOT_STARTED |
| Runtime DP 0x30, Ledger pro Capability | V13 §12 | `src/esp/privacy` | WP-055 | NOT_STARTED |
| INT8_SYM ⇔ QUANTIZED-Bit | V13 §8.4 | codec | WP-056 | NOT_STARTED |
| Covert Leakage (fixed-null V-Information) | V13 §9.8 | `benchmarks/leakage` | WP-057 | NOT_STARTED |
| Audit Suite (KSG/MINE/HSIC/dCor/Probes) | V13 §13 | `src/esp/audit` | WP-058 | NOT_STARTED |
| Bundle 0x01 / Caps-Ext 0x10 / Type Profile 0x11 | V13 §8.5–8.7 | codec | WP-061 | NOT_STARTED |
| SF0–SF7, I2I-Envelopes | V13 §8.6, §16 | session | WP-063 | NOT_STARTED |
| Turn Token 0x52, PANIC zuverlässig | V13 §8.4, §16 | session | WP-064 | NOT_STARTED |
| Adaptives Replay-Fenster | V13 §9.5 | session | WP-065 | NOT_STARTED |
| Maschinen autorisieren kein EMO | V13 §17 | `src/esp/meb` | WP-066 | NOT_STARTED |
| ESP-Agent Opaque-Deskriptor | V13 §18 | `src/esp/agent` | WP-067 | NOT_STARTED |
| XCF 148-Byte-Header, CID, Gate | V13 §19.1 | `src/esp/xcf` | WP-068 | NOT_STARTED |
| Recall Frame 0x51, NO_REPLAY-Lineage | V13 §19.3 | `src/esp/xcf` | WP-068 | NOT_STARTED |
| Trust Vector | V13 App E | `src/esp/xcf` | WP-069 | NOT_STARTED |
| Typed Hive 0x70–0x73, EMO λ=0 | V13 §20 | `src/esp/hive` | WP-070 | NOT_STARTED |
| EU AI Act Art. 5(1)(f) Guard | V13 §23 | `src/esp/regulatory` | WP-078 | NOT_STARTED |
| Lizenz/REUSE/DCO | §52a | Repo-Root | WP-076 | NOT_STARTED |

---

# 57. Decision Log

Neue Decisions werden hier kurz gespiegelt und ausführlich als ADR gespeichert.

| ADR | Entscheidung | Status |
|---|---|---|
| ADR-0001 | QUIC als Referenztransport unter ESP | ACCEPTED |
| ADR-0002 | Keine Summennormierung menschlicher Emotionsintensitäten | ACCEPTED |
| ADR-0003 | Appraisal-Ursachen über Semantic Bindings statt EMO-Duplikation | ACCEPTED |
| ADR-0004 | Legacy Movie Ontology nur als Vocabulary/Mapping Seed | ACCEPTED |
| ADR-0005 | Lizenzmatrix AGPL-3.0-or-later / CC BY-SA 4.0 / CC BY 4.0, DCO statt CLA | ACCEPTED |
| ADR-0006 | Patent-Nichtangriffszusage für konforme Implementierungen | PROPOSED (Rechtsprüfung WP-084) |
| ADR-0007 | Markenrichtlinie und Siegel „ESP-Conformant“ nur nach bestandener Conformance-Suite | PROPOSED |
| ADR-0008 | `affect_scope` (CONTENT / SELF_DECLARED / INFERRED_SUBJECT / MACHINE_RELAY) | ACCEPTED |
| ADR-0009 | Deterministische Nonce-Ableitung (GAP-002) | ACCEPTED |
| ADR-0010 | `payload_len` = Ciphertext ohne Tag (GAP-003) | ACCEPTED |
| ADR-0011 | Addendum-TLV-Profil `esp-addendum-v1` (GAP-004) | ACCEPTED |
| ADR-0012 | Session Descriptor + Control-TLVs (GAP-005) | ACCEPTED |
| ADR-0013 | Static-Key-Cross-Signatur (GAP-006) | ACCEPTED |
| ADR-0014 | Layout `TLV_ANCHOR_COORDS` (GAP-007) | PROPOSED |
| ADR-0015 | Kanonisches Weglassen optionaler Capability-Felder (GAP-008) | ACCEPTED |
| ADR-0016 | `segment_seq`-Erschöpfung ⇒ Session-Neuaufbau (GAP-009) | ACCEPTED |
| ADR-0017 | Reservierte Header-Bits ablehnen; Capability-Bits 0–11 senden 0, empfangen ignorieren (GAP-011) | ACCEPTED |
| ADR-0018 | DP-Referenzprofile und Accountant (GAP-012) | ACCEPTED |
| ADR-0019 | Default Δ_clock pro Profil (GAP-013) | ACCEPTED |
| ADR-0020 | Fehlercode-Register (GAP-014) | PROPOSED |
| ADR-0021 | Referenzwahl MLS/FROST/Secure Aggregation für Hive (GAP-017) | PROPOSED |
| ADR-0022 | XCF-Gate-Protokoll (GAP-018) | PROPOSED |
| ADR-0023 | Transparenzlog-Profil (GAP-019) | PROPOSED |
| ADR-0024 | Datensatz-Register und Lizenzprüfung für ExperienceBench (GAP-023) | PROPOSED |
| ADR-0025 | Strikte SF-Level, Custom-Typ-Set-Profile (GAP-027) | ACCEPTED |
| ADR-0026 | SOS-Kodierung (GAP-028) | PROPOSED |
| ADR-0027 | Metadatenschutz-Profil (GAP-029) | PROPOSED |

---

# 58. Offene Forschungsfragen

Diese Punkte dürfen nicht still als gelöst markiert werden:

1. Welche TAOSS-Typzahl ist empirisch optimal?
2. Wie gut lassen sich Typen tatsächlich disentanglen?
3. Wie stabil sind Anchors über Kulturen und Encoder-Versionen?
4. Welche physiologischen Features generalisieren personübergreifend?
5. Wie viel subjektive Experience ist aus nicht-invasiver Sensorik überhaupt
   sinnvoll erfassbar?
6. Wie zuverlässig können Decoder semantische Zustände rekonstruieren?
7. Wann ist ein Anchor-Set ausreichend?
8. Wie viel Information über maskierte Typen bleibt synergistisch ableitbar?
9. Welche Teile des Appraisals sollten typübergreifend modelliert werden?
10. Wie sehen sichere zukünftige Neural-Output-Renderer aus?
11. Lässt sich DP-*Ausführung* (nicht nur Accounting) kryptografisch beweisen? (V13 OP „Verifiable Privacy Transformation“)
12. Wie viel Covert-Kapazität hat ein adaptiver, böswilliger Sender — über Empfänger-Extraktoren hinaus? (V13 OP „Adaptive Adversaries“)
13. Gibt es eine informationstheoretische Untergrenze für Experience-Transfer? (V13 OP „Floor“)
14. Wie wird Encoder-Identität über Versionen hinweg definiert? (V13 OP „Encoder Identity“)
15. Wie lassen sich gepaarte Mensch-/Maschinen-Daten für MEB-Alignment gewinnen?
16. Wann ist ein Typed-Hive-Emergenzbefund robust gegen Kopplungsartefakte?
17. Welche Side-Channels der Encoder-Inferenz sind praktisch ausnutzbar? (V13 OP „Side-Channel Resistance“)

---

# 59. Claims Ladder

Jede öffentliche Aussage muss einer Evidenzstufe entsprechen.

## Stufe 0

```text
Specification exists.
```

## Stufe 1

```text
Implementation conforms to wire and consent tests.
```

## Stufe 2

```text
Semantic states transfer correctly in synthetic / manual ground truth tests.
```

## Stufe 3

```text
Physiological and multimodal adapters operate reliably.
```

## Stufe 4

```text
Empirical models predict selected states on held-out data.
```

## Stufe 5

```text
H1/H2/H3 supported by preregistered ExperienceBench.
```

## Stufe 6

```text
Neural interface populates selected TAOSS fields in controlled experiments.
```

Keine höhere Stufe behaupten, solange die vorherigen Tests nicht erfüllt sind.

---

# 60. Definition von "fertig"

ESP/TAOSS v1.0 ist technisch fertig, wenn:

1. das semantische Modell implementiert ist;
2. V13 Wire Format byte-exakt implementiert ist;
3. Consent und Revocation maschinell erzwungen werden;
4. Python und Rust interoperabel sind;
5. Conformance Vectors öffentlich/reproduzierbar sind;
6. die BCI-freie Demo funktioniert;
7. Physiologieadapter mindestens synthetisch und als Replay funktionieren;
8. ExperienceBench ausführbar ist;
9. alle normativen Aussagen auf Tests zurückgeführt werden können;
10. keine kritische Spezifikationsabweichung undokumentiert ist.

Psychologische oder neurowissenschaftliche Forschung gilt dadurch **nicht** als
abgeschlossen.

---

# 61. Empfohlene Implementierungsreihenfolge

Strikt:

```text
M0
 ↓
M1
 ↓
M2
 ↓
M3
 ↓
M4
 ↓
M5
 ↓
M6
 ↓
M7
 ↓
M8
 ↓
M9
 ↓
M10
 ↓
M11
 ↓
M12
 ↓
M13   (Machine & Agent Governance — kann parallel ab M5 starten)
 ↓
M14   (XCF Persistence)
 ↓
M15   (Typed Hive, Research)
 ↓
M16   (Horizon Interfaces)
 ↓
M17   (maximale Ausbaustufe)
```

M3a liegt zwischen M3 und M4. M13 hängt nur von M5 ab und darf parallel zu
M6–M12 laufen, weil es weder Hardware noch Human Subjects braucht.

Keine EEG-Optimierung vor M5.

Keine neuronale Modellbehauptung vor M7/M8.

Keine H1/H2/H3-Behauptung vor M9 und sauberer Evaluation.

---

# 62. Was der Coding-LLM bei jedem neuen Chat zuerst tun soll

Prompt-kompatible Startanweisung:

```text
Read docs/MASTER_IMPLEMENTATION_PLAN.md completely.
Read docs/IMPLEMENTATION_STATUS.md and all ADRs referenced by the current work package.
Identify the earliest non-VERIFIED work package whose dependencies are VERIFIED.
Inspect the repository before coding.
Implement only that work package and directly necessary dependencies.
Add or update unit, property, integration and milestone tests as specified.
Run the required tests.
If implementation must differ from the plan, do not silently diverge:
create/update an ADR and update the master plan in the same change.
Update status, traceability matrix and test evidence before finishing.
Do not claim VERIFIED unless the specified acceptance tests pass.
```

---

# 63. Quellen und externe technische Anker

## ESP

- The Experience Semantic Protocol, Version V13, 25 September 2026.
- Normativer Ausgangspunkt dieses Masterplans.

## Emotion Modelling

- W3C Emotion Markup Language 1.0.
  - Kategorien, Dimensionen, Appraisals, Action Tendencies,
    Confidence und zeitliche Traces.
- Geneva Emotion Wheel.
  - Mehrere gleichzeitig berichtbare Emotionen mit eigener Intensität.
- Component Process / Appraisal Tradition nach Klaus Scherer.
  - Emotion als mehrkomponentiger dynamischer Prozess.

## Physiological / Neural Data

- BrainFlow.
  - Synthetic Board, Playback Board und Streaming Board ermöglichen
    hardwarefreie Entwicklung.
- Lab Streaming Layer.
  - Multi-Stream-Aufzeichnung, Zeitstempel und Clock-Offset-Information.
- Extensible Data Format.
  - Replay von multimodalen LSL-Aufzeichnungen.
- Brain Imaging Data Structure.
  - Referenz für strukturierte neuro- und physiologische Forschungsdaten.

## Transport

- RFC 9000 — QUIC.
- RFC 9001 — TLS für QUIC.
- RFC 9221 — QUIC Datagram Extension.

---

# 64. Letzte Designentscheidung vor Implementierungsstart

Der erste Coding-Schritt ist **nicht**:

```text
train emotion detector
```

und nicht:

```text
connect EEG
```

Der erste Schritt ist:

```text
build a correct semantic and protocol substrate
```

Reihenfolge:

```text
semantics
→ schemas
→ ontology
→ simulation
→ wire
→ consent/security
→ network transport
→ BCI-free demo
→ physiology
→ inference
→ learned TAOSS
→ ExperienceBench
→ independent implementation
```

Damit bleibt das System testbar, falsifizierbar und hardwareunabhängig.

---

# 65. Projektstatus

```yaml
current_milestone: M5
next_work_package: WP-025
overall_status: IN_PROGRESS
plan_version: "0.2.0"
scope_target: "MAXIMAL (M17)"
wire_version: "1.0"
taoss_profile: "TAOSS-6 / 512"
reference_transport: "QUIC (hinter Transport-Abstraktion, ADR-0001)"
psychology_model_status: "PROPOSED_ADDENDUM"
affect_scope_model: "PROPOSED (ADR-0008)"
license_model: "ACCEPTED (ADR-0005)"
open_gaps: 12        # GAP-007, 014–020, 022–024, 030
resolved_gaps: 16    # GAP-001–006, 008–013, 021, 025–027
work_packages_total: 86   # WP-000 … WP-085
experiencebench_status: "DESIGN"
independent_implementation_status: "NOT_STARTED"
```

Dieses Statusobjekt ist bei jedem abgeschlossenen Arbeitspaket zu aktualisieren.
