# Lizenzierung — Überblick und FAQ

Kurzfassung: **Der Kern bleibt für immer frei. Kommerzielle Nutzung ist
erlaubt. Namensnennung ist Pflicht.**

Maßgeblich sind `LICENSE`, `LICENSES/`, `REUSE.toml` und `NOTICE`. Dieses
Dokument erklärt sie und ist keine Rechtsberatung.

## Lizenzmatrix

| Bereich | Lizenz |
|---|---|
| Referenzimplementierung (Code) | AGPL-3.0-or-later |
| Spezifikation, Companion Specs, Doku | CC BY-SA 4.0 |
| Ontologie, Anker-Sets | CC BY-SA 4.0 |
| Testvektoren, JSON-Schemas | CC BY 4.0 |
| Namen „Experience Semantic Protocol“, „TAOSS“, „ESP-Conformant“ | Markenrichtlinie (`TRADEMARKS.md`) |

## Warum dieses Modell?

- **AGPL-3.0-or-later** sorgt dafür, dass jede veränderte Version des
  Kerns offen bleibt, auch wenn sie nur als Netzdienst betrieben und nie
  „verteilt“ wird (AGPL §13).
- **DCO statt CLA**: Mitwirkende behalten ihre Rechte. Deshalb kann
  niemand, auch nicht Vigilant, den Kern später proprietär umlizenzieren.
- **CC BY 4.0 für Vektoren und Schemas**: Wer ESP unabhängig
  implementiert, muss gegen dieselben Testvektoren prüfen können. Nur so
  ist Interoperabilität möglich.
- **NOTICE (AGPL §7(b))** macht die Namensnennung verbindlich, auch in
  Benutzeroberflächen.
- **Markenrichtlinie (AGPL §7(e))**: Nur wer die Conformance-Suite
  besteht, darf „ESP-Conformant“ sagen. Das schützt Nutzer vor
  Implementierungen, die Consent oder Masking nur vortäuschen.

## FAQ: Darf ich …?

| Frage | Antwort |
|---|---|
| … ESP in einem kommerziellen Produkt nutzen? | **Ja.** |
| … den Kern unverändert als bezahlten Dienst betreiben? | **Ja.** NOTICE anzeigen, Link zur Quelle anbieten. |
| … den Kern verändern und als Dienst betreiben? | **Ja**, aber der veränderte Quelltext des Kerns muss den Nutzern des Dienstes angeboten werden (AGPL §13). |
| … den Kern als Bibliothek in mein geschlossenes Programm einbinden? | Nur wenn das Gesamtwerk unter AGPL weitergegeben wird. |
| … ein eigenes, geschlossenes Programm schreiben, das nur über das ESP-Protokoll mit dem Kern kommuniziert? | **Ja.** Kommunikation über ein Wire-Protokoll macht ein separates Programm nicht zum abgeleiteten Werk. |
| … ESP unabhängig nach der Spezifikation neu implementieren, auch proprietär? | **Ja.** Die Spezifikation ist offen. Namensnennung nach CC BY-SA; „ESP-Conformant“ nur nach bestandener Conformance-Suite. |
| … Hardware, Sensoren, Beratung, Zertifizierung oder Hosting verkaufen? | **Ja.** |
| … eine proprietäre Version des Kerns anbieten? | **Nein.** |
| … mein Produkt „Experience Semantic Protocol“ nennen? | Nein, siehe `TRADEMARKS.md`. „Based on ESP“ ist erlaubt. |

## Pflichten in Kürze

1. NOTICE-Hinweis erhalten, in Quelltext, Binärdateien und
   Benutzeroberflächen.
2. Änderungen kennzeichnen (AGPL §5(a)).
3. Den Quelltext des Kerns anbieten, auch bei Netzbetrieb (AGPL §13).
4. Namensnennung für Spezifikation, Doku, Ontologie und Vektoren (CC BY / BY-SA).

## Status

- ADR-0005 (Lizenzmatrix, DCO): ACCEPTED
- ADR-0006 (Patentzusage, `PATENTS.md`): PROPOSED, noch nicht in Kraft
- ADR-0007 (Markenrichtlinie): PROPOSED
- Rechtsprüfung vor v1.0: WP-084
