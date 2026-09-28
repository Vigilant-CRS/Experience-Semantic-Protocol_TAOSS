# ADR-0005 — Lizenzmodell: AGPL-3.0-or-later / CC BY-SA 4.0 / CC BY 4.0, DCO statt CLA

- Status: ACCEPTED
- Datum: 2026-09-28
- Plan-Referenz: §52a, WP-076

## Kontext

Anforderung des Maintainers: Der Kern muss immer frei bleiben, auch wenn
Dritte ihn kommerziell nutzen. Namensnennung ist Pflicht. Kommerzielle
Nutzung soll erlaubt sein. ESP soll ein offener, unabhängig
implementierbarer Standard werden.

## Betrachtete Optionen

1. AGPL-3.0-or-later + CC BY-SA, DCO (gewählt)
2. MPL-2.0 + CC BY-SA: bessere Industrie-Adoption, aber SaaS-Lücke
   (veränderter Kern als Dienst ohne Offenlegung)
3. AGPL + CLA/Dual Licensing: Einnahmequelle, aber der Kern ist dann nur
   so frei, wie der Rechteinhaber es hält

## Entscheidung

Option 1: Code unter AGPL-3.0-or-later; Spezifikation, Doku und Ontologie
unter CC BY-SA 4.0; Testvektoren und Schemas unter CC BY 4.0;
Namensnennung über AGPL §7(b) (`NOTICE`); Marken über AGPL §7(e)
(`TRADEMARKS.md`); Beiträge per DCO 1.1, kein CLA.

## Konsequenzen

- Keine proprietäre Umlizenzierung des Kerns möglich, auch nicht durch
  den Maintainer.
- Einbindung als Bibliothek in geschlossene Produkte ist nicht möglich;
  Protokoll-Kommunikation und unabhängige Implementierungen bleiben frei.
- Dual Licensing ist künftig nur für Code möglich, der allein Vigilant
  gehört.
- Rechtsprüfung vor v1.0 (WP-084).
