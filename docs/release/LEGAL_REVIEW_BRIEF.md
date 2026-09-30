<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Legal review brief (WP-084)

This is the briefing for counsel. It lists what to review and the concrete questions. It is not
legal advice and makes no legal decision.

## 1. License model (ADR-0005, `docs/LICENSING.md`, `REUSE.toml`)

- Code AGPL-3.0-or-later; spec, docs and ontology CC BY-SA 4.0; test vectors and schemas
  CC BY 4.0; DCO, no CLA.
- **Questions:**
  1. Is the split enforceable as intended, in particular the permissive CC BY 4.0 vectors
     next to AGPL code?
  2. Does AGPL §13 (network use) work as intended for ESP services, and is the
     "Corresponding Source" notice in the demo UI sufficient?
  3. Without a CLA, the project can never relicense contributions. Is that acceptable to
     Vigilant e.K.?

## 2. NOTICE, additional terms under AGPL §7(b) and §7(e)

- `NOTICE` requires a fixed attribution text in source, binaries and interactive
  UIs/network services, plus a modification statement.
- **Questions:**
  1. Is the text a "reasonable author attribution" under §7(b), or could it count as a
     "further restriction" that a recipient may remove (§7, last paragraphs)?
  2. Is the UI placement requirement proportionate?

## 3. Patent non-assertion pledge (`PATENTS.md`, ADR-0006, draft)

- The pledge covers independent implementations of the specification, with defensive
  termination.
- **Questions:**
  1. Scope: are "necessarily infringed" claims and conformant implementations defined
     precisely enough?
  2. Does defensive termination work in German and EU law?
  3. Interaction with AGPL §11.
  4. Does Vigilant e.K. hold, or plan to file, any relevant patent applications?

## 4. Trademark and conformance mark (`TRADEMARKS.md`, ADR-0007)

- Names: "Experience Semantic Protocol", "TAOSS", "ESP-Conformant".
- **Questions:**
  1. Registration strategy (EUIPO / DPMA / others) and clearance search.
  2. Is it lawful to tie the conformance mark to passing `esp-conformance`?
  3. Is the "always allowed" list compatible with trademark law?

## 5. Regulation (`docs/REGULATORY.md`, `src/esp/regulatory/`)

- **EU AI Act:**
  - Art. 5(1)(f): emotion recognition at work and in education is prohibited. ESP
    enforces a declared deployment context.
  - Annex III high-risk classification for subject-side inference (profile L2).
  - Do the runtime guards and the declaration model match the Act's obligations for
    providers versus deployers?
- **GDPR:**
  - Affect, physiology and neural data are special-category data under Art. 9 (health,
    biometric).
  - Are the consent capabilities an adequate technical implementation of Art. 7 and
    Art. 9(2)(a) consent, including withdrawal (Art. 7(3)), for which ESP has signed
    revocation?
  - Art. 17: deletion attestations, and the explicit statement that copied plaintext
    cannot be erased cryptographically.
  - Art. 25: data protection by design.
- **Neural data:** several jurisdictions protect neural data specifically (e.g. Chile's
  constitutional neurorights, US state laws such as Colorado and California). Does
  ESP's L4 policy (live invasive sources refused, replay only with a declaration) fit
  them?
- **Medical devices (MDR):** could any ESP component be a medical device or an accessory
  if used with implants? The project claims no medical purpose.

## 6. Third-party data and dependencies

- **Datasets:** the public datasets are CC BY 4.0, ODC-By 1.0, BSD-3-Clause or MIT (see
  `datasets/neural.json`, `datasets/registry.json`). The repository publishes derived
  numbers and citations, but not the data.
  - Is the README's attribution sufficient?
  - Are there obligations from the data's original consent terms?
- **Dependencies:** licenses of Python/Rust dependencies, checked by `cargo-deny` and the
  lockfile. Are any AGPL-incompatible?
- **Legacy movie ontology:** proprietary; it is used only at runtime and never vendored
  (ADR-0004). Is that sufficient separation?

## 7. Claims and liability

- The public claims are tied to the claims ladder (`docs/CLAIMS.md`). The README states
  what is and is not shown on real data.
- **Questions:**
  1. Are there statements that could be read as medical or safety claims?
  2. Is a disclaimer beyond the licenses' warranty exclusions needed?

## Deliverable

For each section: acceptable as is / change needed (with text) / blocker. Then record the
result in the sign-off table of `RELEASE_1.0.md`.
