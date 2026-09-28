# Trademark and Conformance Mark Policy

Status: **PROPOSED** (ADR-0007) — subject to legal review (WP-084).

The source code of this project is free software under AGPL-3.0-or-later.
The license deliberately does **not** grant rights to the project's names
(AGPL-3.0 Section 7(e)). This policy protects users: anyone who sees the
name "Experience Semantic Protocol" or the mark "ESP-Conformant" must be
able to trust that the software actually implements the protocol,
including its consent, masking and revocation guarantees.

## Names covered

- "Experience Semantic Protocol"
- "TAOSS" (Typed Approximately Orthogonal Semantic Subspaces)
- "ESP-Conformant" (conformance mark)

## Always allowed, without asking

- Truthful statements of origin: "based on the ESP reference
  implementation", "implements the Experience Semantic Protocol V13".
- Referring to the protocol in articles, papers, talks, documentation,
  and comparisons.
- Using the names in unmodified redistributions of this project.
- Commercial products and services that use or implement ESP, as long as
  the name is not used to imply endorsement by Vigilant e.K.

## Requires passing the public conformance suite

The mark **"ESP-Conformant"** (and phrasing that claims conformance) may be
used only by an implementation that:

1. passes the public conformance suite (`esp-conformance run`, WP-039)
   for the claimed profile(s) and version,
2. publishes the machine-readable conformance report (including commit,
   suite version and results), and
3. keeps the claim limited to the profiles and version actually tested.

A conformance claim lapses when the implementation changes in a way that
would fail the suite, or when the claimed suite version is withdrawn for a
security defect.

## Not allowed

- Naming a fork or product "Experience Semantic Protocol" or "TAOSS" in a
  way that suggests it *is* the official project.
- Claiming ESP conformance for software that does not enforce the
  normative consent, masking or revocation rules (for example, "masking"
  that merely hides data in the UI while it is still in the decryptable
  payload).
- Implying endorsement, certification or partnership by Vigilant e.K.
  without written agreement.

## Contact

Questions and permission requests: open an issue in the repository.
