<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Regulatory layer (WP-078)

> **Not legal advice.** This page maps protocol mechanisms to EU instruments
> for engineers (V13 §23). Deploying parties must obtain their own counsel.
> The project's legal review (WP-084) is pending. Nothing here is a
> conformity claim.

## 1. Mandatory declaration

Every ESP endpoint is constructed with a `RegulatoryDeclaration`
(`esp.regulatory.guard`). Without one, the endpoint does not start
(`REGULATORY_DECLARATION_MISSING 0x0800`).

| Field | Meaning |
|---|---|
| `regimes` | `eu_ai_act`, `eu_gdpr`, `other` (sorted, at least one) |
| `intended_use` | free-text purpose statement (logged) |
| `deployment_context` | `workplace`, `education`, `medical`, `safety`, `other` |
| `biometric_inputs` | are inputs biometric data in the legal sense (face, voice, physiology, neural)? |
| `affect_scopes` | every `affect_scope` the pipeline may output (`content`, `self_declared`, `inferred_subject`, `machine_relay`) |
| `infers_subject_intention` | does the system infer natural persons' intentions? |
| `exemption` + `exemption_justification` | `medical` / `safety` exception, justification mandatory |
| `high_risk_declared` | the deployer acknowledges Annex III high-risk status |

`audit_record()` returns the declaration, its BLAKE2b-256 digest, the
classification and the obligations checklist. Endpoints expose the
assessment as `endpoint.regulatory`.

## 2. EU AI Act

### Article 5(1)(f) guard

The pipeline does not start (`REGULATORY_PROHIBITED_PRACTICE 0x0801`) when
all of the following hold:

1. The regime includes `eu_ai_act`.
2. `biometric_inputs` is true.
3. `affect_scopes` contains `inferred_subject` (inferring a natural person's emotion).
4. The context is `workplace` or `education`.
5. There is no medical or safety exemption.

A unit test covers every combination of these fields (13,440 cases).

### Annex III

Other emotion-recognition systems are high-risk. That means a biometric
input combined with inferred subject emotions or subject intentions. They
must set `high_risk_declared`, otherwise the start fails with
`REGULATORY_MISDECLARED 0x0802`. The assessment lists these obligations:

- risk management (Art. 9)
- data governance (Art. 10)
- technical documentation (Art. 11, Annex IV)
- logging (Art. 12)
- transparency (Art. 13)
- human oversight (Art. 14)
- accuracy, robustness and security (Art. 15)
- QMS (Art. 17)
- conformity assessment and registration (Art. 43, 49)
- informing exposed persons (Art. 50(3))
- FRIA where applicable (Art. 27)

### Content-side is not a safe harbour

V13 §23: labelling affect as "content" does not take a system outside the
regime if biometric signals are used to infer a person's emotion. Declare
`inferred_subject` whenever that happens.

### Runtime enforcement

Both endpoints check every frame. The sender refuses to send, and the
receiver refuses to deliver (`regulatory:` violation), any frame whose
affect statements carry an `affect_scope` outside the declaration. Emotion
episodes carry no scope of their own (GAP-030). Under a declaration they
are only accepted together with an affect descriptor in the same EMO block.

## 3. GDPR mapping

| GDPR | Protocol mechanism |
|---|---|
| Art. 4(11), 7: consent (specific, informed, withdrawable) | Signed `SenderCapability` per type set, audience and expiry. Withdrawal via `TLV_REVOCATION_INTENT` is as easy as granting. Revoked capabilities cannot open new sessions. |
| Art. 5(1)(c): data minimisation | Per-type masking removes objects from the payload (not just hides them). Default-deny receiver (KNO+CTX). Bindings default-deny. Evidence refs dropped unless kept. Anchor-only frames (no latent). |
| Art. 5(2): accountability | Declaration digest and audit record. Transparency log for key lineage. Deletion attestations. Milestone evidence reports. |
| Art. 9: special categories (health, biometric) | Affect and physiological latents are treated as sensitive by default. `EMO_MASKED` by default. The regulatory declaration records biometric status. |
| Art. 17: erasure | `Effects.REQUEST_DELETE_STORED` / `REQUEST_DELETE_DERIVED` plus `TLV_DELETION_ATTESTATION` bound to the request digest. |
| Art. 25: data protection by design and by default | Default deny. Quarantined receiving (no decoding before acceptance). Runtime DP profiles. Metadata protection profile (ADR-0027). |
| Art. 35: DPIA | Template below. |

## 4. DPIA template (Art. 35)

1. **Processing description:** purpose (`intended_use`), TAOSS types, SF
   profile, rates, retention (`ALLOW_STORE`, `ALLOW_REPLAY`), recipients
   (audience).
2. **Necessity and proportionality:** why each type is needed. Why weaker
   profiles (SF level, anchor-only, DP level) do not suffice.
3. **Risks to data subjects:**
   - inference of emotional or mental state;
   - re-identification from latents (inversion audit, WP-058);
   - metadata leaks (ADR-0027);
   - function creep;
   - coercion in asymmetric relationships (workplace, education).
4. **Measures:**
   - consent capabilities, revocation, DP ledger;
   - masking defaults, metadata protection;
   - regulatory guard, audit records;
   - human oversight, access control on stored capsules.
5. **Residual risk and decision:** sign-off, DPO consultation, prior
   consultation (Art. 36) if the residual risk stays high.
6. **Review:** trigger conditions (new types, new contexts, new estimators),
   review date.
