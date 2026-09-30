<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Manual threat-model review: checklist

The reviewer should not have written the code. For each item, record: agree / disagree (why) /
residual risk accepted by whom.

## Scope and assets

- [ ] Assets and trust boundaries in [ARCHITECTURE](../guide/ARCHITECTURE.md) are complete,
  including the receiver consent store, the privacy ledgers, gate secrets and the
  transparency log keys.
- [ ] The adversary classes cover malicious senders, malicious receivers, network attackers,
  colluding receivers, compromised devices and insiders at the log or gate operator.

## Per threat (T1–T19 in `docs/THREAT_MODEL.md`)

For each threat check four things:
- the mitigation exists in code;
- a test fails if the mitigation is removed (mutation evidence);
- the residual risk is stated;
- no mitigation relies on the in-memory default where persistence is needed.

## Focus areas from the external review (ADR-0033)

- [ ] Authorization chains end to end: capability → gate / recall / endpoint. Is every hop
  signed and bound (issuer, audience, recipient key, session)?
- [ ] State that must survive restarts is persistent and serialized across processes:
  segments, ε, grants, revocations, sequence numbers.
- [ ] Failure behaviour: malformed control or data never raises into the pump; the session
  closes when it must.
- [ ] Resource bounds under hostile load: caches, queues, decode budget.

## Privacy

- [ ] DP parameters, the accountant and the float-sampler limitation (errata E-11).
- [ ] Cross-type leakage: the reference encoder leaks masked EMO (R² ≈ 0.78). Is the
  audit-then-refuse rule sufficient for deployment?
- [ ] Metadata protection (ADR-0027) and its limits: rate, volume, endpoint identity.
- [ ] Neural data: L4-live is refused, L4-replay requires a declaration, EMO/KNO are never
  taken from neural data (ADR-0034).

## Reference-grade parts that need hardening before production

- [ ] FROST, DKG and Shamir custody are pure Python and not constant time.
- [ ] The guardian quorum runs in one process in the reference gate.
- [ ] The Rust peer is an interop peer with a limited profile (ADR-0033 §11).

## Outcome

Sign the result into `RELEASE_1.0.md` (row "Manual threat-model review").
