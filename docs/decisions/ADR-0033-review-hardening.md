<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ADR-0033: Hardening after the external review of 2026-09-29

- Status: ACCEPTED (security fixes; implemented)
- Context: an external code review ([report and status](../reviews/2026-09-29-external-review.md))
  confirmed integration gaps between individually correct components. Examples:
  - a gate that trusted an unsigned capability;
  - `previously_accepted=True` passed unconditionally;
  - two privacy ledgers overwriting each other.

## Decisions

1. **XCF gate release (F01).** `Gate.release` takes the *signed* sender capability TLV. The
   issuer must be the gate's registered owner. A `ReleaseRequest` signed by the recipient
   identity binds CID, grant digest, HPKE recipient key and an expiry. The recipient must be in
   the capability's audience. A correctly signed but foreign grant never opens a capsule.
2. **Recall (F12).** It requires `ALLOW_REPLAY`, a verified capability, the audience and no
   revocation. Every ancestor must be present, correctly addressed and signed, and issued by the
   same issuer. A missing ancestor or missing policy evidence refuses the recall (fail closed).
3. **Key rotation (F02).** A grant counts as *previously accepted* only if its canonical
   digest was accepted before. A rotated key cannot issue fresh grants.
4. **Differential privacy (F03, F04, F08, F09).**
   - A sender refuses a non-NONE DP descriptor without a matching DP configuration, and the
     ledger must bind the capability and respect its ceiling.
   - Ledger charges are serialized across processes with an exclusive SQLite lock, and the
     state is reloaded inside the lock.
   - Receivers audit *cumulative* RDP; they never multiply the last release by k.
   - An identical, authenticated release (same header and payload) is not charged twice, so a
     throttled packet can be retransmitted.
5. **Session binding (F06, F07).**
   - The effective payload limit is the minimum of both descriptors, enforced on both sides.
   - Profile, SF level and DP level of every packet must equal the negotiated values.
   - Wire extensions (addendum, anchor sets) are used only if both peers pinned them.
6. **Control channel (F10).**
   - A control packet is validated completely before any effect is applied.
   - A malformed control packet is a rejection, never an exception into the receiver pump.
   - A descriptor change closes the session.
   - Only registered application objects (0x98, 0x99) pass through.
7. **Affect bounds (F05).** Every affect descriptor's valence is checked against the receiver's
   interval.
8. **Resources (F11).** Retransmit and digest caches are bounded (default 8192). Evicted
   sequence numbers are never re-encrypted.
9. **Persistent receiver consent (open item of the review).** `ConsentStateStore` persists
   segment counters, cumulative ε, accepted grants and revocations.
   - Each decision runs in one exclusive transaction.
   - Counters never decrease.
   - The reference demo receiver uses it.
10. **Benchmarks (F13).** LEACE, the learned filter and Procrustes alignment are fitted on
    training units only and evaluated on held-out units.
11. **Rust peer (F14).** `esp-rs` is an *interop peer* for a deliberately limited profile (KNO,
    DP NONE, SF0). Within it, the peer enforces fail closed:
    - capability fields, per-packet expiry, `max_segments`;
    - rights, norm cap and negotiated profile;
    - the verified receiver capability.
    
    It is not a second full implementation of every consent rule.

## Consequences

- `Gate.release` and `recall` have new, stricter signatures.
- `ReceiverEndpoint.receive` returns a rejection instead of raising on malformed control.
- Receivers that serve several sessions or restart must use a `ConsentStateStore`. Without
  one, limits are per endpoint (documented and tested).
