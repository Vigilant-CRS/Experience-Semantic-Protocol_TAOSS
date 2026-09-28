<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ADR-0028 — MEB type-set profiles and ESP-Agent TLVs

- Status: PROPOSED (implemented; awaiting maintainer review)
- Work packages: WP-066 (MEB), WP-067 (ESP-Agent)
- Related: ADR-0011 (addendum profile), ADR-0025 (strict SF levels, custom type-set profiles)

## Context

V13 §17 requires that machine-authored packets never carry EMO. For `MEB-HANDOVER` it
requires `EMO_MASKED=1` and no KNO, and receivers verify both before decoding. Surgical
assistance makes `NO_REPLAY` mandatory. V13 §18.1 lists the mandatory fields of an
authenticated opaque-latent descriptor, but gives it no wire encoding.

## Decision

1. **Type-set profiles gain two fields** (`esp.session.profiles.TypeSetProfile`):
   - `must_mask`: types that must be explicitly masked in every data packet. Only EMO has a
     header mask bit, so the header must carry `EMO_MASKED=1`.
   - `required_consent_flags`: header consent flags every data packet must carry.

   Both endpoints enforce them. The receiver checks them inside the quarantine, before the
   Accept predicate and the decoder.

   A definition with these fields pins them in its registry digest. Older definitions keep
   their digests unchanged.
2. **MEB domain profiles** are pinned custom type-set profiles (`sf_level = 0`, ADR-0025).
   Each one has EMO in `must_mask`:

   | Registry | Name | Required | Optional | Flags |
   |---|---|---|---|---|
   | `esp-typeset-meb-handover-v1` | MEB-HANDOVER | INT, CTX, TEM, SEN | – | – |
   | `esp-typeset-meb-robotic-v1` | MEB-ROBOTIC | INT, SEN, TEM, KNO | – | – |
   | `esp-typeset-meb-surgical-v1` | MEB-SURGICAL | INT, SEN, TEM, KNO | – | NO_REPLAY |
   | `esp-typeset-meb-swarm-v1` | MEB-SWARM | INT, CTX, TEM | KNO, SEN | – |
   | `esp-typeset-meb-assistive-v1` | MEB-ASSISTIVE | CTX, SEN, INT | – | – |
   | `esp-typeset-agent-v1` | AGENT | KNO | INT, CTX | – |

   The assistive EMO relay is not part of `T_mach`. It is human-origin affect, carried with
   `affect_scope = machine_relay`, human-origin references and L2+ consent.
3. **Addendum TLV codes** (in `esp-addendum-v1`, range 0x80–0x9F):
   - `0x98` AGENT_OPAQUE_LATENT_DESCRIPTOR. Its fields:
     - state kind; tensor schema (dtype, shape, layer range);
     - model and model-version digests; payload digest and length;
     - agent public key; recipient-capability digest;
     - ESP transcript hash; event id; optional visible-action digest;
     - an Ed25519 signature by the agent (domain `esp/agent/v1/descriptor`).
   - `0x99` AGENT_EVENT: a signed, event-linked audit statement (kind, event id, causing
     event id, subject digest, agent key).
   - `0x9A` and `0x9B` stay reserved for this profile.

   Both travel on CONTROL (`types_bitmap = 0`). The tensor itself uses a companion stream.
4. **Naming rule.** Opaque payloads are never described as TAOSS, and reports carry no
   TAOSS types or consent guarantees for them. `g_agent` output is called TAOSS only after a
   passed pairwise leakage audit.

## Consequences

- A buggy or malicious machine sender cannot get EMO, a missing `EMO_MASKED` or a missing
  `NO_REPLAY` past a receiver. The receiver rejects it before decoding (tested with crafted
  packets).
- Changing the `MEB-HANDOVER` definition changed its registry digest. No published vector
  pinned the old one.
- The cross-domain alignment (`esp.meb.alignment`) is EXPERIMENTAL: linear per-type maps
  trained on synthetic pairs. V13 names paired-data acquisition as an open problem.
