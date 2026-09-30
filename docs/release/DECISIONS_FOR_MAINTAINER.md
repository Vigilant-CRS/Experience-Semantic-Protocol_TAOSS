<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Open decisions and recommendations for the maintainer

Formal acceptance is the maintainer's act. Each item below comes with a clear recommendation
and the reason for it. Every item is implemented and tested; the decision is whether its
design becomes the project's normative choice.

To accept an item:

1. set the ADR's status to `ACCEPTED (date)`;
2. update its row in the plan's decision log (§57);
3. for release-blocking items, set the row in `RELEASE_1.0.md` to `APPROVED`.

Do it in one signed-off commit.

## Blocking release 1.0

| ADR | Topic | Recommendation | Why |
|---|---|---|---|
| ADR-0014 | Anchor coordinates `0x50` layout (kind byte cosine / projection / RBF) | **Accept** | Implemented, byte-exact vectors, used by M14. The kind byte keeps it extensible. |
| ADR-0023 | Transparency log: operator, witnesses, quorum | **Accept, with:** Vigilant e.K. operates the reference log for the public registries; deployments run their own log with the same profile; at least 3 independent witnesses; quorum 2-of-3 for L1, 3-of-5 for L2+ (health or neural data) | Makes key rotation and DP checkpoints publicly auditable. With C2SP formats (being implemented), public transparency witnesses can cosign without new infrastructure. |
| ADR-0026 | SOS as control TLV `0x86` | **Accept** | Minimal, carries no EMO/KNO, and works on the reliable CONTROL channel under 10 % loss (M4 gate). |
| ADR-0027 | Metadata-protection profile (constant bitmap, decoys, padding, timing buckets) | **Accept** | Header and size features become identical with and without EMO (traffic-analysis test), and one-sided configuration fails closed. |

## Not blocking, recommended now

| ADR | Topic | Recommendation |
|---|---|---|
| ADR-0021 | Typed Hive reference profile | **Accept** as the v2-research reference. MLS and anonymous credentials stay open (GAP-017). |
| ADR-0022 | XCF gate protocol | **Accept.** Hardened after the external review (signed grant, owner and recipient binding). |
| ADR-0028 | MEB and ESP-Agent profiles, TLV `0x98`/`0x99` | **Accept.** |
| ADR-0030 | Replay watermark `0x89` | **Accept.** An asymmetric-key variant can follow as a separate profile. |
| ADR-0034 | Neural companion profile (M18) | **Accept.** The wire is unchanged, EMO/KNO are never taken from neural data, and it is tested on real implant data. |

## Still needs people outside the codebase

- **WP-084 legal review:** see [LEGAL_REVIEW_BRIEF.md](LEGAL_REVIEW_BRIEF.md).
- **Manual threat-model review:** see [THREAT_REVIEW_CHECKLIST.md](THREAT_REVIEW_CHECKLIST.md).
  It should be done by someone who did not write the code. The external review of
  2026-09-29 covered code integration, not the threat model as a whole.
