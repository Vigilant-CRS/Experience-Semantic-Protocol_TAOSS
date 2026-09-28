<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Release candidate 1.0 (WP-047, milestone M12)

The M12 gate (`scripts/run_milestone.py M12`) checks everything a machine can check. It
passes only when every human sign-off below is recorded as `APPROVED`. Until then the release
candidate is **technically complete but not released**.

## Automated criteria

| Criterion (plan WP-047) | How it is checked |
|---|---|
| all required v1 work packages VERIFIED | `tests/milestone/test_m12.py` reads the plan |
| Python/Rust interop green | `tests/interop/` (live matrix), M10 gate |
| conformance green | `tests/conformance/`, `esp-conformance run` |
| security smoke green | `security`-marked tests, `scripts/security_review.py` (M11) |
| docs complete | `docs/guide/` executed by `tests/unit/test_docs_examples.py` |
| versioned test vectors frozen | `vectors/FROZEN-1.0.0.json`, `scripts/freeze_vectors.py --check` |
| no unresolved critical ADR | sign-off table below (the maintainer decides) |

## Human sign-offs

Only the maintainer (or the named reviewer) changes a row, in a signed-off commit.
Allowed values: `PENDING`, `APPROVED`. A rejected ADR is replaced by a revised one and then
approved.

<!-- signoffs:start -->
| Item | Blocks 1.0 | Status | By | Date |
|---|---|---|---|---|
| WP-084 legal review (license matrix, NOTICE §7(b), trademark policy, patent pledge, regulatory docs) | yes | PENDING | | |
| Manual threat-model review (`docs/THREAT_MODEL.md`, T1–T19) | yes | PENDING | | |
| ADR-0014 anchor coordinates 0x50 layout | yes | PENDING | | |
| ADR-0023 transparency log: who operates log and witnesses | yes | PENDING | | |
| ADR-0026 SOS encoding | yes | PENDING | | |
| ADR-0027 metadata-protection profile | yes | PENDING | | |
<!-- signoffs:end -->

Not blocking 1.0; these are decided with their own tracks:

- ADR-0021 (Typed Hive);
- ADR-0022 (XCF gate);
- ADR-0028 (MEB and agent profile);
- ADR-0030 (replay watermark).

## Known, documented limitations of 1.0

See [What ESP is not](../guide/WHAT_ESP_IS_NOT.md) and the claims ladder (plan §59). In
particular:

- no post-quantum protection (`pq_mode = CLASSICAL_ONLY`);
- float Gaussian DP sampler (errata E-11);
- the covert-channel hardening defaults are experimental (errata E-27);
- no human-study evidence for H1–H3.
