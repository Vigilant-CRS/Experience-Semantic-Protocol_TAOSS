<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Conformance guide and the "ESP-Conformant" mark

## Run the suite

```bash
uv run esp-conformance run --json report.json                     # this implementation
uv run esp-conformance run --peer path/to/your-binary --json report.json   # yours, live
```

Categories:

| Category | What it checks |
|---|---|
| `index` | vector file digests |
| `wire` | headers and typed latents, byte-exact re-encoding |
| `malformed` | every invalid header and latent must be refused |
| `crypto` | key derivation, open, byte-identical reseal, tamper detection |
| `consent` | sender and receiver capabilities |
| `revocation` | revocation intent, deletion attestation |
| `identity` | identity proof, session binding |
| `session` | session descriptor encoding and digest |
| `replay` | window accept patterns |
| `privacy` | `TLV_DP_PARAMS` |
| `ontology` | registry digest |
| `interop` | only with `--peer`: both directions, including revocation |

## Implementing a peer for `--peer`

Your binary must implement two commands and print JSON lines. The reference is
`rust/esp-rs`, and `src/esp/conformance/interop.py` documents the contract.

- `send --addr H:P --responder-static HEX --receiver-id HEX --master-seed HEX --static-seed HEX --frames N [--revoke-after K --ignore-revocation yes]`
- `receive --addr H:P --static-seed HEX --identity-seed HEX --trusted HEX`

Transport: TCP, frames `len u32 BE · channel u8 · data`.

## The conformance mark

Per [TRADEMARKS.md](../TRADEMARKS.md), "ESP-Conformant" may be used for an implementation
version that meets three conditions:

1. It passes `esp-conformance run` for the suite version it claims (`vectors/INDEX.json`,
   `suite_version`).
2. It publishes the JSON report together with:
   - the implementation name and version,
   - the commit,
   - the suite version,
   - the date.
3. It keeps enforcing consent. An implementation that decodes before acceptance, or ignores
   revocations, is not conformant even if its codec passes.

Publication process:

1. Open a pull request that adds the report under `artifacts/conformance/<implementation>/<version>.json`.
2. Maintainers re-run the suite against the published binary.
3. After merge, the implementation is listed in `docs/CONFORMANT_IMPLEMENTATIONS.md`.

Claims lapse on incompatible changes or a new suite version.
