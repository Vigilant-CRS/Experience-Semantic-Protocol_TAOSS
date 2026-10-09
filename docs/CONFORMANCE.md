<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Conformance guide and the "ESP-Conformant" mark

## Run the suite

```bash
uv run esp-conformance run --json report.json                     # this implementation
uv run esp-conformance run --peer path/to/your-binary --json report.json   # yours, live
uv run esp-conformance run --neural-adapter your_pkg.module:factory       # your neural device
uv run esp-conformance run --neural-rust rust/esp-rs/target/release/esp-rs  # Rust neural mirror
uv run esp-conformance run --neural-rust rust/esp-rs/target/release/esp-rs \
    --neural-c libyour_adapter.so --neural-c-config ""          # your C/C++ adapter
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
| `xcf` | experience capsules |
| `hive` | Typed Hive TLVs |
| `neural` | neural vendor contract 1.0.0: reference adapters and decoders pass; every built-in broken adapter or decoder is refused with exactly its rule; `--neural-adapter` checks yours; `--neural-rust` cross-checks the Rust implementation; `--neural-c` checks a C/C++ adapter library |
| `interop` | only with `--peer`: both directions, including revocation |

## Implementing a peer for `--peer`

Your binary must implement two commands and print JSON lines. The reference is
`rust/esp-rs`, and `src/esp/conformance/interop.py` documents the contract.

- `send --addr H:P --responder-static HEX --receiver-id HEX --master-seed HEX --static-seed HEX --frames N [--revoke-after K --ignore-revocation yes]`
- `receive --addr H:P --static-seed HEX --identity-seed HEX --trusted HEX`

Transport: TCP, frames `len u32 BE · channel u8 · data`.

## Neural devices: vendor quickstart

Contract `1.0.0` (`esp.neural_sdk`, mirrored in `rust/esp-rs/src/neural.rs`) is the only thing a
device maker has to implement. Everything above it is identical for live devices, replayed
recordings and simulators: features, the decoder boundary, consent, frames and sessions.

1. Subclass `esp.neural_sdk.BlockAdapter` and implement `acquire()`. It returns int64 nanosecond
   timestamps and `samples × channels` values in a normalized unit. Declare the device, channels,
   rate and clock domain in `NeuralAdapterInfo`.
2. Optionally subclass `esp.neural_sdk.TypedDecoderBase` for your `f_decode`. Declare only the
   TAOSS types your decoder can defend.
3. Run `esp-conformance run --neural-adapter your_pkg.module:factory` and publish the report.

Rules:

| Rule | Meaning |
|---|---|
| `channels` | declared, non-empty channels; every block carries exactly them |
| `rate`, `unit` | positive rate, normalized units (`uV`, `count`, …) |
| `modality` | neural modalities only; invasive ones only under `L4-REPLAY` |
| `neutral` | no channel name may name an interpretation (`valence`, `intent_x`, `fear`, …) |
| `identity` | device and clock domain stay as declared |
| `size` | at most `max_samples` samples per block |
| `clock` | int64 ns timestamps, strictly increasing within and across blocks |
| `output` | at least one block, and only `SampleBlock`s |
| `level`, `replay:*` | live invasive sources are refused; recordings need a `ReplayDeclaration` (dataset, version, open license, consent basis, https source) |
| `decode` | decoders answer only consented types, with finite vectors of the typed dimension |

Other languages print the JSON-lines protocol of `esp.neural_sdk.jsonl`. `esp-rs neural-sim`
is the reference: an info line, block lines, and the Rust checker's verdict. Template:
[`examples/neural_vendor_adapter/`](../examples/neural_vendor_adapter/README.md).

### C and C++ adapters

Drivers and SDKs in C or C++ implement the same contract through the C ABI in
[`rust/esp-rs/include/esp_neural.h`](../rust/esp-rs/include/esp_neural.h). The library exports
one function, `esp_neural_adapter_create(config, vtable)`. It fills a vtable with these
callbacks: `info`, `start`, `read`, `release`, `stop` and `destroy`.

- **Ownership.** All memory stays with the vendor.
  - `info` pointers must stay valid until `destroy`.
  - A block's buffers must stay valid until the host calls `release`. The host calls it
    exactly once per successful `read`, right after copying.
  - The host never writes through or frees vendor pointers.
- **Host-side validation** (`esp_rs::neural_capi::CAdapter`). These are refused when loading:
  - NULL pointers or invalid UTF-8;
  - a wrong ABI version;
  - a NULL callback;
  - a level other than 3 or 4.

  The context is destroyed on refusal.
- **Blocks.** Some blocks become a contract violation:
  - a NULL buffer, an Inf sample or a `read` error → `output`;
  - a block width that differs from the declaration → `channels`.

  NaN marks a dropout and is allowed.
- **Check.** `esp-rs neural-capi --lib libx.so --config "..."` prints the JSON lines of
  `neural-sim`. `esp-conformance run --neural-rust <esp-rs> --neural-c libx.so` requires that
  Python and the Rust host find the same rules, and that the adapter passes.

The example [`examples/neural_vendor_adapter_c/`](../examples/neural_vendor_adapter_c/README.md)
has one mode per broken rule. Each mode is refused with the same rule in Python and Rust:

| Mode | Rule |
|---|---|
| `non-monotonic-clock` | `clock` |
| `interpretive-channel` | `neutral` |
| `l4-live-undeclared` | `level` |
| `null-buffer`, `inf-sample`, `read-error` | `output` |
| `length-mismatch` | `channels` |

The host cannot verify that the buffer lengths a vendor reports are honest; no C interface
can.

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
