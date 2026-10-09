<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Neural vendor adapter: template

Connect a neural device or dataset to ESP in three steps.

1. **Adapter.** Subclass `esp.neural_sdk.BlockAdapter` and implement `acquire()`. It must
   return integer-nanosecond timestamps and a `samples × channels` array in the declared unit.
   The base class builds the blocks, enforces start/stop and refuses clock errors.
2. **Decoder (optional).** Subclass `esp.neural_sdk.TypedDecoderBase` and implement
   `decode_one()` for the TAOSS types your decoder can defend. The decoder boundary requests
   only consented types and discards malformed output.
3. **Prove it.**

   ```bash
   uv run python examples/neural_vendor_adapter/vendor_adapter.py
   uv run esp-conformance run --neural-adapter your_package.module:factory
   ```

Rules of contract `1.0.0` (see `esp.neural_sdk`):

- A neural source never emits emotions, intentions or other interpretations. Channel names
  such as `valence` or `intent_x` are refused.
- Live invasive (L4) sources have no v1 profile. Recorded invasive datasets are admitted as
  `L4-REPLAY` with a `ReplayDeclaration`: dataset, version, open license and consent basis.
  See `esp.neural_sdk.example` for an ECoG replay declaration.
- Device ids are pseudonymous, never hardware serial numbers.

**Other languages.**

- Out-of-process adapters print the JSON-lines protocol of `esp.neural_sdk.jsonl`.
- The Rust implementation provides the trait `esp_rs::neural::NeuralAdapter` and
  `esp-rs neural-sim`. The conformance runner cross-checks it with `--neural-rust`.
- C and C++ drivers implement the C ABI `rust/esp-rs/include/esp_neural.h`; see
  [`../neural_vendor_adapter_c/`](../neural_vendor_adapter_c/README.md).
