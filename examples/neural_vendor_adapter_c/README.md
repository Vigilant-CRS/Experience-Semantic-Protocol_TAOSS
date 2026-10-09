<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Neural vendor adapter in C (contract 1.0.0, C ABI)

`esp_example_adapter.c` is a deterministic adapter written against
[`rust/esp-rs/include/esp_neural.h`](../../rust/esp-rs/include/esp_neural.h). It produces a
synthetic EEG-like source: 4 channels in uV at 256 Hz, and 4096 samples in total. To connect
your device, replace `fill_block` with calls into your driver.

## Build and check

```bash
make                                   # -> libesp_example_adapter.so
cargo build --release --manifest-path ../../rust/esp-rs/Cargo.toml
ESP_RS=../../rust/esp-rs/target/release/esp-rs
$ESP_RS neural-capi --lib ./libesp_example_adapter.so            # JSON lines + verdict
uv run esp-conformance run --neural-rust $ESP_RS --neural-c ./libesp_example_adapter.so
```

C++ works the same way. The header is wrapped in `extern "C"`; export
`esp_neural_adapter_create` with C linkage.

## Ownership

All memory stays with the adapter.

- The pointers that `info()` fills stay valid until `destroy()`.
- A block's buffers stay valid until the host calls `release()`. The host does this exactly
  once per successful `read()`, after copying the block.
- The host never writes through your pointers and never frees them.

This example keeps everything in its context struct, so `release()` does nothing.

## Modes (`--config`)

| Mode | Behaviour | Expected result |
|---|---|---|
| `""` | well-behaved L3 source | passes |
| `l4-replay` | recorded ECoG with descriptor and CC0 replay declaration | passes |
| `nan-dropout` | one sample is NaN (a dropout) | passes |
| `non-monotonic-clock` | repeated timestamp in block 2 | `clock` |
| `interpretive-channel` | a channel named `valence` | `neutral` |
| `l4-live-undeclared` | level 4 without a replay declaration | `level` |
| `null-buffer` | NULL value buffer in block 2 | `output` |
| `length-mismatch` | block 2 has 3 instead of 4 channels | `channels` |
| `inf-sample` | +Inf in block 2 | `output` |
| `read-error` | `read()` fails on block 2 | `output` |

Python (`tests/conformance/test_neural_c.py`) and Rust (`rust/esp-rs/tests/capi.rs`) compile
this file and check that every mode gives exactly the rule above.
