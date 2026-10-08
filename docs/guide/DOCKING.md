<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Docking: how to connect to ESP

ESP is built so that others can connect without asking. There are four kinds of
connection, and each one has a fixed contract and a test that proves you meet it.

## 1. Device makers and labs: neural and physiological sources

You implement **one interface**, the `NeuralAdapter`. Everything above it works unchanged:
- decoding at the V13 decoder boundary;
- the mapping to typed parts (never EMO or KNO from neural data);
- consent, encryption, provenance and revocation.

1. Describe your device: `NeuralDeviceDescriptor`, with a pseudonymous device id, electrodes,
   unit, rate and processing chain.
2. Subclass `esp.neural_sdk.BlockAdapter` and implement `acquire()`. It returns int64
   nanosecond timestamps and samples × channels in the declared unit. See
   [`examples/neural_vendor_adapter/`](../../examples/neural_vendor_adapter/README.md).
3. Prove the contract:

   ```bash
   uv run esp-conformance run --neural-adapter your_package.module:factory
   ```

4. Stress-test it with the implant stream emulator (`esp.adapters.neural.emulator`), which
   injects jitter, dropouts, channel death, clock drift, reconnects, gain steps and packet loss.

Profiles you can use today:
- `L3-LIVE`: non-invasive, live.
- `L4-REPLAY`: recorded invasive data, with a declaration of dataset, license and consent.

Live invasive sources need their own profile and ethics process. That is a deliberate v1
boundary.

The contract has already been exercised with public human recordings of these kinds:
- intracortical arrays (FALCON H1/H2);
- ECoG (DANDI 000019, AJILE12);
- physiology from PhysioNet and Empatica.

Rust implementers use the trait `esp_rs::neural::NeuralAdapter`. Other languages speak the
JSON-lines protocol of `esp.neural_sdk.jsonl`.

## 2. Other implementations of the protocol

A third implementation, in Go, C, TypeScript, Swift or any other language, is welcome. It is
the strongest evidence that ESP is a protocol and not one codebase.

- **Byte-exact target:** the frozen v1 golden vectors in [`vectors/`](../../vectors/)
  (`FROZEN-1.0.0.json`, CC BY 4.0).
- **Live interop:** run your sender and receiver against the reference:

  ```bash
  uv run esp-conformance run --peer ./your-implementation
  ```

- Read [CONFORMANCE.md](../CONFORMANCE.md) for the categories and the peer CLI protocol.

## 3. AI agents and machines

- **ESP-Agent profile:** agents exchange INT, CTX and KNO under capabilities, with signed
  opaque-latent descriptors and a causal event audit (`esp.agent`, ADR-0028). Opaque internal
  states are never presented as TAOSS unless a leakage audit passed.
- **Machine Experience Bridge:** handover profiles (vehicle, robotic, surgical, drone swarm)
  where machines never author EMO (`esp.meb`, ADR-0028).

## 4. Researchers

- **Datasets:** register them with license, consent basis, split unit and checksums
  (`datasets/registry.json`, `datasets/neural.json`). Data is never committed.
- **Preregistered studies:** follow the pattern of the three published studies in
  [`docs/research/`](../research/).
  1. Develop on known data.
  2. Push the preregistration publicly.
  3. Run the test exactly once with `--unblind --prereg-commit <sha>`.
  4. Publish the result, whatever it is.
- **Open questions** with real impact:
  - H1 (does per-part consent change what people share?);
  - H3 (do receivers understand an experience better with typed parts than with text?);
  - reducing nonlinear leakage after erasure;
  - cross-day neural drift.

## Licenses in one line

The code is AGPL-3.0-or-later. Spec and docs are CC BY-SA 4.0. Test vectors are CC BY 4.0.
There are no patents. Contributions need a DCO sign-off; there is no CLA. See
[DISCLAIMER](../DISCLAIMER.md) for responsibility.
