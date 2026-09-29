<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ADR-0034: Neural companion profile (M18, implant-ready)

- Status: PROPOSED (implemented; awaiting maintainer review)
- Context: V13 defines the decoder interface boundary `f_decode` but leaves the neural source
  side to vendors. M18 makes that boundary testable with public human intracortical and ECoG
  recordings instead of an implant.

## Decisions

1. **No ESP wire change.** Raw neural data never becomes TAOSS. Only decoder outputs cross
   the boundary, as typed latents.
2. **One adapter contract for live and replay.** A device driver, an NWB or BIDS-iEEG replay,
   an emulator and a simulator implement the same `NeuralAdapter`. Everything above the
   adapter cannot tell them apart.
3. **Profiles.**
   - `L3-LIVE`: EEG, EMG and eye tracking.
   - `L4-REPLAY`: recorded invasive data, only with a declaration naming the dataset, a
     pinned version, an open license and the consent basis.
   - `L4-LIVE`: refused in v1.
4. **Mapping profile `esp-neural-mapping-v1`.**
   - Decoded *attempted* movement, grasp, handwriting and articulation map to INT.
   - Measured kinematics or pose map to SEN, never to INT.
   - Task context maps to CTX, timing to TEM.
   - **EMO and KNO are never populated from neural features.**
5. **Session type-set profile `esp-typeset-neural-v1`.** INT is required. SEN, CTX and TEM
   are optional. KNO is not allowed. EMO must be masked in every packet.
6. **Versioned recalibration.** A decoder's id includes a digest of its calibration.
   Provenance names the calibration and the dataset, which is disclosed only with explicit
   permission.

## Consequences

- Vendors implement one Python protocol or Rust trait and pass `esp-conformance`'s `neural`
  category. A C ABI is future work.
- FALCON H1 shows that day-to-day drift is real (R² 0.21 within a day, about 0 across days
  with a frozen decoder). Recalibration versioning is therefore part of the contract, not an
  implementation detail.
