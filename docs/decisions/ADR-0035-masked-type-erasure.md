<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ADR-0035: Masked-type erasure (typing plus concept erasure)

- Status: ACCEPTED (2026-10-08, maintainer decision)
- Context: the preregistered GoEmotions H2 study (`docs/research/result-goemotions-h2.md`)
  showed that typed heads leak less of a masked type than naive masking, but more than LEACE
  or an adversarial filter. Masking removes a block from the wire. It does not remove what the
  released blocks still say about the masked type.

## Decision

1. **Optional profile.** A sender may declare an `ErasureProfile` (`esp.privacy.erasure`). For
   each concept type that can be masked, it holds a LEACE eraser fitted on training data for
   the ordered set of released types. Erasure is off by default.
2. **When it applies.** After disclosure, if a declared concept is masked, the released
   latents are erased with the closed form `x' = x - (x - mu) M^T`.
3. **Declaration.** The frame provenance carries `erasure:<TYPE>:leace:<digest>`. The digest
   covers the concept, the released types and dimensions, the fitted parameters and the
   training-data id. These declarations are kept even when other evidence references are
   stripped.
4. **Fail closed.** A declared eraser that cannot be applied (different released types or
   dimensions) is an error. The frame is never sent un-erased.
5. **Receiver side.** `ReceiverHardening.require_erasure` lists masked types whose erasure must
   be declared. Frames without the declaration are refused.
6. **No wire change.** The declaration travels in the frame metadata (addendum `0x95`).

## Consequences

- **The guarantee is linear.** No linear probe of the masked concept beats a constant on the
  fitting distribution. Nonlinear leakage remains, and it is measured by the audit suite and
  tested in the preregistered DailyDialog study
  (`docs/research/prereg-dailydialog-erasure.md`).
- **Utility.** Erasure removes the shared linear component. Utility of the released types can
  drop, and studies report it.
- **Not verifiable from one frame.** A receiver cannot check from a single frame that the
  declared erasure was applied correctly; it can only audit statistically.
