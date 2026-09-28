# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Reference decoders (WP-059). Small, transparent, deterministic.

- :class:`LinearDecoder` (``Y_vector``): ``y = Σ_t W_t x_t``; a GRACEFUL absent
  type contributes a learned *absence embedding* ``b_t`` — never ``W_t · 0``.
- :class:`NearestAnchorDecoder` (``Y_text``): cosine-nearest anchor
  realization for one type; the label is the output.
"""

from __future__ import annotations

from collections.abc import Mapping

import numpy as np

from esp.core.taoss_types import L1_DIMS, TaossType
from esp.decoder.core import Absent, DecoderPolicyError, DecoderProfile, Slot, Vector
from esp.decoder.outputs import OutputTag, TextOutput, VectorOutput
from esp.session.descriptor import DecoderPolicy


class LinearDecoder:
    def __init__(
        self,
        decoder_id: str,
        policies: Mapping[TaossType, DecoderPolicy],
        *,
        out_dim: int = 8,
        seed: int = 0,
        priors: Mapping[TaossType, tuple[float, ...]] | None = None,
        noise: float = 0.0,
    ) -> None:
        self._profile = DecoderProfile(
            decoder_id=decoder_id,
            version="1",
            output_tag=OutputTag.VECTOR,
            types=frozenset(policies),
            policies=policies,
            priors=priors or {},
        )
        rng = np.random.default_rng(seed)
        self._w = {t: rng.normal(size=(out_dim, L1_DIMS[t])) / L1_DIMS[t] ** 0.5 for t in policies}
        if noise:  # a "different vendor": same structure, perturbed weights
            perturb = np.random.default_rng(seed + 1)
            self._w = {t: w + noise * perturb.normal(size=w.shape) for t, w in self._w.items()}
        self._absence = {t: rng.normal(size=out_dim) for t in policies}

    @property
    def profile(self) -> DecoderProfile:
        return self._profile

    def decode(self, inputs: Mapping[TaossType, Slot]) -> VectorOutput:
        y = np.zeros(next(iter(self._w.values())).shape[0])
        for t in sorted(self._profile.types):
            slot = inputs[t]
            y += self._absence[t] if isinstance(slot, Absent) else self._w[t] @ slot
        return VectorOutput(tuple(float(v) for v in y))


class ZeroFillDecoder(LinearDecoder):
    """Deliberately wrong: treats ``⊥`` as a zero vector (for the policy audit)."""

    def decode(self, inputs: Mapping[TaossType, Slot]) -> VectorOutput:
        filled = {
            t: np.zeros(L1_DIMS[t]) if isinstance(s, Absent) else s for t, s in inputs.items()
        }
        y = sum(self._w[t] @ filled[t] for t in sorted(self.profile.types))
        return VectorOutput(tuple(float(v) for v in np.asarray(y)))


class NearestAnchorDecoder:
    """Text output: the label of the cosine-nearest anchor realization of one type."""

    def __init__(
        self,
        decoder_id: str,
        t: TaossType,
        realizations: Mapping[str, tuple[float, ...]],
        policy: DecoderPolicy = DecoderPolicy.STRICT_REFUSE,
    ) -> None:
        if not realizations:
            msg = "at least one anchor realization is required"
            raise DecoderPolicyError(msg)
        self._t = t
        self._labels = sorted(realizations)
        m = np.array([realizations[k] for k in self._labels], dtype=np.float64)
        if m.shape[1] != L1_DIMS[t]:
            msg = f"realizations must be {L1_DIMS[t]}-dimensional"
            raise DecoderPolicyError(msg)
        self._m: Vector = m / np.linalg.norm(m, axis=1, keepdims=True)
        self._profile = DecoderProfile(
            decoder_id=decoder_id,
            version="1",
            output_tag=OutputTag.TEXT,
            types=frozenset({t}),
            policies={t: policy},
        )

    @property
    def profile(self) -> DecoderProfile:
        return self._profile

    def decode(self, inputs: Mapping[TaossType, Slot]) -> TextOutput:
        slot = inputs[self._t]
        if isinstance(slot, Absent):
            return TextOutput(f"<{self._t.name} absent>")
        norm = float(np.linalg.norm(slot))
        if norm == 0.0:
            return TextOutput(f"<{self._t.name} zero>")  # zero is a value, not absence
        return TextOutput(self._labels[int(np.argmax(self._m @ (slot / norm)))])
