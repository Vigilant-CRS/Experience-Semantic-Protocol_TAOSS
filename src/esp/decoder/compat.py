# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Decoder compatibility metrics (V13 section 7.3).

- ε-compatibility (average case), quantile ``Q_q`` and worst case over a
  public reference set ``R`` of *experiences* (encoder inputs);
- anchor-mediated compatibility for heterogeneous output spaces via
  separately certified classifiers ``C_i : Y_i → L`` and a public labeling
  ``Ψ : R → L``.

Compatibility is measured on references, never asserted globally.
"""

from __future__ import annotations

from collections.abc import Callable, Hashable, Sequence
from dataclasses import dataclass

import numpy as np

from esp.decoder.core import Decoder, run_decoder
from esp.decoder.outputs import Output, default_distance
from esp.frame.model import ExperienceFrame


@dataclass(frozen=True, slots=True)
class CompatibilityReport:
    n: int
    mean: float
    quantile_q: float
    quantile: float
    worst: float

    def compatible(
        self, epsilon: float, *, epsilon_q: float | None = None, epsilon_max: float | None = None
    ) -> bool:
        ok = self.mean <= epsilon
        if epsilon_q is not None:
            ok = ok and self.quantile <= epsilon_q
        if epsilon_max is not None:
            ok = ok and self.worst <= epsilon_max
        return ok


def compatibility[R](
    references: Sequence[R],
    encoder_a: Callable[[R], ExperienceFrame],
    decoder_a: Decoder,
    decoder_b: Decoder,
    *,
    encoder_b: Callable[[R], ExperienceFrame] | None = None,
    distance: Callable[[Output, Output], float] = default_distance,
    q: float = 0.95,
) -> CompatibilityReport:
    """``d_Y(D_φ(E_e(r)), D_φ'(E_e'(r)))`` over ``R`` (``E_e' = E_e`` unless given)."""
    if not references:
        msg = "the reference set must not be empty"
        raise ValueError(msg)
    if not 0.0 < q <= 1.0:
        msg = "quantile q must be in (0, 1]"
        raise ValueError(msg)
    enc_b = encoder_b or encoder_a
    ds = np.array(
        [
            distance(
                run_decoder(decoder_a, encoder_a(r)).output,
                run_decoder(decoder_b, enc_b(r)).output,
            )
            for r in references
        ]
    )
    return CompatibilityReport(
        n=len(ds),
        mean=float(ds.mean()),
        quantile_q=q,
        quantile=float(np.quantile(ds, q, method="higher")),
        worst=float(ds.max()),
    )


def mediated_compatibility[R, L: Hashable](
    references: Sequence[R],
    labeling: Callable[[R], L],
    pair_a: tuple[Callable[[R], ExperienceFrame], Decoder, Callable[[Output], L]],
    pair_b: tuple[Callable[[R], ExperienceFrame], Decoder, Callable[[Output], L]],
    *,
    epsilon: float,
    minimum_references: int = 1,
) -> tuple[float, bool]:
    """``Pr_r[C1(D(E(r))) = C2(D'(E'(r))) = Ψ(r)]`` and whether it is ``≥ 1 - ε``."""
    if len(references) < minimum_references:
        msg = f"at least {minimum_references} references required"
        raise ValueError(msg)
    (enc_a, dec_a, cls_a), (enc_b, dec_b, cls_b) = pair_a, pair_b
    hits = 0
    for r in references:
        label = labeling(r)
        a = cls_a(run_decoder(dec_a, enc_a(r)).output)
        b = cls_b(run_decoder(dec_b, enc_b(r)).output)
        hits += a == b == label
    agreement = hits / len(references)
    return agreement, agreement >= 1.0 - epsilon
