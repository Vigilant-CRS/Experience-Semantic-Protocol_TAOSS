# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Released-representation variants for the typing-plus-erasure studies.

Every eraser and filter here is fitted on **training rows only**. Evaluation rows enter the
learned filter only as unlabelled inputs, with placeholder labels that the fit ignores; the
LEACE eraser never sees them during fitting. LEACE uses the protocol mechanism
:class:`esp.privacy.erasure.LeaceEraser`, the same code a sender would run.

Variants:

| name | released representation |
|---|---|
| ``taoss`` | the typed encoder's released blocks |
| ``taoss_leace`` | typed blocks with LEACE erasure of the masked concept (the mechanism) |
| ``taoss_filter`` | typed blocks through the learned adversarial filter |
| ``mono`` | the same-size slice of an untyped (monolithic) latent |
| ``mono_leace`` | monolithic slice with LEACE erasure (LEACE alone, same dimension) |
| ``mono_filter`` | monolithic slice through the learned adversarial filter |
| ``raw_leace`` | the frozen sentence embedding with LEACE erasure (no encoder at all) |
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Final

import numpy as np
from numpy.typing import NDArray

from esp.core.taoss_types import TaossType
from esp.privacy.erasure import LeaceEraser

F64 = NDArray[np.float64]
I64 = NDArray[np.int64]
VARIANTS: Final = (
    "taoss",
    "taoss_leace",
    "taoss_filter",
    "mono",
    "mono_leace",
    "mono_filter",
    "raw_leace",
)


def leace_pair(
    r_tr: F64, r_ev: F64, concept_tr: F64, *, training_data_id: str
) -> tuple[tuple[F64, F64], LeaceEraser]:
    """Fit the protocol eraser on training rows and apply it to both splits."""
    eraser = LeaceEraser.fit(
        [r_tr],
        concept_tr,
        concept=TaossType.EMO,
        released_types=(TaossType.KNO,),  # one concatenated released vector
        training_data_id=training_data_id,
    )
    return (eraser.apply(r_tr), eraser.apply(r_ev)), eraser


def filter_pair(
    r_tr: F64, r_ev: F64, task_tr: I64, concept_tr: F64, *, seed: int
) -> tuple[F64, F64]:
    """Learned adversarial filter (``esp.bench.filter``) fitted on training rows only."""
    from esp.bench.filter import learned_filter  # noqa: PLC0415 - torch import kept local

    n_tr, n_ev = len(r_tr), len(r_ev)
    stacked = np.vstack([r_tr, r_ev])
    mask = np.r_[np.ones(n_tr, bool), np.zeros(n_ev, bool)]
    task = np.r_[task_tr, np.zeros(n_ev, dtype=np.int64)]
    concept = np.vstack([concept_tr, np.zeros((n_ev, concept_tr.shape[1]))])
    out = learned_filter(stacked, task, concept, train=mask, seed=seed)
    return out[:n_tr], out[n_tr:]


def variants(
    typed: tuple[F64, F64],
    mono: tuple[F64, F64],
    raw: tuple[F64, F64],
    concept_tr: F64,
    task_tr: I64,
    *,
    seed: int,
    training_data_id: str,
    names: Sequence[str] = VARIANTS,
) -> dict[str, tuple[F64, F64]]:
    """The released ``(train, eval)`` representation of every requested variant."""
    out: dict[str, tuple[F64, F64]] = {}
    tid = f"{training_data_id}:seed{seed}"
    for name in names:
        base, _, mod = name.partition("_")
        src = {"taoss": typed, "mono": mono, "raw": raw}[base]
        if mod == "":
            out[name] = src
        elif mod == "leace":
            out[name] = leace_pair(src[0], src[1], concept_tr, training_data_id=f"{tid}:{base}")[0]
        elif mod == "filter":
            out[name] = filter_pair(src[0], src[1], task_tr, concept_tr, seed=seed)
        else:  # pragma: no cover - names are validated by VARIANTS
            msg = f"unknown variant {name}"
            raise ValueError(msg)
    return out
