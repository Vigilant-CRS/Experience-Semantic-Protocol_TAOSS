# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Learned selective-privacy baseline (WP-036; V13 H2 "learned privacy filter").

A monolithic latent plus a trained disclosure-time filter ``f``: a nonlinear
MLP trained so that a task head still works on ``f(z)`` while an adversary
(behind gradient reversal) cannot reconstruct the withheld type from it.
Matched to the TAOSS budget by keeping the same output dimension.
"""

from __future__ import annotations

import numpy as np
import torch
from numpy.typing import NDArray
from torch import nn

from esp.training.encoder import grl


def learned_filter(
    z: NDArray[np.float64],
    task_labels: NDArray[np.int64],
    protected: NDArray[np.float64],
    *,
    steps: int = 400,
    lam: float = 1.0,
    seed: int = 0,
) -> NDArray[np.float64]:
    torch.manual_seed(seed)
    x = torch.tensor(z, dtype=torch.float32)
    y = torch.tensor(task_labels, dtype=torch.long)
    p = torch.tensor(protected, dtype=torch.float32)
    d = x.shape[1]
    filt = nn.Sequential(nn.Linear(d, 64), nn.GELU(), nn.Linear(64, d))
    head = nn.Linear(d, int(task_labels.max()) + 1)
    adv = nn.Sequential(nn.Linear(d, 64), nn.GELU(), nn.Linear(64, p.shape[1]))
    params = [*filt.parameters(), *head.parameters(), *adv.parameters()]
    opt = torch.optim.Adam(params, lr=3e-3)
    for _ in range(steps):
        f = filt(x)
        task = nn.functional.cross_entropy(head(f), y)
        leak = nn.functional.mse_loss(adv(grl(f, lam)), p)
        opt.zero_grad()
        (task + leak).backward()  # type: ignore[no-untyped-call]  # adversary minimizes leak; the filter maximizes it via GRL
        opt.step()
    with torch.no_grad():
        out: NDArray[np.float64] = filt(x).numpy().astype(np.float64)
    return out
