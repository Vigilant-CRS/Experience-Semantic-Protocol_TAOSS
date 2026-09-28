# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""MINE (Belghazi et al. 2018) as the second MI estimator of the audit suite (WP-058).

Donsker-Varadhan bound ``I >= E_P[T] - log E_Q[e^T]`` with a small MLP critic,
bias-corrected moving average for the gradient of the log term, a fixed
train/evaluation split and a fixed seed. Reported in bits. MINE is a lower
bound estimator with high variance; the audit uses it only to flag dissent
against KSG, never to average it away.
"""

from __future__ import annotations

import math

import numpy as np
import torch
from numpy.typing import NDArray
from torch import nn


def mine_mi(
    x: NDArray[np.float64],
    y: NDArray[np.float64],
    *,
    steps: int = 600,
    hidden: int = 64,
    lr: float = 1e-3,
    batch: int = 256,
    seed: int = 0,
) -> float:
    x = np.asarray(x, dtype=np.float64).reshape(len(x), -1)
    y = np.asarray(y, dtype=np.float64).reshape(len(y), -1)
    torch.manual_seed(seed)
    gen = torch.Generator().manual_seed(seed)
    xt = torch.tensor((x - x.mean(0)) / (x.std(0) + 1e-12), dtype=torch.float32)
    yt = torch.tensor((y - y.mean(0)) / (y.std(0) + 1e-12), dtype=torch.float32)
    n = xt.shape[0]
    split = int(0.7 * n)
    critic = nn.Sequential(
        nn.Linear(xt.shape[1] + yt.shape[1], hidden),
        nn.ELU(),
        nn.Linear(hidden, hidden),
        nn.ELU(),
        nn.Linear(hidden, 1),
    )
    opt = torch.optim.Adam(critic.parameters(), lr=lr)
    ema = None
    for _ in range(steps):
        i = torch.randint(0, split, (batch,), generator=gen)
        j = torch.randint(0, split, (batch,), generator=gen)
        joint = critic(torch.cat([xt[i], yt[i]], 1)).mean()
        marg = torch.exp(critic(torch.cat([xt[i], yt[j]], 1))).mean()
        ema = marg.detach() if ema is None else 0.99 * ema + 0.01 * marg.detach()
        loss = -(joint - marg / ema)  # unbiased gradient of the DV bound
        opt.zero_grad()
        loss.backward()
        opt.step()
    with torch.no_grad():
        xe, ye = xt[split:], yt[split:]
        perm = torch.randperm(xe.shape[0], generator=gen)
        joint = critic(torch.cat([xe, ye], 1)).mean()
        marg = torch.logsumexp(critic(torch.cat([xe, ye[perm]], 1)), 0) - math.log(xe.shape[0])
        return max(0.0, float(joint - marg.squeeze())) / math.log(2.0)
