# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Encoder stability mechanisms and certified-stability mode (WP-073). EXPERIMENTAL.

V13 section "Stability Mechanisms" lists practice, not guarantees:

- running per-coordinate standardization at the attention inputs;
- spectral normalization on discriminators (always on, :mod:`esp.training.encoder`);
- gradient penalty on the discriminator score functions;
- instance noise on the discriminator inputs (annealed linearly to 0 here);
- multi-capacity discriminator ensembles (small + large);
- early stopping on a held-out HSIC/MINE plateau;
- ``beta`` annealed from 0 to ``beta_max`` over the first 20 % of training;
- encoder-only updates every ``k`` epochs (discriminators frozen).

Missing-modality gates ``g_m`` are part of the architecture; ``modality_dropout``
trains them by randomly marking modalities absent.

**Certified mode** (V13 Theorem "Local Lipschitzness of Self-Attention Fusion",
Remark "Why local is enough", Proposition "Multi-head bound"): the attention
input is spectrally clipped to ``R_max`` and, after every optimizer step, the
projections ``W_Q, W_K, W_V, W_O`` are scaled to spectral norm ``<= sigma_max``.
Then, with ``n`` tokens, ``H`` heads and ``tau = sqrt(d_k)``, for every head
``L_h(R_max) <= sqrt(n) s + 2 sqrt(n) R_max^2 s^3 / tau`` and
``L_MH <= s * sqrt(H) * L_h``: the *declared bound*, which must not exceed the
profile ceiling. :mod:`esp.training.certify` checks the trained weights
independently (numpy only).

The bound covers the fusion operator on its clipped input, as in V13; it does
not bound the modality encoders or the gating (documented limitation).
"""

from __future__ import annotations

import math
from collections.abc import Mapping
from dataclasses import dataclass, field
from itertools import combinations
from typing import Any, Literal

import numpy as np
import torch
from numpy.typing import NDArray

from esp.audit.estimators import hsic
from esp.audit.mine import mine_mi

F64 = NDArray[np.float64]


def declared_bound(
    *, r_max: float, sigma_max: float, tokens: int, d_model: int, heads: int
) -> float:
    """V13 multi-head local Lipschitz bound with every projection norm ``<= sigma_max``."""
    if d_model % heads:
        msg = "d_model must be divisible by heads"
        raise ValueError(msg)
    tau = math.sqrt(d_model // heads)
    root_n = math.sqrt(tokens)
    l_h = root_n * sigma_max + 2.0 * root_n * r_max**2 / tau * sigma_max**3
    return sigma_max * math.sqrt(heads) * l_h


@dataclass(frozen=True, slots=True)
class CertifiedConfig:
    r_max: float
    sigma_max: float
    ceiling: float
    """Profile-defined ceiling for the fusion Lipschitz constant."""

    def __post_init__(self) -> None:
        if min(self.r_max, self.sigma_max, self.ceiling) <= 0:
            msg = "r_max, sigma_max and ceiling must be positive"
            raise ValueError(msg)

    def check(self, *, tokens: int, d_model: int, heads: int) -> float:
        """The declared bound; refuses a configuration whose bound exceeds the ceiling."""
        bound = declared_bound(
            r_max=self.r_max, sigma_max=self.sigma_max, tokens=tokens, d_model=d_model, heads=heads
        )
        if bound > self.ceiling:
            msg = f"declared bound {bound:.4g} exceeds the ceiling {self.ceiling:.4g}"
            raise ValueError(msg)
        return bound


@dataclass(frozen=True, slots=True)
class EarlyStopConfig:
    estimator: Literal["hsic", "mine"] = "hsic"
    eval_every: int = 25
    patience: int = 4
    """Stop after this many evaluations without an improvement of ``min_delta``."""
    min_delta: float = 1e-4
    holdout_frac: float = 0.2
    mine_steps: int = 200

    def __post_init__(self) -> None:
        if self.estimator not in ("hsic", "mine"):
            msg = "estimator must be 'hsic' or 'mine'"
            raise ValueError(msg)
        if self.eval_every < 1 or self.patience < 1 or not 0.0 < self.holdout_frac < 0.5:
            msg = "need eval_every >= 1, patience >= 1 and 0 < holdout_frac < 0.5"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class StabilityConfig:
    grad_penalty: float = 0.0
    instance_noise: float = 0.0
    """Initial std of discriminator-input noise; annealed linearly to 0 over training."""
    disc_capacities: tuple[int, ...] = ()
    beta_anneal_frac: float = 0.0
    """V13: 0.2 (beta from 0 to beta_max over the first 20 % of the steps)."""
    encoder_only_every: int = 0
    """Every k-th epoch the discriminators are frozen (0 = never)."""
    standardize_fusion_input: bool = False
    modality_dropout: float = 0.0
    early_stop: EarlyStopConfig | None = None
    certified: CertifiedConfig | None = None

    def __post_init__(self) -> None:
        if self.grad_penalty < 0 or self.instance_noise < 0:
            msg = "grad_penalty and instance_noise must be non-negative"
            raise ValueError(msg)
        if not 0.0 <= self.beta_anneal_frac <= 1.0 or not 0.0 <= self.modality_dropout < 1.0:
            msg = "beta_anneal_frac must lie in [0, 1] and modality_dropout in [0, 1)"
            raise ValueError(msg)
        if self.encoder_only_every < 0:
            msg = "encoder_only_every must be non-negative"
            raise ValueError(msg)

    @classmethod
    def recommended(cls, *, certified: CertifiedConfig | None = None) -> StabilityConfig:
        """All V13 mechanisms on (values are starting points, not tuned results)."""
        return cls(
            grad_penalty=0.1,
            instance_noise=0.1,
            disc_capacities=(16, 64),
            beta_anneal_frac=0.2,
            encoder_only_every=5,
            standardize_fusion_input=True,
            modality_dropout=0.1,
            early_stop=EarlyStopConfig(),
            certified=certified,
        )

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> StabilityConfig:
        es, cert = d.get("early_stop"), d.get("certified")
        return cls(
            **{k: v for k, v in d.items() if k not in ("early_stop", "certified")}
            | {
                "disc_capacities": tuple(d.get("disc_capacities", ())),
                "early_stop": None if es is None else EarlyStopConfig(**es),
                "certified": None if cert is None else CertifiedConfig(**cert),
            }
        )

    def beta(self, beta_max: float, step: int, steps: int) -> float | None:
        """Annealed beta for 0-based ``step``; ``None`` when annealing is off."""
        if self.beta_anneal_frac == 0.0:
            return None
        return beta_max * min(1.0, step / max(1.0, self.beta_anneal_frac * steps))

    def noise(self, step: int, steps: int) -> float:
        return self.instance_noise * max(0.0, 1.0 - step / max(1, steps))

    def encoder_only(self, step: int, steps_per_epoch: int) -> bool:
        k = self.encoder_only_every
        return k > 0 and (step // steps_per_epoch) % k == k - 1


@dataclass
class EarlyStopState:
    history: list[tuple[int, float]] = field(default_factory=list)
    best: float = math.inf
    since_best: int = 0
    stopped_at: int | None = None

    def update(self, step: int, value: float, cfg: EarlyStopConfig) -> bool:
        """Record a held-out leakage value; returns True once the plateau is reached."""
        self.history.append((step, value))
        if value < self.best - cfg.min_delta:
            self.best, self.since_best = value, 0
        else:
            self.since_best += 1
        if self.since_best >= cfg.patience and self.stopped_at is None:
            self.stopped_at = step
        return self.stopped_at is not None


def holdout_leakage(latents: Mapping[str, F64], cfg: EarlyStopConfig, *, seed: int = 0) -> float:
    """Mean cross-type dependence over unordered type pairs (HSIC statistic or MINE bits)."""
    vals = []
    for s, t in combinations(sorted(latents), 2):
        if cfg.estimator == "hsic":
            vals.append(hsic(latents[s], latents[t], permutations=0)[0])
        else:
            with torch.random.fork_rng():  # MINE seeds torch; never disturb the training RNG
                vals.append(mine_mi(latents[s], latents[t], steps=cfg.mine_steps, seed=seed))
    return float(np.mean(vals))
