# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""TAOSS reference encoder skeleton (WP-031; V13 section 5, App. refimpl). EXPERIMENTAL.

Architecture (V13 eq. encoder):

- modality encoders ``phi_m`` (small MLP adapters here; ViT/CNN/BERT plug in
  the same way) with missing-modality gates ``g_m = sigmoid(W_m h)``;
- cross-modal fusion (multi-head attention over modality tokens), mean pooled;
- six typed heads ``Head_t`` with orthogonal initialization;
- per-type running standardization ``E~_t``;
- losses (V13 eq. totalloss): typed task losses + ``lambda * sum ||Cov(E~_s, E~_t)||_F^2``
  + ``beta * sum E||Disc_{s<-t}(GRL[E_t]) - sg[E_s]||^2`` with spectrally
  normalized discriminators ``Disc_{s<-t}: R^{d_t} -> R^{d_s}``. Both penalty
  sums are reported as means over pairs (and covariance entries), so the
  weights do not scale with the number or size of the types.

"Architecture correct and trainable" — no H1/H2/H3 claim (plan WP-031).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import torch
from torch import Tensor, nn

from esp.core.taoss_types import L1_DIMS, TAOSS6_ORDER, TaossType


class GradReverse(torch.autograd.Function):
    """Identity forward; multiplies the gradient by ``-lambda`` backward."""

    @staticmethod
    def forward(ctx: torch.autograd.function.FunctionCtx, x: Tensor, lam: float) -> Tensor:
        ctx.lam = lam  # type: ignore[attr-defined]
        return x.view_as(x)

    @staticmethod
    def backward(ctx: torch.autograd.function.FunctionCtx, grad: Tensor) -> tuple[Tensor, None]:
        return -ctx.lam * grad, None  # type: ignore[attr-defined]


def grl(x: Tensor, lam: float) -> Tensor:
    out: Tensor = GradReverse.apply(x, lam)
    return out


class RunningStandardization(nn.Module):
    def __init__(self, dim: int, momentum: float = 0.01, eps: float = 1e-5) -> None:
        super().__init__()
        self.momentum, self.eps = momentum, eps
        self.register_buffer("running_mean", torch.zeros(dim))
        self.register_buffer("running_std", torch.ones(dim))

    def forward(self, x: Tensor) -> Tensor:
        if self.training and x.shape[0] > 1:
            with torch.no_grad():
                self.running_mean.lerp_(x.mean(0), self.momentum)  # type: ignore[operator]
                self.running_std.lerp_(x.std(0), self.momentum)  # type: ignore[operator]
        return (x - self.running_mean) / (self.running_std + self.eps)  # type: ignore[operator]


@dataclass(frozen=True, slots=True)
class EncoderConfig:
    modality_dims: Mapping[str, int]
    d_model: int = 64
    heads: int = 4
    type_dims: Mapping[TaossType, int] = field(default_factory=lambda: dict(L1_DIMS))
    disc_hidden: int = 64
    lambda_cov: float = 5.0
    beta_adv: float = 0.1
    lambda_grl: float = 1.0
    alphas: Mapping[TaossType, float] = field(default_factory=dict)


class TaossEncoder(nn.Module):
    def __init__(self, cfg: EncoderConfig) -> None:
        super().__init__()
        self.cfg = cfg
        self.types = tuple(t for t in TAOSS6_ORDER if t in cfg.type_dims)
        self.modalities = tuple(sorted(cfg.modality_dims))
        self.encoders = nn.ModuleDict(
            {
                m: nn.Sequential(
                    nn.Linear(d, cfg.d_model), nn.GELU(), nn.Linear(cfg.d_model, cfg.d_model)
                )
                for m, d in cfg.modality_dims.items()
            }
        )
        self.gates = nn.ModuleDict({m: nn.Linear(cfg.d_model, 1) for m in cfg.modality_dims})
        self.fusion = nn.MultiheadAttention(cfg.d_model, cfg.heads, batch_first=True)
        self.heads = nn.ModuleDict(
            {t.name: self._ortho(cfg.d_model, cfg.type_dims[t]) for t in self.types}
        )
        self.standardize = nn.ModuleDict(
            {t.name: RunningStandardization(cfg.type_dims[t]) for t in self.types}
        )
        sn = nn.utils.parametrizations.spectral_norm
        self.discriminators = nn.ModuleDict(
            {
                f"{s.name}_from_{t.name}": nn.Sequential(
                    sn(nn.Linear(cfg.type_dims[t], cfg.disc_hidden)),
                    nn.ReLU(),
                    sn(nn.Linear(cfg.disc_hidden, cfg.type_dims[s])),
                )
                for s in self.types
                for t in self.types
                if s != t
            }
        )

    @staticmethod
    def _ortho(d_in: int, d_out: int) -> nn.Linear:
        h = nn.Linear(d_in, d_out, bias=False)
        nn.init.orthogonal_(h.weight)
        return h

    def forward(
        self, inputs: Mapping[str, Tensor], present: Mapping[str, Tensor] | None = None
    ) -> dict[TaossType, Tensor]:
        """``inputs[m]``: (batch, dim_m). ``present[m]``: (batch,) 0/1 mask; absent -> gated out."""
        tokens, gates = [], []
        for m in self.modalities:
            h = self.encoders[m](inputs[m])
            g = torch.sigmoid(self.gates[m](h))
            if present is not None:
                g = g * present[m].unsqueeze(-1)
            tokens.append(h * g)
            gates.append(g)
        seq = torch.stack(tokens, dim=1)
        fused, _ = self.fusion(seq, seq, seq)
        weight = torch.stack(gates, dim=1)
        pooled = (fused * weight).sum(1) / weight.sum(1).clamp_min(1e-6)
        return {t: self.heads[t.name](pooled) for t in self.types}

    def standardized(self, latents: Mapping[TaossType, Tensor]) -> dict[TaossType, Tensor]:
        return {t: self.standardize[t.name](z) for t, z in latents.items()}

    def losses(
        self, latents: Mapping[TaossType, Tensor], targets: Mapping[TaossType, Tensor]
    ) -> dict[str, Tensor]:
        """Task (MSE to typed targets), covariance and adversarial terms."""
        cfg = self.cfg
        task = sum(
            (
                cfg.alphas.get(t, 1.0) * nn.functional.mse_loss(latents[t], targets[t])
                for t in self.types
                if t in targets
            ),
            torch.zeros(()),
        )
        std = self.standardized(latents)
        cov = torch.zeros(())
        adv = torch.zeros(())
        n = next(iter(latents.values())).shape[0]
        for s in self.types:
            for t in self.types:
                if s == t:
                    continue
                if s.value < t.value:  # each unordered pair once for the covariance term
                    c = (std[s] - std[s].mean(0)).T @ (std[t] - std[t].mean(0)) / max(1, n - 1)
                    cov = cov + (c**2).mean()  # per-entry: independent of type dimensions
                rec = self.discriminators[f"{s.name}_from_{t.name}"](
                    grl(latents[t], cfg.lambda_grl)
                )
                adv = adv + nn.functional.mse_loss(rec, latents[s].detach())
        pairs = len(self.types) * (len(self.types) - 1)
        cov, adv = cov / (pairs // 2), adv / pairs  # means over pairs: lambda/beta stay comparable
        total = task + cfg.lambda_cov * cov + cfg.beta_adv * adv
        return {"total": total, "task": task, "cov": cov, "adv": adv}


def type_shapes(latents: Mapping[TaossType, Tensor]) -> dict[str, tuple[int, ...]]:
    return {t.name: tuple(z.shape) for t, z in latents.items()}


def heads_of(model: TaossEncoder) -> Sequence[str]:
    return [t.name for t in model.types]
