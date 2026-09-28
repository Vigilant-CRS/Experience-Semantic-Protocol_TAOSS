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

Stability mechanisms (WP-073; V13 section "Stability Mechanisms"), all opt-in so
the default model is unchanged:

- running per-coordinate standardization of the attention-layer inputs
  (``standardize_fusion_input``; statistics only from present modalities);
- multi-capacity discriminator ensembles (``disc_capacities``);
- gradient penalty on the discriminator score functions and instance noise on
  the discriminator inputs (arguments of :meth:`TaossEncoder.losses`);
- **certified mode** (``r_max``): the explicit spectral clip
  ``E <- E * min(1, R_max / ||E||_2)`` at the attention input (V13 Remark
  "Why local is enough") and bias-free attention projections, so the
  hypotheses of the local-Lipschitz theorem hold architecturally. The bound
  is verified independently by :mod:`esp.training.certify`.

Type keys are TAOSS-6 types or, for alternate decompositions (TAOSS-3/-8/-12,
WP-074), plain identifier names; the architecture is identical.

"Architecture correct and trainable" — no H1/H2/H3 claim (plan WP-031).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

import numpy as np
import torch
from numpy.typing import NDArray
from torch import Tensor, nn

from esp.core.taoss_types import L1_DIMS, TAOSS6_ORDER, TaossType

_NAME = re.compile(r"^[A-Za-z][A-Za-z0-9]*$")


def type_name(t: TaossType | str) -> str:
    return t.name if isinstance(t, TaossType) else t


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


def spectral_clip(seq: Tensor, r_max: float) -> Tensor:
    """``E <- E * min(1, R_max / ||E||_2)`` per sample; ``seq`` is (batch, tokens, d)."""
    norms = torch.linalg.matrix_norm(seq, ord=2)
    scale = torch.clamp(r_max / norms.clamp_min(1e-12), max=1.0)
    return seq * scale[:, None, None]


class RunningStandardization(nn.Module):
    def __init__(self, dim: int, momentum: float = 0.01, eps: float = 1e-5) -> None:
        super().__init__()
        self.momentum, self.eps = momentum, eps
        self.register_buffer("running_mean", torch.zeros(dim))
        self.register_buffer("running_std", torch.ones(dim))

    def forward(self, x: Tensor, mask: Tensor | None = None) -> Tensor:
        """``mask`` (batch,) selects the rows that update the statistics (absent rows do not)."""
        rows = x if mask is None else x[mask > 0]
        if self.training and rows.shape[0] > 1:
            with torch.no_grad():
                self.running_mean.lerp_(rows.mean(0), self.momentum)  # type: ignore[operator]
                self.running_std.lerp_(rows.std(0), self.momentum)  # type: ignore[operator]
        return (x - self.running_mean) / (self.running_std + self.eps)  # type: ignore[operator]


@dataclass(frozen=True, slots=True)
class EncoderConfig[K: (TaossType, str)]:
    modality_dims: Mapping[str, int]
    d_model: int = 64
    heads: int = 4
    type_dims: Mapping[K, int] = field(default_factory=lambda: dict(L1_DIMS))  # type: ignore[arg-type]
    disc_hidden: int = 64
    lambda_cov: float = 5.0
    beta_adv: float = 0.1
    lambda_grl: float = 1.0
    alphas: Mapping[K, float] = field(default_factory=dict)
    disc_capacities: tuple[int, ...] = ()
    """Hidden sizes of a multi-capacity discriminator ensemble; empty means ``(disc_hidden,)``."""
    standardize_fusion_input: bool = False
    r_max: float | None = None
    """Certified mode: spectral clip radius at the attention input (bias-free attention)."""

    def capacities(self) -> tuple[int, ...]:
        caps = self.disc_capacities or (self.disc_hidden,)
        if len(set(caps)) != len(caps) or min(caps) < 1:
            msg = "discriminator capacities must be distinct positive sizes"
            raise ValueError(msg)
        return caps


def ordered_types[K: (TaossType, str)](type_dims: Mapping[K, int]) -> tuple[K, ...]:
    """TAOSS-6 keys in TAOSS order; named profiles in their declared order."""
    keys = tuple(type_dims)
    if all(isinstance(k, TaossType) for k in keys):
        return tuple(t for t in TAOSS6_ORDER if t in type_dims)  # type: ignore[misc]
    names = [type_name(k) for k in keys]
    if len(set(names)) != len(names) or not all(_NAME.match(n) for n in names):
        msg = "type names must be distinct identifiers (letters and digits)"
        raise ValueError(msg)
    return keys


class TaossEncoder[K: (TaossType, str)](nn.Module):
    def __init__(self, cfg: EncoderConfig[K]) -> None:
        super().__init__()
        self.cfg: EncoderConfig[K] = cfg
        self.types: tuple[K, ...] = ordered_types(cfg.type_dims)
        self.modalities = tuple(sorted(cfg.modality_dims))
        self.last_input_radius: float | None = None
        """Largest ``||E||_2`` at the attention input in the last forward (before any clip)."""
        self.encoders = nn.ModuleDict(
            {
                m: nn.Sequential(
                    nn.Linear(d, cfg.d_model), nn.GELU(), nn.Linear(cfg.d_model, cfg.d_model)
                )
                for m, d in cfg.modality_dims.items()
            }
        )
        self.gates = nn.ModuleDict({m: nn.Linear(cfg.d_model, 1) for m in cfg.modality_dims})
        if cfg.standardize_fusion_input:
            self.fusion_standardize = nn.ModuleDict(
                {m: RunningStandardization(cfg.d_model) for m in cfg.modality_dims}
            )
        if cfg.r_max is not None and cfg.r_max <= 0:
            msg = "r_max must be positive"
            raise ValueError(msg)
        self.fusion = nn.MultiheadAttention(
            cfg.d_model, cfg.heads, batch_first=True, bias=cfg.r_max is None
        )
        self.heads = nn.ModuleDict(
            {type_name(t): self._ortho(cfg.d_model, cfg.type_dims[t]) for t in self.types}
        )
        self.standardize = nn.ModuleDict(
            {type_name(t): RunningStandardization(cfg.type_dims[t]) for t in self.types}
        )
        sn = nn.utils.parametrizations.spectral_norm
        self.discriminators = nn.ModuleDict(
            {
                key: nn.Sequential(
                    sn(nn.Linear(cfg.type_dims[t], hidden)),
                    nn.ReLU(),
                    sn(nn.Linear(hidden, cfg.type_dims[s])),
                )
                for s in self.types
                for t in self.types
                if s != t
                for key, hidden in self._disc_keys(s, t)
            }
        )

    def _disc_keys(self, s: K, t: K) -> list[tuple[str, int]]:
        base = f"{type_name(s)}_from_{type_name(t)}"
        caps = self.cfg.capacities()
        return [(base if len(caps) == 1 else f"{base}_h{h}", h) for h in caps]

    @staticmethod
    def _ortho(d_in: int, d_out: int) -> nn.Linear:
        h = nn.Linear(d_in, d_out, bias=False)
        nn.init.orthogonal_(h.weight)
        return h

    def fusion_input(
        self, inputs: Mapping[str, Tensor], present: Mapping[str, Tensor] | None = None
    ) -> tuple[Tensor, Tensor]:
        """Attention input ``E`` (batch, tokens, d) after standardization and clip, and gates."""
        tokens, gates = [], []
        for m in self.modalities:
            h = self.encoders[m](inputs[m])
            g = torch.sigmoid(self.gates[m](h))
            if present is not None:
                g = g * present[m].unsqueeze(-1)
            if self.cfg.standardize_fusion_input:
                h = self.fusion_standardize[m](h, None if present is None else present[m])
            tokens.append(h * g)
            gates.append(g)
        seq = torch.stack(tokens, dim=1)
        if self.cfg.r_max is not None or self.cfg.standardize_fusion_input:
            with torch.no_grad():  # V13: the empirical R is logged (monitorable)
                self.last_input_radius = float(torch.linalg.matrix_norm(seq, ord=2).max())
        if self.cfg.r_max is not None:
            seq = spectral_clip(seq, self.cfg.r_max)
        return seq, torch.stack(gates, dim=1)

    def forward(
        self, inputs: Mapping[str, Tensor], present: Mapping[str, Tensor] | None = None
    ) -> dict[K, Tensor]:
        """``inputs[m]``: (batch, dim_m). ``present[m]``: (batch,) 0/1 mask; absent -> gated out."""
        seq, weight = self.fusion_input(inputs, present)
        fused, _ = self.fusion(seq, seq, seq)
        pooled = (fused * weight).sum(1) / weight.sum(1).clamp_min(1e-6)
        return {t: self.heads[type_name(t)](pooled) for t in self.types}

    def standardized(self, latents: Mapping[K, Tensor]) -> dict[K, Tensor]:
        return {t: self.standardize[type_name(t)](z) for t, z in latents.items()}

    def discriminator_parameters(self) -> list[nn.Parameter]:
        return list(self.discriminators.parameters())

    def losses(
        self,
        latents: Mapping[K, Tensor],
        targets: Mapping[K, Tensor],
        *,
        beta: float | None = None,
        instance_noise: float = 0.0,
        grad_penalty: float = 0.0,
    ) -> dict[str, Tensor]:
        """Task (MSE to typed targets), covariance, adversarial and gradient-penalty terms.

        ``beta`` overrides ``beta_adv`` (annealing); ``instance_noise`` is the std of
        Gaussian noise added to discriminator inputs; ``grad_penalty`` weights
        ``E||J_Disc(x)^T v||^2`` (a Hutchinson estimate of the squared Frobenius
        norm of the discriminator Jacobian) on detached inputs, so it trains only
        the discriminators.
        """
        cfg = self.cfg
        beta = cfg.beta_adv if beta is None else beta
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
        gp = torch.zeros(())
        n = next(iter(latents.values())).shape[0]
        for i, s in enumerate(self.types):
            for j, t in enumerate(self.types):
                if s == t:
                    continue
                if i < j:  # each unordered pair once for the covariance term
                    c = (std[s] - std[s].mean(0)).T @ (std[t] - std[t].mean(0)) / max(1, n - 1)
                    cov = cov + (c**2).mean()  # per-entry: independent of type dimensions
                src = grl(latents[t], cfg.lambda_grl)
                if instance_noise > 0:
                    src = src + instance_noise * torch.randn_like(src)
                for key, _ in self._disc_keys(s, t):
                    disc = self.discriminators[key]
                    rec = disc(src)
                    adv = adv + nn.functional.mse_loss(rec, latents[s].detach())
                    if grad_penalty > 0:
                        gp = gp + _jacobian_penalty(disc, latents[t].detach(), instance_noise)
        pairs = len(self.types) * (len(self.types) - 1)
        members = pairs * len(cfg.capacities())
        cov, adv = cov / (pairs // 2), adv / members  # means: lambda/beta stay comparable
        gp = gp / members
        total = task + cfg.lambda_cov * cov + beta * adv
        if grad_penalty > 0:
            total = total + grad_penalty * gp
        return {"total": total, "task": task, "cov": cov, "adv": adv, "gp": gp}


def _jacobian_penalty(disc: nn.Module, x: Tensor, instance_noise: float) -> Tensor:
    if instance_noise > 0:
        x = x + instance_noise * torch.randn_like(x)
    x = x.requires_grad_(True)
    out = disc(x)
    v = torch.randn_like(out)
    (g,) = torch.autograd.grad((out * v).sum(), x, create_graph=True)
    return (g**2).sum(1).mean()


def project_attention(model: TaossEncoder[TaossType] | TaossEncoder[str], sigma_max: float) -> None:
    """Scale ``W_Q, W_K, W_V, W_O`` down so each has spectral norm <= ``sigma_max`` (in place)."""
    d = model.cfg.d_model
    with torch.no_grad():
        w_in = model.fusion.in_proj_weight
        for block in (w_in[:d], w_in[d : 2 * d], w_in[2 * d :], model.fusion.out_proj.weight):
            sigma = float(torch.linalg.matrix_norm(block, ord=2))
            if sigma > sigma_max:
                block.mul_(sigma_max / sigma)


def export_fusion(
    model: TaossEncoder[TaossType] | TaossEncoder[str],
) -> dict[str, NDArray[np.float64]]:
    """The attention weights as float64 numpy arrays (the input of the independent verifier)."""
    out = {k: v.detach().numpy().astype(np.float64) for k, v in model.fusion.state_dict().items()}
    out["heads"] = np.array(float(model.cfg.heads))
    out["tokens"] = np.array(float(len(model.modalities)))
    return out


@torch.no_grad()
def capture_fusion_inputs(
    model: TaossEncoder[TaossType] | TaossEncoder[str],
    batches: Sequence[Mapping[str, Tensor]],
) -> NDArray[np.float64]:
    """Attention inputs ``E`` actually fed to the fusion operator, stacked over ``batches``."""
    was_training = model.training
    model.eval()
    try:
        seqs = [model.fusion_input(b)[0] for b in batches]
    finally:
        model.train(was_training)
    return torch.cat(seqs).numpy().astype(np.float64)


def type_shapes[K: (TaossType, str)](latents: Mapping[K, Tensor]) -> dict[str, tuple[int, ...]]:
    return {type_name(t): tuple(z.shape) for t, z in latents.items()}


def heads_of(model: TaossEncoder[TaossType] | TaossEncoder[str]) -> Sequence[str]:
    return [type_name(t) for t in model.types]
