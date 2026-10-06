# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Drift-robust decoder family for binned intracortical spike counts (claims level 4 work).

Everything here uses only the neural data and labels a caller passes in. Adaptation
to a new recording day never uses that day's labels. The building blocks:

- **features:** optional ``sqrt`` variance stabilisation, then causal exponential
  smoothing (``tau`` in bins), computed per session with no look-ahead;
- **day normalisation (unsupervised):** per-channel z-scoring with statistics from
  a day's *unlabelled* calibration block. Training days use their own statistics;
  a new day uses its own block. This absorbs firing-rate drift of single channels;
- **CORAL (unsupervised):** after z-scoring, the new day's feature covariance
  (from its unlabelled block, shrunk toward the identity) is whitened and
  re-coloured with the pooled training covariance (Sun, Feng & Saenko 2016). This
  absorbs changes in channel correlation structure, e.g. electrode shifts;
- **ridge / Wiener filter:** closed-form ridge on lagged features (the reference
  decoder of ``esp.adapters.neural.mapping``);
- **GRU:** a small recurrent decoder in PyTorch. It is deterministic on a given
  device (seeded, ``torch.use_deterministic_algorithms``) and runs on CPU or CUDA
  (``ESP_DEVICE`` overrides auto-detection). Used for regression and for
  classification of a trial's symbol.

Nothing here is TAOSS or ESP wire code. It produces the decoder outputs that the
neural mapping profile turns into typed parts.
"""

from __future__ import annotations

import os
import platform
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

import numpy as np
from numpy.typing import NDArray
from scipy.signal import lfilter  # type: ignore[import-untyped]

F64 = NDArray[np.float64]
Mask = NDArray[np.bool_]


# --- features ------------------------------------------------------------------------------------


def smooth(x: F64, tau_bins: float) -> F64:
    """Causal exponential smoothing ``y_t = a*y_{t-1} + (1-a)*x_t`` (zero initial state)."""
    if tau_bins <= 0:
        return np.asarray(x, dtype=np.float64)
    a = float(np.exp(-1.0 / tau_bins))
    out: F64 = lfilter([1.0 - a], [1.0, -a], np.asarray(x, dtype=np.float64), axis=0)
    return out


def preprocess(counts: F64, *, sqrt: bool, tau_bins: float) -> F64:
    x = np.sqrt(np.maximum(counts, 0.0)) if sqrt else np.asarray(counts, dtype=np.float64)
    return smooth(x, tau_bins)


def lag_stack(x: F64, lags: int, stride: int = 1) -> F64:
    """``[x_t, x_{t-s}, …, x_{t-lags*s}]`` per row, zero-padded at the session start."""
    cols = [x]
    for k in range(1, lags + 1):
        shifted = np.zeros_like(x)
        shifted[k * stride :] = x[: -k * stride]
        cols.append(shifted)
    return np.concatenate(cols, axis=1)


# --- unsupervised day adaptation -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DayStats:
    mean: F64
    std: F64

    @classmethod
    def of(cls, x: F64, floor: float = 0.05) -> DayStats:
        """Per-channel mean and std; near-silent channels are floored (no blow-up)."""
        return cls(x.mean(axis=0), np.maximum(x.std(axis=0), floor))

    def apply(self, x: F64) -> F64:
        out: F64 = (x - self.mean) / self.std
        return out


def _sqrtm_psd(c: F64, inverse: bool = False) -> F64:
    w, v = np.linalg.eigh((c + c.T) / 2)
    w = np.maximum(w, 1e-2 * max(float(w.mean()), 1e-12))  # relative floor: stable inverse
    p = -0.5 if inverse else 0.5
    out: F64 = (v * w**p) @ v.T
    return out


def shrunk_cov(x: F64, shrink: float) -> F64:
    c = np.cov(x, rowvar=False)
    target = np.eye(c.shape[0]) * float(np.trace(c)) / c.shape[0]
    out: F64 = (1 - shrink) * c + shrink * target
    return out


@dataclass(frozen=True, slots=True)
class Coral:
    """Re-colour a new day's (z-scored) features with the reference covariance."""

    ref_sqrt: F64
    shrink: float

    @classmethod
    def fit_reference(cls, x_ref: F64, shrink: float) -> Coral:
        return cls(_sqrtm_psd(shrunk_cov(x_ref, shrink)), shrink)

    def transform(self, x_new_block: F64, x: F64) -> F64:
        """Map ``x`` using statistics estimated on the new day's unlabelled block only."""
        mu = x_new_block.mean(axis=0)
        white = _sqrtm_psd(shrunk_cov(x_new_block, self.shrink), inverse=True)
        out: F64 = (x - mu) @ white @ self.ref_sqrt
        return out


# --- metrics -------------------------------------------------------------------------------------


def r2_variance_weighted(y: F64, pred: F64) -> float:
    ss_res = float(np.sum((y - pred) ** 2))
    ss_tot = float(np.sum((y - y.mean(axis=0)) ** 2))
    return 1.0 - ss_res / ss_tot if ss_tot > 0 else float("nan")


# --- ridge ---------------------------------------------------------------------------------------


@dataclass
class Ridge:
    alpha: float
    w: F64 | None = None
    b: F64 | None = None
    mu: F64 | None = None
    sd: F64 | None = None

    def fit(self, x: F64, y: F64, weights: F64 | None = None) -> Ridge:
        w = np.ones(len(x)) if weights is None else np.asarray(weights, dtype=np.float64)
        w = w / w.mean()
        self.mu = np.average(x, axis=0, weights=w)
        self.sd = np.sqrt(np.average((x - self.mu) ** 2, axis=0, weights=w)) + 1e-9
        xs = (x - self.mu) / self.sd
        self.b = np.average(y, axis=0, weights=w)
        xw = xs * w[:, None]
        a = xw.T @ xs + self.alpha * np.eye(xs.shape[1])
        self.w = np.linalg.solve(a, xw.T @ (y - self.b))
        return self

    def predict(self, x: F64) -> F64:
        if self.w is None or self.b is None or self.mu is None or self.sd is None:
            msg = "ridge not fitted"
            raise RuntimeError(msg)
        out: F64 = ((x - self.mu) / self.sd) @ self.w + self.b
        return out


# --- torch helpers -------------------------------------------------------------------------------


def device_name() -> str:
    import torch  # noqa: PLC0415 - torch is optional for the numpy parts

    forced = os.environ.get("ESP_DEVICE")
    if forced:
        return forced
    return "cuda" if torch.cuda.is_available() else "cpu"


def set_deterministic(seed: int) -> None:
    import torch  # noqa: PLC0415

    os.environ.setdefault("CUBLAS_WORKSPACE_CONFIG", ":4096:8")
    torch.manual_seed(seed)
    np.random.seed(seed)
    torch.use_deterministic_algorithms(True)
    torch.backends.cudnn.benchmark = False


def hardware_record() -> dict[str, Any]:
    import torch  # noqa: PLC0415

    dev = device_name()
    rec: dict[str, Any] = {
        "device": dev,
        "torch": torch.__version__,
        "numpy": np.__version__,
        "python": platform.python_version(),
        "cpu": platform.processor() or platform.machine(),
        "torch_threads": torch.get_num_threads(),
    }
    if dev.startswith("cuda") and torch.cuda.is_available():
        rec["gpu"] = torch.cuda.get_device_name(0)
        rec["cuda"] = torch.version.cuda
        rec["cudnn"] = torch.backends.cudnn.version()  # type: ignore[no-untyped-call]
    return rec


@dataclass(frozen=True, slots=True)
class GruConfig:
    hidden: int = 128
    layers: int = 1
    dropout: float = 0.2
    input_dropout: float = 0.1
    lr: float = 2e-3
    weight_decay: float = 1e-4
    epochs: int = 30
    chunk: int = 250
    """Training sequence length in bins (5 s at 20 ms)."""
    batch: int = 32
    seed: int = 0
    patience: int = 5


@dataclass
class GruDecoder:
    """Sequence-to-sequence GRU. ``n_classes > 0`` makes it a trial classifier."""

    n_in: int
    n_out: int
    cfg: GruConfig = field(default_factory=GruConfig)
    n_classes: int = 0
    model: Any = None
    y_mean: F64 | None = None
    y_std: F64 | None = None
    history: list[dict[str, float]] = field(default_factory=list)

    def _build(self) -> Any:  # noqa: ANN401 - torch module
        import torch  # noqa: PLC0415
        from torch import nn  # noqa: PLC0415

        cfg, n_out = self.cfg, (self.n_classes or self.n_out)

        class Net(nn.Module):
            def __init__(self, n_in: int) -> None:
                super().__init__()
                self.drop_in = nn.Dropout(cfg.input_dropout)
                self.gru = nn.GRU(
                    n_in,
                    cfg.hidden,
                    num_layers=cfg.layers,
                    batch_first=True,
                    dropout=cfg.dropout if cfg.layers > 1 else 0.0,
                )
                self.drop = nn.Dropout(cfg.dropout)
                self.out = nn.Linear(cfg.hidden, n_out)

            def forward(self, x: torch.Tensor) -> torch.Tensor:
                h, _ = self.gru(self.drop_in(x))
                return self.out(self.drop(h))  # type: ignore[no-any-return]

        return Net(self.n_in)

    def _chunks(
        self, xs: Sequence[F64], ys: Sequence[F64], ms: Sequence[Mask]
    ) -> tuple[F64, F64, NDArray[np.float32]]:
        c = self.cfg.chunk
        bx, by, bm = [], [], []
        for x, y, m in zip(xs, ys, ms, strict=True):
            for s in range(0, max(1, len(x) - c + 1), c // 2):
                seg = slice(s, s + c)
                if len(x[seg]) < c:
                    continue
                bx.append(x[seg])
                by.append(y[seg])
                bm.append(m[seg])
        return np.stack(bx), np.stack(by), np.stack(bm).astype(np.float32)

    def fit(
        self,
        xs: Sequence[F64],
        ys: Sequence[F64],
        ms: Sequence[Mask],
        val: tuple[Sequence[F64], Sequence[F64], Sequence[Mask]] | None = None,
    ) -> GruDecoder:
        import torch  # noqa: PLC0415

        set_deterministic(self.cfg.seed)
        dev = torch.device(device_name())
        if self.n_classes == 0:
            ally = np.concatenate([y[m] for y, m in zip(ys, ms, strict=True)])
            self.y_mean, self.y_std = ally.mean(axis=0), ally.std(axis=0) + 1e-6
            ys = [(y - self.y_mean) / self.y_std for y in ys]
        bx, by, bm = self._chunks(xs, ys, ms)
        tx = torch.tensor(bx, dtype=torch.float32, device=dev)
        ty = torch.tensor(by, dtype=torch.float32 if not self.n_classes else torch.long, device=dev)
        tm = torch.tensor(bm, device=dev)
        self.model = self._build().to(dev)
        opt = torch.optim.AdamW(
            self.model.parameters(), lr=self.cfg.lr, weight_decay=self.cfg.weight_decay
        )
        gen = torch.Generator(device="cpu").manual_seed(self.cfg.seed)
        best, best_state, bad = float("inf"), None, 0
        for epoch in range(self.cfg.epochs):
            self.model.train()
            perm = torch.randperm(len(tx), generator=gen)
            total = 0.0
            for i in range(0, len(tx), self.cfg.batch):
                idx = perm[i : i + self.cfg.batch].to(dev)
                loss = self._loss(self.model(tx[idx]), ty[idx], tm[idx])
                opt.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.model.parameters(), 1.0)
                opt.step()
                total += float(loss.detach()) * len(idx)
            rec = {"epoch": float(epoch), "train_loss": total / len(tx)}
            if val is not None:
                v = self.val_loss(*val)
                rec["val_loss"] = v
                if v < best - 1e-4:
                    best, bad = v, 0
                    best_state = {k: t.detach().clone() for k, t in self.model.state_dict().items()}
                else:
                    bad += 1
            self.history.append(rec)
            if val is not None and bad >= self.cfg.patience:
                break
        if best_state is not None:
            self.model.load_state_dict(best_state)
        return self

    def _loss(self, out: Any, y: Any, m: Any) -> Any:  # noqa: ANN401 - torch tensors
        import torch  # noqa: PLC0415

        if self.n_classes:
            # classification: every masked step predicts the trial's class
            lp = torch.log_softmax(out, dim=-1)
            nll = -lp.gather(-1, y[..., None]).squeeze(-1)
            return (nll * m).sum() / m.sum().clamp(min=1.0)
        err = ((out - y) ** 2).mean(dim=-1)
        return (err * m).sum() / m.sum().clamp(min=1.0)

    def val_loss(self, xs: Sequence[F64], ys: Sequence[F64], ms: Sequence[Mask]) -> float:
        import torch  # noqa: PLC0415

        dev = next(self.model.parameters()).device
        tot, n = 0.0, 0.0
        self.model.eval()
        with torch.no_grad():
            for x, y, m in zip(xs, ys, ms, strict=True):
                if self.n_classes or self.y_mean is None or self.y_std is None:
                    yy = y
                else:
                    yy = (y - self.y_mean) / self.y_std
                out = self.model(torch.tensor(x[None], dtype=torch.float32, device=dev))
                ty = torch.tensor(yy[None], device=dev)
                if not self.n_classes:
                    ty = ty.float()
                tm = torch.tensor(m[None].astype(np.float32), device=dev)
                w = float(tm.sum())
                tot += float(self._loss(out, ty, tm)) * w
                n += w
        return tot / max(n, 1.0)

    def predict(self, x: F64) -> F64:
        """Regression: de-standardised outputs. Classification: per-step log-probabilities."""
        import torch  # noqa: PLC0415

        dev = next(self.model.parameters()).device
        self.model.eval()
        with torch.no_grad():
            out = self.model(torch.tensor(x[None], dtype=torch.float32, device=dev))[0]
            if self.n_classes:
                res: F64 = torch.log_softmax(out, dim=-1).cpu().numpy().astype(np.float64)
                return res
        pred: F64 = out.cpu().numpy().astype(np.float64)
        if self.y_mean is not None and self.y_std is not None:
            pred = pred * self.y_std + self.y_mean
        return pred
