# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Training harness (WP-032): configs, deterministic runs, checkpoints, metrics, metadata.

- one JSON config pins everything (seed, steps, model, data, registry digests);
- runs are deterministic on CPU (seeded torch/numpy generators, deterministic
  algorithms); resuming from a checkpoint continues *bitwise* identically;
- checkpoints hold model, optimizer, RNG states and the step;
- metrics are appended as JSON lines; experiment metadata records the
  config digest, registry binding, library versions and git commit.
"""

from __future__ import annotations

import hashlib
import json
import platform
import subprocess
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
import torch

from esp.core.taoss_types import TaossType
from esp.training.encoder import EncoderConfig, TaossEncoder


@dataclass(frozen=True, slots=True)
class DataConfig:
    n: int = 512
    factor_dim: int = 4
    noise: float = 0.05
    leak: float = 0.0
    """Share of a common factor planted into EMO and CTX targets (tests the leakage harness)."""
    seed: int = 1


@dataclass(frozen=True, slots=True)
class TrainConfig:
    modality_dims: Mapping[str, int] = field(
        default_factory=lambda: {"audio": 12, "physio": 8, "text": 16}
    )
    type_dims: Mapping[str, int] = field(
        default_factory=lambda: {"KNO": 12, "INT": 6, "EMO": 6, "CTX": 6, "SEN": 6, "TEM": 4}
    )
    d_model: int = 32
    heads: int = 4
    lambda_cov: float = 1.0
    beta_adv: float = 0.1
    lambda_grl: float = 1.0
    lr: float = 3e-3
    steps: int = 200
    batch: int = 64
    seed: int = 0
    checkpoint_every: int = 50
    data: DataConfig = field(default_factory=DataConfig)
    registries: Mapping[str, str] = field(default_factory=dict)
    """Registry name -> digest the trained encoder is bound to."""

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    def digest(self) -> str:
        return hashlib.sha256(self.to_json().encode()).hexdigest()

    @classmethod
    def from_json(cls, raw: str) -> TrainConfig:
        d = json.loads(raw)
        d["data"] = DataConfig(**d["data"])
        return cls(**d)

    def encoder_config(self) -> EncoderConfig:
        return EncoderConfig(
            modality_dims=dict(self.modality_dims),
            d_model=self.d_model,
            heads=self.heads,
            type_dims={TaossType[k]: v for k, v in self.type_dims.items()},
            disc_hidden=32,
            lambda_cov=self.lambda_cov,
            beta_adv=self.beta_adv,
            lambda_grl=self.lambda_grl,
        )


@dataclass(frozen=True, slots=True)
class SyntheticData:
    inputs: dict[str, torch.Tensor]
    targets: dict[TaossType, torch.Tensor]
    factors: dict[TaossType, np.ndarray]


def make_synthetic(cfg: TrainConfig) -> SyntheticData:
    """Independent latent factors per type, mixed into every modality with noise."""
    dc = cfg.data
    rng = np.random.default_rng(dc.seed)
    types = sorted((TaossType[k] for k in cfg.type_dims), key=lambda t: t.value)  # order-free
    factors = {t: rng.normal(size=(dc.n, dc.factor_dim)) for t in types}
    if dc.leak > 0:
        common = rng.normal(size=(dc.n, dc.factor_dim))
        for t in (TaossType.EMO, TaossType.CTX):
            if t in factors:
                factors[t] = np.sqrt(1 - dc.leak) * factors[t] + np.sqrt(dc.leak) * common
    stacked = np.concatenate([factors[t] for t in types], axis=1)
    inputs = {
        m: stacked @ rng.normal(size=(stacked.shape[1], d)) / np.sqrt(stacked.shape[1])
        + dc.noise * rng.normal(size=(dc.n, d))
        for m, d in sorted(cfg.modality_dims.items())
    }
    targets = {
        t: factors[t]
        @ rng.normal(size=(dc.factor_dim, cfg.type_dims[t.name]))
        / np.sqrt(dc.factor_dim)
        for t in types
    }

    def as_t(a: np.ndarray) -> torch.Tensor:
        return torch.from_numpy(np.ascontiguousarray(a, dtype=np.float32))

    return SyntheticData(
        inputs={m: as_t(v) for m, v in inputs.items()},
        targets={t: as_t(v) for t, v in targets.items()},
        factors=factors,
    )


def _metadata(cfg: TrainConfig) -> dict[str, Any]:
    try:
        commit = subprocess.run(
            ["git", "rev-parse", "HEAD"],  # noqa: S607
            capture_output=True,
            text=True,
            check=False,
            cwd=Path(__file__).parent,
        ).stdout.strip()
    except OSError:  # pragma: no cover
        commit = ""
    return {
        "config_digest": cfg.digest(),
        "registries": dict(cfg.registries),
        "torch": torch.__version__,
        "numpy": np.__version__,
        "python": platform.python_version(),
        "git_commit": commit or None,
        "class": "EXPERIMENTAL",
        "claims": "architecture trainable; no H1/H2/H3 claim",
    }


class Trainer:
    def __init__(self, cfg: TrainConfig, out_dir: Path) -> None:
        torch.use_deterministic_algorithms(True)
        torch.set_num_threads(1)
        self.cfg = cfg
        self.out = out_dir
        self.out.mkdir(parents=True, exist_ok=True)
        torch.manual_seed(cfg.seed)
        self.model = TaossEncoder(cfg.encoder_config())
        self.opt = torch.optim.Adam(self.model.parameters(), lr=cfg.lr)
        self.gen = torch.Generator().manual_seed(cfg.seed)
        self.step = 0
        self.data = make_synthetic(cfg)
        (self.out / "config.json").write_text(cfg.to_json() + "\n", encoding="utf-8")
        (self.out / "metadata.json").write_text(
            json.dumps(_metadata(cfg), indent=2) + "\n", encoding="utf-8"
        )

    def train(self, until_step: int | None = None) -> dict[str, float]:
        end = self.cfg.steps if until_step is None else until_step
        last: dict[str, float] = {}
        self.model.train()
        with (self.out / "metrics.jsonl").open("a", encoding="utf-8") as log:
            while self.step < end:
                idx = torch.randint(0, self.cfg.data.n, (self.cfg.batch,), generator=self.gen)
                lat = self.model({m: x[idx] for m, x in self.data.inputs.items()})
                losses = self.model.losses(lat, {t: y[idx] for t, y in self.data.targets.items()})
                self.opt.zero_grad()
                losses["total"].backward()  # type: ignore[no-untyped-call]
                self.opt.step()
                self.step += 1
                last = {k: float(v.detach()) for k, v in losses.items()}
                log.write(json.dumps({"step": self.step, **last}, sort_keys=True) + "\n")
                if self.step % self.cfg.checkpoint_every == 0:
                    self.save(self.out / f"ckpt-{self.step:06d}.pt")
        return last

    def save(self, path: Path) -> None:
        torch.save(
            {
                "step": self.step,
                "config": self.cfg.to_json(),
                "model": self.model.state_dict(),
                "opt": self.opt.state_dict(),
                "gen": self.gen.get_state(),
                "torch_rng": torch.get_rng_state(),
            },
            path,
        )

    @classmethod
    def resume(cls, path: Path, out_dir: Path) -> Trainer:
        ck = torch.load(path, weights_only=False)
        t = cls(TrainConfig.from_json(ck["config"]), out_dir)
        t.model.load_state_dict(ck["model"])
        t.opt.load_state_dict(ck["opt"])
        t.gen.set_state(ck["gen"])
        torch.set_rng_state(ck["torch_rng"])
        t.step = ck["step"]
        return t

    @torch.no_grad()
    def encode_all(self) -> dict[TaossType, np.ndarray]:
        self.model.eval()
        lat = self.model(self.data.inputs)
        self.model.train()
        return {t: z.numpy().astype(np.float64) for t, z in lat.items()}
