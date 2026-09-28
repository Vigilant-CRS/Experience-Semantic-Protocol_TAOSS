# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-031/WP-032: encoder skeleton, gradients, deterministic training and checkpoints."""

import dataclasses
import json
from pathlib import Path

import pytest

torch = pytest.importorskip("torch")

from esp.core.taoss_types import L1_DIMS, TaossType  # noqa: E402
from esp.training.encoder import EncoderConfig, TaossEncoder, grl  # noqa: E402
from esp.training.harness import DataConfig, TrainConfig, Trainer  # noqa: E402

T = TaossType


def test_full_size_heads_have_v13_dimensions() -> None:
    model = TaossEncoder(EncoderConfig(modality_dims={"audio": 10, "text": 20}, d_model=32))
    out = model({"audio": torch.randn(3, 10), "text": torch.randn(3, 20)})
    assert {t: z.shape for t, z in out.items()} == {t: (3, d) for t, d in L1_DIMS.items()}
    assert len(model.discriminators) == 30  # 6 x 5 ordered pairs
    w = model.heads["EMO"].weight
    assert torch.allclose(w.T @ w, torch.eye(32), atol=1e-5)  # orthonormal columns (64 x 32)


def test_gradient_reversal_flips_the_sign() -> None:
    x = torch.randn(4, 3, requires_grad=True)
    (grl(x, 0.7) * 2.0).sum().backward()
    assert torch.allclose(x.grad, torch.full((4, 3), -1.4))


def test_all_losses_have_finite_nonzero_gradients() -> None:
    cfg = TrainConfig(steps=1)
    model = TaossEncoder(cfg.encoder_config())
    data = {m: torch.randn(16, d) for m, d in cfg.modality_dims.items()}
    lat = model(data)
    targets = {t: torch.randn_like(z) for t, z in lat.items()}
    losses = model.losses(lat, targets)
    losses["total"].backward()
    for name, p in model.named_parameters():
        if p.grad is not None:
            assert torch.isfinite(p.grad).all(), name
    for part in ("heads", "encoders", "discriminators", "fusion"):
        assert any(
            p.grad is not None and p.grad.abs().sum() > 0
            for n, p in model.named_parameters()
            if n.startswith(part)
        ), part


def test_missing_modality_gate_removes_its_influence() -> None:
    cfg = TrainConfig()
    model = TaossEncoder(cfg.encoder_config()).eval()
    x = {m: torch.randn(2, d) for m, d in cfg.modality_dims.items()}
    y = dict(x) | {"audio": torch.randn(2, cfg.modality_dims["audio"]) * 100}
    present = {m: torch.ones(2) for m in x} | {"audio": torch.zeros(2)}
    a, b = model(x, present), model(y, present)
    for t in a:
        assert torch.allclose(a[t], b[t], atol=1e-5)  # absent audio cannot change the output


def test_tiny_training_converges(tmp_path: Path) -> None:
    t = Trainer(TrainConfig(steps=300), tmp_path)
    first = t.train(until_step=1)["task"]
    last = t.train()
    assert last["task"] < 0.35 * first
    rows = [json.loads(line) for line in (tmp_path / "metrics.jsonl").read_text().splitlines()]
    assert len(rows) == 300
    assert json.loads((tmp_path / "metadata.json").read_text())["config_digest"] == t.cfg.digest()


def test_runs_and_checkpoints_are_bitwise_reproducible(tmp_path: Path) -> None:
    cfg = TrainConfig(steps=40, checkpoint_every=20)
    straight = Trainer(cfg, tmp_path / "a")
    straight.train()
    twin = Trainer(cfg, tmp_path / "b")
    twin.train()
    resumed = Trainer.resume(tmp_path / "a" / "ckpt-000020.pt", tmp_path / "c")
    resumed.train()
    for other in (twin, resumed):
        for (k, v), (_, w) in zip(
            straight.model.state_dict().items(), other.model.state_dict().items(), strict=True
        ):
            assert torch.equal(v, w), k


def test_config_roundtrip_and_registry_binding(tmp_path: Path) -> None:
    cfg = TrainConfig(registries={"esp-emo-v13-basic8-v1": "ab" * 32}, data=DataConfig(n=64))
    assert TrainConfig.from_json(cfg.to_json()) == cfg
    assert dataclasses.replace(cfg, seed=1).digest() != cfg.digest()
    Trainer(cfg, tmp_path)
    meta = json.loads((tmp_path / "metadata.json").read_text())
    assert meta["registries"] == {"esp-emo-v13-basic8-v1": "ab" * 32}
    assert "no H1/H2/H3 claim" in meta["claims"]


def test_synthetic_data_does_not_depend_on_dict_order() -> None:
    """Regression: JSON round trips sort keys; data must not change with the type order."""
    from esp.training.harness import make_synthetic  # noqa: PLC0415

    a = TrainConfig()
    b = dataclasses.replace(a, type_dims=dict(sorted(a.type_dims.items())))
    assert list(a.type_dims) != list(b.type_dims)
    da, db = make_synthetic(a), make_synthetic(b)
    for t in da.targets:
        assert torch.equal(da.targets[t], db.targets[t])
