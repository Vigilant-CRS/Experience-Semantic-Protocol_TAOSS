# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-073: encoder stability mechanisms (V13 section "Stability Mechanisms")."""

import dataclasses
import json
import math
from itertools import pairwise
from pathlib import Path

import numpy as np
import pytest

torch = pytest.importorskip("torch")

from esp.core.taoss_types import TaossType  # noqa: E402
from esp.training.encoder import EncoderConfig, TaossEncoder  # noqa: E402
from esp.training.harness import (  # noqa: E402
    DataConfig,
    TrainConfig,
    Trainer,
    modality_dropout_mask,
    train_step,
)
from esp.training.stability import (  # noqa: E402
    CertifiedConfig,
    EarlyStopConfig,
    EarlyStopState,
    StabilityConfig,
    holdout_leakage,
)

TYPES3 = {"KNO": 6, "EMO": 4, "CTX": 4}
CERT = CertifiedConfig(r_max=4.0, sigma_max=1.0, ceiling=50.0)


def all_on(**kw: object) -> StabilityConfig:
    """Every V13 mechanism on, certified mode included; early stopping never triggers."""
    base = StabilityConfig.recommended(certified=CERT)
    return dataclasses.replace(base, early_stop=EarlyStopConfig(eval_every=50, patience=100), **kw)


def small(st: StabilityConfig, **kw: object) -> TrainConfig:
    fields: dict[str, object] = {
        "steps": 300,
        "batch": 32,
        "lr": 5e-3,
        "type_dims": TYPES3,
        "data": DataConfig(n=40),
        "stability": st,
    }
    return TrainConfig(**(fields | kw))  # type: ignore[arg-type]


def params(model: torch.nn.Module, prefix: str) -> dict[str, torch.Tensor]:
    return {n: p.detach().clone() for n, p in model.named_parameters() if n.startswith(prefix)}


# --- configuration and schedules ----------------------------------------------------------------


def test_config_roundtrip_with_every_mechanism() -> None:
    cfg = small(all_on())
    assert TrainConfig.from_json(cfg.to_json()) == cfg
    assert json.loads(cfg.to_json())["stability"]["certified"]["r_max"] == 4.0
    legacy = json.loads(TrainConfig().to_json())
    del legacy["stability"]  # configs written before WP-073 still load, mechanisms off
    assert TrainConfig.from_json(json.dumps(legacy)).stability == StabilityConfig()


def test_invalid_stability_settings_are_refused() -> None:
    for bad in (
        {"grad_penalty": -1.0},
        {"beta_anneal_frac": 1.5},
        {"modality_dropout": 1.0},
        {"encoder_only_every": -1},
    ):
        with pytest.raises(ValueError, match="must"):
            StabilityConfig(**bad)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="estimator"):
        EarlyStopConfig(estimator="dcor")  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="distinct"):
        EncoderConfig(modality_dims={"a": 2}, disc_capacities=(8, 8)).capacities()


def test_beta_is_annealed_over_the_first_20_percent() -> None:
    st = StabilityConfig(beta_anneal_frac=0.2)
    betas = [st.beta(0.5, s, 100) for s in range(100)]
    assert betas[0] == 0.0
    assert betas[10] == pytest.approx(0.25)
    assert all(b == 0.5 for b in betas[20:])
    assert all(a is not None and b is not None and a <= b for a, b in pairwise(betas))
    assert StabilityConfig().beta(0.5, 0, 100) is None  # off: the configured beta is used


def test_instance_noise_anneals_to_zero_and_encoder_only_epochs() -> None:
    st = StabilityConfig(instance_noise=0.2, encoder_only_every=3)
    assert st.noise(0, 100) == 0.2
    assert st.noise(50, 100) == pytest.approx(0.1)
    assert st.noise(100, 100) == 0.0
    frozen = [st.encoder_only(s, 4) for s in range(24)]  # 4 steps per epoch
    assert frozen == [False] * 8 + [True] * 4 + [False] * 8 + [True] * 4


# --- mechanisms -----------------------------------------------------------------------------------


def test_multi_capacity_ensemble() -> None:
    cfg = small(StabilityConfig(disc_capacities=(8, 32)))
    model = TaossEncoder(cfg.encoder_config())
    assert len(model.discriminators) == 3 * 2 * 2
    assert {k.rsplit("_h", 1)[1] for k in model.discriminators} == {"8", "32"}
    hidden = {k: m[0].out_features for k, m in model.discriminators.items()}
    assert all(int(k.rsplit("_h", 1)[1]) == v for k, v in hidden.items())
    x = {m: torch.randn(16, d) for m, d in cfg.modality_dims.items()}
    lat = model(x)
    losses = model.losses(lat, {t: torch.randn_like(z) for t, z in lat.items()})
    losses["total"].backward()
    for key in model.discriminators:
        grads = [p.grad for p in model.discriminators[key].parameters()]
        assert all(g is not None and torch.isfinite(g).all() for g in grads), key


def test_gradient_penalty_trains_only_the_discriminators() -> None:
    torch.manual_seed(0)
    model = TaossEncoder(small(StabilityConfig()).encoder_config())
    x = {m: torch.randn(16, d) for m, d in model.cfg.modality_dims.items()}
    lat = model(x)
    gp = model.losses(lat, {}, grad_penalty=1.0)["gp"]
    assert gp > 0
    gp.backward()
    touched = {
        n
        for n, p in model.named_parameters()
        if p.grad is not None and bool(p.grad.abs().sum() > 0)
    }
    assert all(n.startswith("discriminators.") for n in touched)  # never the encoder
    for key in model.discriminators:  # every discriminator's weights (biases do not enter J)
        assert any(n.startswith(f"discriminators.{key}.") and "weight" in n for n in touched), key


def test_instance_noise_reaches_the_discriminator_inputs() -> None:
    torch.manual_seed(0)
    model = TaossEncoder(small(StabilityConfig()).encoder_config())
    x = {m: torch.randn(16, d) for m, d in model.cfg.modality_dims.items()}
    lat = model(x)
    model.eval()  # freeze the spectral-norm power iteration so only the noise differs
    clean = model.losses(lat, {})["adv"]
    torch.manual_seed(1)
    noisy = model.losses(lat, {}, instance_noise=1.0)["adv"]
    torch.manual_seed(1)
    again = model.losses(lat, {}, instance_noise=1.0)["adv"]
    assert noisy != clean
    assert noisy == again  # seeded: deterministic


def test_encoder_only_updates_freeze_the_discriminators() -> None:
    cfg = small(StabilityConfig())
    for every, frozen in ((1, True), (0, False)):  # k=0 is the mutation: nothing frozen
        torch.manual_seed(0)
        model = TaossEncoder(cfg.encoder_config())
        opt = torch.optim.Adam(model.parameters(), lr=1e-2)
        gen = torch.Generator().manual_seed(0)
        before_d, before_e = params(model, "discriminators"), params(model, "encoders")
        st = StabilityConfig(encoder_only_every=every)
        for step in range(3):
            x = {m: torch.randn(16, d) for m, d in cfg.modality_dims.items()}
            y = {TaossType[t]: torch.randn(16, n) for t, n in TYPES3.items()}
            out = train_step(model, opt, x, y, st, step=step, steps=3, steps_per_epoch=1, gen=gen)
            assert out.get("encoder_only", 0.0) == float(frozen)
        after_d, after_e = params(model, "discriminators"), params(model, "encoders")
        same = all(torch.equal(before_d[k], after_d[k]) for k in before_d)
        assert same is frozen
        assert not all(torch.equal(before_e[k], after_e[k]) for k in before_e)


def test_modality_dropout_keeps_at_least_one_modality() -> None:
    gen = torch.Generator().manual_seed(0)
    mask = modality_dropout_mask(("a", "b", "c"), 4000, 0.6, gen)
    stacked = torch.stack(list(mask.values()), 1)
    assert bool((stacked.sum(1) >= 1).all())
    assert 0.3 < float(1 - stacked.mean()) < 0.6  # about p, less the restored rows


def test_fusion_standardization_ignores_absent_modalities() -> None:
    cfg = small(StabilityConfig(standardize_fusion_input=True))
    model = TaossEncoder(cfg.encoder_config())
    x = {m: torch.randn(8, d) for m, d in cfg.modality_dims.items()}
    present = {m: torch.ones(8) for m in x} | {"audio": torch.zeros(8)}
    stats = model.fusion_standardize["audio"].running_mean.clone()
    model.train()(x, present)
    assert torch.equal(model.fusion_standardize["audio"].running_mean, stats)
    assert not torch.equal(model.fusion_standardize["text"].running_mean, stats)
    model.eval()
    y = dict(x) | {"audio": torch.randn(8, cfg.modality_dims["audio"]) * 100}
    a, b = model(x, present), model(y, present)
    for t in a:
        assert torch.allclose(a[t], b[t], atol=1e-5)  # absent audio still has no influence
    assert model.last_input_radius is not None
    assert model.last_input_radius > 0


# --- early stopping ------------------------------------------------------------------------------


def test_plateau_rule() -> None:
    cfg = EarlyStopConfig(patience=2, min_delta=0.01)
    state = EarlyStopState()
    assert not state.update(10, 0.5, cfg)
    assert not state.update(20, 0.4, cfg)
    assert not state.update(30, 0.395, cfg)  # below min_delta: 1 without improvement
    assert state.update(40, 0.41, cfg)
    assert state.stopped_at == 40
    assert state.update(50, 0.1, cfg)  # stays stopped


def test_early_stopping_on_held_out_hsic_plateau(tmp_path: Path) -> None:
    st = StabilityConfig(early_stop=EarlyStopConfig(eval_every=10, patience=3, min_delta=1e-3))
    cfg = TrainConfig(steps=400, data=DataConfig(n=256), stability=st, checkpoint_every=1000)
    t = Trainer(cfg, tmp_path / "a")
    t.train()
    assert t.stopped
    assert t.early.stopped_at == t.step < cfg.steps
    assert [s for s, _ in t.early.history] == list(range(10, t.step + 1, 10))
    rows = [json.loads(r) for r in (tmp_path / "a" / "metrics.jsonl").read_text().splitlines()]
    assert rows[-1]["early_stopped"] == 1.0
    assert len(rows) == t.step
    ckpt = tmp_path / "a" / f"ckpt-{t.step:06d}.pt"
    assert ckpt.exists()  # the stopping point is always checkpointed
    resumed = Trainer.resume(ckpt, tmp_path / "b")
    assert resumed.stopped
    assert resumed.early.history == t.early.history
    resumed.train()
    assert resumed.step == t.step  # a stopped run does not continue


def test_holdout_uses_unseen_samples_and_mine_leaves_the_rng_alone() -> None:
    cfg = small(StabilityConfig(early_stop=EarlyStopConfig(holdout_frac=0.25)))
    assert cfg.n_train() == 30
    rng = np.random.default_rng(0)
    common = rng.normal(size=(120, 2))
    lat = {
        "A": common + 0.1 * rng.normal(size=(120, 2)),
        "B": common,
        "C": rng.normal(size=(120, 2)),
    }
    state = torch.get_rng_state()
    mine = holdout_leakage(lat, EarlyStopConfig(estimator="mine", mine_steps=50), seed=3)
    assert torch.equal(torch.get_rng_state(), state)
    assert math.isfinite(mine)
    assert mine >= 0
    dependent = holdout_leakage(lat, EarlyStopConfig())
    independent = holdout_leakage({"A": lat["A"], "C": lat["C"]}, EarlyStopConfig())
    assert dependent > independent


# --- whole runs ----------------------------------------------------------------------------------


def test_every_mechanism_is_bitwise_reproducible_and_resumable(tmp_path: Path) -> None:
    cfg = small(all_on(), steps=40, checkpoint_every=20, data=DataConfig(n=80))
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
        assert other.early.history == straight.early.history


def test_tiny_overfit_with_every_mechanism_active(tmp_path: Path) -> None:
    t = Trainer(small(all_on()), tmp_path)
    first = t.train(until_step=1)
    last = t.train()
    assert last["task"] < 0.1 * first["task"]
    for key in ("gp", "beta", "instance_noise", "encoder_only", "fusion_input_radius"):
        assert key in last, key
    assert last["gp"] > 0
    assert last["beta"] == pytest.approx(t.cfg.beta_adv)
    rows = [json.loads(r) for r in (tmp_path / "metrics.jsonl").read_text().splitlines()]
    assert rows[0]["beta"] == 0.0  # annealing starts at 0
    assert any(r["encoder_only"] == 1.0 for r in rows)
    assert any(r["encoder_only"] == 0.0 for r in rows)
    assert "holdout_leakage" in rows[49]
