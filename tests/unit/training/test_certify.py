# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-073 certified-stability mode: explicit spectral clip at R_max and an independent check.

Gate condition of M8 ("Certified-Mode-Check"): the measured Lipschitz bound of a
trained certified encoder is at most the declared bound, the empirical ratio is at
most the measured bound, and disabling the clip (or the weight projection) fails
the check.
"""

import ast
import math
from pathlib import Path

import numpy as np
import pytest

torch = pytest.importorskip("torch")

import esp.training.certify as certify  # noqa: E402
import esp.training.encoder as encoder  # noqa: E402
import esp.training.harness as harness  # noqa: E402
from esp.training.encoder import (  # noqa: E402
    TaossEncoder,
    capture_fusion_inputs,
    export_fusion,
    spectral_clip,
)
from esp.training.harness import DataConfig, TrainConfig, Trainer  # noqa: E402
from esp.training.stability import CertifiedConfig, StabilityConfig, declared_bound  # noqa: E402

R_MAX, SIGMA = 4.0, 1.0
DECLARED = declared_bound(r_max=R_MAX, sigma_max=SIGMA, tokens=3, d_model=32, heads=4)
CERT = CertifiedConfig(r_max=R_MAX, sigma_max=SIGMA, ceiling=50.0)


def certified_cfg(cert: CertifiedConfig = CERT, steps: int = 60) -> TrainConfig:
    return TrainConfig(
        steps=steps,
        data=DataConfig(n=128),
        stability=StabilityConfig(standardize_fusion_input=True, certified=cert),
    )


def audit_inputs(t: Trainer) -> np.ndarray:
    """Real inputs plus inputs scaled far outside any training range."""
    x = t.data.inputs
    return capture_fusion_inputs(t.model, [x, {m: v * 1000.0 for m, v in x.items()}])


@pytest.fixture(scope="module")
def trained(tmp_path_factory: pytest.TempPathFactory) -> Trainer:
    t = Trainer(certified_cfg(), tmp_path_factory.mktemp("cert"))
    t.train()
    return t


def test_declared_bound_formula_and_ceiling() -> None:
    tau, n = math.sqrt(8), 3
    l_h = math.sqrt(n) + 2 * math.sqrt(n) * R_MAX**2 / tau
    assert pytest.approx(math.sqrt(4) * l_h) == DECLARED
    assert CERT.check(tokens=3, d_model=32, heads=4) == pytest.approx(DECLARED)
    with pytest.raises(ValueError, match="exceeds the ceiling"):
        CertifiedConfig(r_max=R_MAX, sigma_max=SIGMA, ceiling=DECLARED / 2).check(
            tokens=3, d_model=32, heads=4
        )
    with pytest.raises(ValueError, match="exceeds the ceiling"):
        certified_cfg(CertifiedConfig(r_max=40.0, sigma_max=1.0, ceiling=50.0)).encoder_config()


def test_spectral_clip() -> None:
    torch.manual_seed(0)
    seq = torch.randn(64, 3, 32) * torch.logspace(-2, 3, 64)[:, None, None]
    out = spectral_clip(seq, R_MAX)
    norms_in = torch.linalg.matrix_norm(seq, ord=2)
    norms_out = torch.linalg.matrix_norm(out, ord=2)
    assert bool((norms_out <= R_MAX * (1 + 1e-5)).all())
    inside = norms_in <= R_MAX
    assert bool(inside.any())
    assert bool((~inside).any())
    assert torch.equal(out[inside], seq[inside])  # the ball is left untouched
    assert torch.allclose(norms_out[~inside], torch.full_like(norms_out[~inside], R_MAX))


def test_certified_model_is_bias_free_and_numpy_attention_matches_torch() -> None:
    torch.manual_seed(0)
    model = TaossEncoder(certified_cfg().encoder_config()).eval()
    assert model.fusion.in_proj_bias is None
    assert model.fusion.out_proj.bias is None
    w = certify.AttentionWeights.from_export(export_fusion(model))
    assert not w.has_bias
    assert (w.heads, w.tokens, w.d_k) == (4, 3, 8)
    e = torch.randn(5, 3, 32)
    with torch.no_grad():
        ref = model.fusion(e, e, e)[0].numpy()
    for i in range(5):
        np.testing.assert_allclose(
            certify.mha(w, e[i].numpy().astype(np.float64)), ref[i], atol=1e-5
        )


def test_trained_certified_encoder_passes_the_independent_check(trained: Trainer) -> None:
    report = certify.verify(
        export_fusion(trained.model), audit_inputs(trained), r_max=R_MAX, ceiling=CERT.ceiling
    )
    assert report.passed, report.failures
    assert report.r_observed <= R_MAX * (1 + certify.RADIUS_TOL)
    assert report.empirical <= report.bound <= DECLARED <= CERT.ceiling  # measured <= declared
    assert report.w_o_norm <= SIGMA * (1 + 1e-5)
    assert report.power_iteration_agrees
    rows = (trained.out / "metrics.jsonl").read_text().splitlines()
    assert '"fusion_input_radius"' in rows[-1]  # V13: the empirical R is logged


def test_mutation_clip_disabled_fails(trained: Trainer, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(encoder, "spectral_clip", lambda seq, r_max: seq)
    report = certify.verify(
        export_fusion(trained.model), audit_inputs(trained), r_max=R_MAX, ceiling=CERT.ceiling
    )
    assert not report.passed
    assert any("observed input radius" in f for f in report.failures)
    assert report.r_observed > 10 * R_MAX


def test_mutation_weight_projection_disabled_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(harness, "project_attention", lambda model, sigma_max: None)
    tight = CertifiedConfig(r_max=R_MAX, sigma_max=0.5, ceiling=10.0)
    t = Trainer(certified_cfg(tight, steps=20), tmp_path)
    t.train()
    report = certify.verify(export_fusion(t.model), audit_inputs(t), r_max=R_MAX, ceiling=10.0)
    assert any("exceeds the ceiling" in f for f in report.failures)
    declared = declared_bound(r_max=R_MAX, sigma_max=0.5, tokens=3, d_model=32, heads=4)
    assert report.bound > declared


def test_probe_has_teeth(trained: Trainer, monkeypatch: pytest.MonkeyPatch) -> None:
    exported = export_fusion(trained.model)
    w = certify.AttentionWeights.from_export(exported)
    empirical, targeted = certify.empirical_lipschitz(w, R_MAX)
    sigma_vo = certify.spectral_norm(w.w_v @ w.w_o)
    assert targeted == pytest.approx(sigma_vo, rel=1e-9)  # attained exactly (uniform attention)
    assert empirical >= targeted
    # mutation: a bound that is too small must be caught by the empirical probe
    monkeypatch.setattr(certify, "lipschitz_bound", lambda weights, r: 0.5 * sigma_vo)
    report = certify.verify(exported, audit_inputs(trained), r_max=R_MAX, ceiling=CERT.ceiling)
    assert any("empirical ratio" in f for f in report.failures)


def test_uncertified_model_fails_the_bias_premise() -> None:
    torch.manual_seed(0)
    model = TaossEncoder(TrainConfig().encoder_config())
    x = {m: torch.randn(4, d) for m, d in model.cfg.modality_dims.items()}
    report = certify.verify(
        export_fusion(model), capture_fusion_inputs(model, [x]), r_max=1e9, ceiling=1e30
    )
    assert report.has_bias
    assert any("biases" in f for f in report.failures)


def test_power_iteration_agrees_with_svd() -> None:
    rng = np.random.default_rng(0)
    for shape in ((32, 8), (8, 32), (16, 16)):
        m = rng.normal(size=shape)
        assert certify.power_iteration(m) == pytest.approx(certify.spectral_norm(m), rel=1e-6)


def test_verifier_is_independent_of_torch_and_the_encoder() -> None:
    tree = ast.parse(Path(certify.__file__).read_text(encoding="utf-8"))
    imported = {
        n.module if isinstance(n, ast.ImportFrom) else a.name
        for n in ast.walk(tree)
        if isinstance(n, ast.Import | ast.ImportFrom)
        for a in (n.names if isinstance(n, ast.Import) else [n])
    }
    assert not any(m and (m.startswith("torch") or m.startswith("esp")) for m in imported)
