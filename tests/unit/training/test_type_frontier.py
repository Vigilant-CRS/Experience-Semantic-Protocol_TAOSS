# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-074: TAOSS-3/-6/-8/-12 type profiles, frontier and ablations (smoke, exploratory)."""

import dataclasses
import json
import math
import sys
from pathlib import Path

import numpy as np
import pytest

torch = pytest.importorskip("torch")

from esp.codec.errors import WireError  # noqa: E402
from esp.codec.structure import TypeProfile  # noqa: E402
from esp.core.taoss_types import TAOSS6_ORDER  # noqa: E402
from esp.training import frontier  # noqa: E402
from esp.training.frontier import (  # noqa: E402
    AGGREGATES,
    CROSS,
    SIBLINGS,
    FrontierConfig,
    WorldConfig,
    leakage,
    make_world,
    pseudonym_linkage,
    sample_factors,
    train_encoder,
)
from esp.training.type_profiles import (  # noqa: E402
    ATOMS,
    PROFILES,
    SCENARIOS,
    DecompositionProfile,
)

ROOT = Path(__file__).resolve().parents[3]
SMOKE = FrontierConfig(
    steps=5, world=WorldConfig(n=256, eval_n=400), lambdas=(0.0, 1.0, 50.0), emo_degrees=(1,)
)


@pytest.fixture(scope="module")
def smoke() -> dict[str, object]:
    return frontier.run(SMOKE)


# --- profiles -------------------------------------------------------------------------------------


def test_profiles_partition_the_atoms() -> None:
    assert {p.k for p in PROFILES.values()} == {3, 6, 8, 12}
    for p in PROFILES.values():
        assert sorted(a for atoms in p.types.values() for a in atoms) == sorted(ATOMS)
    assert tuple(PROFILES["TAOSS-6"].types) == tuple(t.name for t in TAOSS6_ORDER)
    with pytest.raises(ValueError, match="partition"):
        DecompositionProfile("bad", {"A": ATOMS[:6], "B": ATOMS[5:]})


def test_type_profile_tlv_binds_the_registry_digest() -> None:
    digests = {p.digest() for p in PROFILES.values()}
    ids = {p.profile_id for p in PROFILES.values()}
    assert len(digests) == len(ids) == 4
    for p in PROFILES.values():
        tlv = p.tlv()
        assert tlv.code == 0x11  # V13 TLV_TYPE_PROFILE; no new code allocated
        decoded = TypeProfile.decode(tlv, pinned={p.profile_id: p.digest()})
        assert (decoded.type_count, decoded.registry_digest) == (p.k, p.digest())
        with pytest.raises(WireError, match="not pinned"):
            TypeProfile.decode(tlv, pinned={})
    six, eight = PROFILES["TAOSS-6"], PROFILES["TAOSS-8"]
    with pytest.raises(WireError, match="digest mismatch"):
        TypeProfile.decode(six.tlv(), pinned={six.profile_id: eight.digest()})


def test_consent_scenario_expressibility() -> None:
    v13 = [s for s in SCENARIOS if not s.startswith("finer")]
    finer = [s for s in SCENARIOS if s.startswith("finer")]
    expr = {n: {s: p.expressible(a) for s, a in SCENARIOS.items()} for n, p in PROFILES.items()}
    assert not any(expr["TAOSS-3"].values())  # three types cannot separate EMO from INT or CTX
    assert all(expr["TAOSS-6"][s] for s in v13)
    assert not any(expr["TAOSS-6"][s] for s in finer)
    assert all(expr["TAOSS-8"].values())
    assert all(expr["TAOSS-12"].values())


# --- synthetic world and metrics --------------------------------------------------------------


def test_world_has_the_planted_dependence() -> None:
    cfg = WorldConfig()
    f = sample_factors(cfg, 40_000, np.random.default_rng(0))

    def corr(a: str, b: str) -> float:
        return float(np.mean([np.corrcoef(f[a][:, i], f[b][:, i])[0, 1] for i in range(3)]))

    for a in ATOMS:
        assert np.allclose(f[a].var(0), 1.0, atol=0.03)
    for a, b in SIBLINGS:
        assert corr(a, b) == pytest.approx(cfg.sibling_rho, abs=0.02)
    for a, b in CROSS:
        assert corr(a, b) == pytest.approx(cfg.cross_rho, abs=0.02)
    assert abs(corr("KNOF", "SENV")) < 0.02
    with pytest.raises(ValueError, match="unit variance"):
        sample_factors(dataclasses.replace(cfg, sibling_rho=0.6), 10, np.random.default_rng(0))


def test_leakage_metric_separates_copies_from_independence() -> None:
    rng = np.random.default_rng(0)
    a, c = rng.normal(size=(2000, 3)), rng.normal(size=(2000, 3))
    copy = leakage({"A": a, "B": a + 0.05 * rng.normal(size=(2000, 3)), "C": c})
    independent = leakage({"A": a, "C": c})
    assert copy["max"] > 2.0
    assert copy["mean"] > copy["max"] / 6  # one coupled pair out of six directed pairs
    assert independent["max"] < 0.05


def test_pseudonyms_stop_id_linking_but_not_content_linking() -> None:
    world = make_world(WorldConfig(n=256, eval_n=100))
    model = train_encoder(
        PROFILES["TAOSS-6"], world, lambda_cov=5.0, beta_adv=0.1, steps=20, seed=0
    )
    r = pseudonym_linkage(model, world, subjects=10, frames=8, offset_scales=(0.0, 2.0))
    assert r["pseudonyms_off"]["linked_by_id"] == 1.0
    assert r["pseudonyms_on"]["linked_by_id"] == 0.0
    content = r["pseudonyms_on"]["content_accuracy_by_offset_scale"]
    assert content["0"] <= 0.4  # no subject signature: close to chance (0.1)
    assert content["2"] >= 0.9  # a strong signature links through the content


# --- the frontier run ---------------------------------------------------------------------------


def test_frontier_smoke_structure_and_labels(smoke: dict[str, object]) -> None:
    result = json.loads(json.dumps(smoke))  # JSON-serializable
    assert result["label"] == "exploratory"
    assert "NOT preregistered" in result["claims"]
    assert "no preregistration" in result["reasons"]
    profiles = result["profiles"]
    assert set(profiles) == set(PROFILES)
    for name, p in profiles.items():
        assert p["registry_digest"] == PROFILES[name].digest().hex()
        assert p["type_profile_tlv"].startswith("11")
        assert set(p["leak"]) == set(AGGREGATES)
        assert all(v >= 0 for v in p["leak"].values())
        assert -1.0 < p["utility"] < 1.0
    rows = result["frontier"]
    assert len(rows) == len(AGGREGATES) * len(SMOKE.lambdas)
    for row in rows:
        for name, score in row["scores"].items():
            p = profiles[name]
            assert score == pytest.approx(
                p["utility"] - row["lambda_p"] * p["leak"][row["aggregate"]]
            )
        assert row["scores"][row["best"]] == max(row["scores"].values())
    zero = next(r for r in rows if r["lambda_p"] == 0.0)
    assert zero["best"] == max(profiles, key=lambda n: profiles[n]["utility"])
    ab = result["ablations"]
    assert set(ab["regularization"]) == {"both", "cov_only", "adv_only", "neither"}
    assert ab["regularization"]["cov_only"]["beta_adv"] == 0.0
    assert ab["regularization"]["adv_only"]["lambda_cov"] == 0.0
    assert set(ab["emo_default_masked"]) == set(ab["regularization"])
    assert set(ab["emo_inherent"]) == {
        "inherent_emo_leak_bits_per_dim",
        "emo_target_r2_from_visible_targets",
    }
    assert {"d_model=32", "d_model=48", "d_model=96"} <= set(ab["rank_bottleneck"])
    assert ab["pseudonyms"]["pseudonyms_on"]["linked_by_id"] == 0.0


def test_frontier_is_deterministic(smoke: dict[str, object]) -> None:
    assert frontier.run(SMOKE) == smoke


def test_large_lambda_picks_the_least_leaky_profile(smoke: dict[str, object]) -> None:
    profiles = smoke["profiles"]
    assert isinstance(profiles, dict)
    for row in smoke["frontier"]:  # type: ignore[attr-defined]
        if row["lambda_p"] == 50.0:
            agg = row["aggregate"]
            assert row["best"] == min(profiles, key=lambda n: profiles[n]["leak"][agg])


def test_script_writes_labelled_json(tmp_path: Path) -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    try:
        import run_type_frontier  # noqa: PLC0415
    finally:
        sys.path.pop(0)
    out = tmp_path / "frontier.json"
    args = ["--steps", "3", "--n", "200", "--eval-n", "300", "--emo-degrees", "1"]
    args += ["--out", str(out)]
    assert run_type_frontier.main(args) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["label"] == "exploratory"
    assert data["config"]["steps"] == 3
    assert math.isfinite(data["runtime_s"])
    assert "exploratory" in run_type_frontier.table(data)
