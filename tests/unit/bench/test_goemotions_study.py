# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""GoEmotions H2 study code: metrics, blinding, comparison and the method pipeline (synthetic)."""

import csv
import itertools
from pathlib import Path

import numpy as np
import pytest

from esp.bench.goemotions_study import (
    N_EMO,
    EncoderConfig,
    ProbeConfig,
    Released,
    SplitData,
    auroc,
    compare,
    holm,
    labels,
    load,
    macro_auroc,
    run_methods,
    summarize,
)


def _pairs_auroc(y: np.ndarray, s: np.ndarray) -> float:
    pos, neg = s[y > 0.5], s[y <= 0.5]
    wins = sum(1.0 if a > b else 0.5 if a == b else 0.0 for a, b in itertools.product(pos, neg))
    return wins / (len(pos) * len(neg))


def test_auroc_matches_pairwise_definition_with_ties() -> None:
    rng = np.random.default_rng(0)
    y = (rng.random(60) > 0.6).astype(float)
    s = np.round(rng.random(60), 1)  # many ties
    assert auroc(y, s) == pytest.approx(_pairs_auroc(y, s))
    assert np.isnan(auroc(np.zeros(5), np.arange(5.0)))
    assert auroc(np.array([0, 0, 1, 1.0]), np.array([0.1, 0.2, 0.8, 0.9])) == 1.0


def test_holm_step_down() -> None:
    assert holm({"a": 0.01, "b": 0.04, "c": 0.02}) == {"a": True, "b": True, "c": True}
    assert holm({"a": 0.01, "b": 0.04, "c": 0.03}) == {"a": True, "b": False, "c": False}
    assert holm({"a": 0.01, "b": 0.2, "c": 0.03}) == {"a": True, "b": False, "c": False}


def _fixture(root: Path) -> None:
    root.mkdir()
    rows = [
        # id, author, subreddit, link_id
        ("a1", "u1", "r/x", "t1"),
        ("a2", "u2", "r/y", "t2"),
        ("b1", "u1", "r/x", "t9"),  # dev: author seen in train
        ("b2", "u7", "r/z", "t8"),  # dev: unseen author and thread, unseen subreddit
        ("c1", "u8", "r/y", "t7"),  # test: unseen author and thread
    ]
    for i in (1, 2, 3):
        with (root / f"goemotions_{i}.csv").open("w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["text", "id", "author", "subreddit", "link_id"])
            if i == 1:
                for r in rows:
                    w.writerow(["t", r[0], r[1], r[2], r[3]])
    (root / "train.tsv").write_text("hi\t0,27\ta1\nho\t3\ta2\n", encoding="utf-8")
    (root / "dev.tsv").write_text("he\t5\tb1\nha\t27\tb2\n", encoding="utf-8")
    (root / "test.tsv").write_text("hu\t1\tc1\n", encoding="utf-8")


def test_test_labels_stay_blinded_until_unblind(tmp_path: Path) -> None:
    _fixture(tmp_path / "ge")
    data = load(tmp_path / "ge")
    assert data["test"].emo is None
    assert data["test"].ctx is None
    with pytest.raises(RuntimeError, match="blinded"):
        labels(data["test"])
    emo, ctx = labels(data["train"])
    assert emo.shape == (2, N_EMO)
    assert emo[0, [0, 27]].tolist() == [1.0, 1.0]
    assert ctx.tolist() == [0, 1]  # vocabulary from train subreddits, sorted
    _, dev_ctx = labels(data["dev"])
    assert dev_ctx.tolist() == [0, -1]  # r/z is not a train subreddit
    assert data["dev"].unseen_author_thread.tolist() == [False, True]
    unblinded = load(tmp_path / "ge", unblind=True)
    assert labels(unblinded["test"])[1].tolist() == [1]
    assert unblinded["test"].unseen_author_thread.tolist() == [True]


def _released(score_emo: np.ndarray, score_ctx: np.ndarray) -> Released:
    return Released(score_emo, score_emo, score_ctx, score_ctx, 0.0)


def test_compare_detects_less_leakage_and_checks_utility() -> None:
    rng = np.random.default_rng(1)
    n = 400
    emo = (rng.random((n, 3)) > 0.5).astype(float)
    ctx = rng.integers(0, 4, n)
    onehot = np.eye(4)[ctx]
    leaky = _released(emo + 0.3 * rng.normal(size=emo.shape), onehot)
    clean = _released(rng.normal(size=emo.shape), onehot)
    res = compare(clean, leaky, emo, ctx, n_boot=500)
    assert res["leak_taoss"] < 0.6 < res["leak_base"]
    assert res["p_leak"] < 0.01
    assert res["noninferior"]
    worse = _released(rng.normal(size=emo.shape), np.eye(4)[(ctx + 1) % 4])
    assert not compare(worse, leaky, emo, ctx, n_boot=500)["noninferior"]
    same = compare(leaky, leaky, emo, ctx, n_boot=500)
    assert same["p_leak"] > 0.5


def test_summarize_uses_the_strongest_probe() -> None:
    emo = np.array([[1.0, 0], [0, 1], [1, 0], [0, 1]])
    ctx = np.array([0, 1, 0, 1])
    good, bad = emo.copy(), emo[::-1].copy()
    r = Released(bad, good, np.eye(2)[ctx], np.eye(2)[1 - ctx], 0.5)
    s = summarize(r, emo, ctx)
    assert s["leak_auroc"] == 1.0
    assert s["ctx_acc"] == 1.0
    assert macro_auroc(emo, bad) == 0.0


def test_pipeline_runs_and_adversary_reduces_leakage_on_planted_data() -> None:
    """Tiny synthetic world: the embedding mixes topic, community and emotion."""
    rng = np.random.default_rng(2)
    n_tr, n_ev, d = 600, 300, 24
    n = n_tr + n_ev
    emo = (rng.random((n, N_EMO)) > 0.85).astype(float)
    ctx = rng.integers(0, 3, n)
    topic = rng.normal(size=(n, 6))
    x = (
        topic @ rng.normal(size=(6, d))
        + emo @ rng.normal(size=(N_EMO, d)) * 0.5
        + np.eye(3)[ctx] @ rng.normal(size=(3, d))
    )
    x /= np.linalg.norm(x, axis=1, keepdims=True)
    unseen = np.zeros(n, dtype=bool)
    tr = SplitData("train", (), (), unseen[:n_tr], emo[:n_tr], ctx[:n_tr])
    ev = SplitData("dev", (), (), unseen[n_tr:], emo[n_tr:], ctx[n_tr:])
    cfg = EncoderConfig(hidden=32, d_kno=8, d_ctx=4, d_emo=4, epochs=40, batch=128, lam_adv=3.0)
    res = run_methods(
        tr,
        ev,
        x[:n_tr],
        x[n_tr:],
        3,
        enc_cfg=cfg,
        probe_cfg=ProbeConfig(epochs=15, batch=128, hidden=32),
        seeds=(0,),
        methods=("taoss", "raw"),
    )
    s_t = summarize(res["taoss"], emo[n_tr:], ctx[n_tr:])
    s_r = summarize(res["raw"], emo[n_tr:], ctx[n_tr:])
    assert res["taoss"].emo_lin.shape == (n_ev, N_EMO)
    assert s_t["leak_auroc"] < s_r["leak_auroc"]  # the released typed parts leak less EMO
    assert s_t["ctx_acc"] > 0.5  # but keep the community
