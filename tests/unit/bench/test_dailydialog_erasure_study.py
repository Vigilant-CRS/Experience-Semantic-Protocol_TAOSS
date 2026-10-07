# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""DailyDialog erasure study: loader, blinding, topics, clusters, variants (synthetic data)."""

from pathlib import Path

import numpy as np
import pytest

from esp.bench.dailydialog_erasure_study import cluster_bootstrap, labels, load, one_hot
from esp.bench.erasure_methods import leace_pair, variants


def _write(root: Path) -> None:
    b = root / "ijcnlp_dailydialog"
    dialogs = {
        "train": ["Hi . __eou__ Hello ! __eou__", "Bye . __eou__ See you . __eou__"],
        "validation": ["Hi . __eou__ Hello ! __eou__"],  # same text as a train dialog
        "test": ["Fine . __eou__ Good . __eou__ Great ! __eou__"],
    }
    acts = {"train": ["1 2", "3 4"], "validation": ["1 2"], "test": ["1 1 2"]}
    emos = {"train": ["0 4", "5 0"], "validation": ["0 4"], "test": ["4 4 6"]}
    for s, lines in dialogs.items():
        (b / s).mkdir(parents=True)
        (b / s / f"dialogues_{s}.txt").write_text("\n".join(lines) + "\n")
        (b / s / f"dialogues_act_{s}.txt").write_text("\n".join(acts[s]) + "\n")
        (b / s / f"dialogues_emotion_{s}.txt").write_text("\n".join(emos[s]) + "\n")
    full = ["Hi . __eou__ Hello ! __eou__", "Bye . __eou__ See you . __eou__"]
    full += ["Fine . __eou__ Good . __eou__ Great ! __eou__", "Bye . __eou__ See you . __eou__"]
    (b / "dialogues_text.txt").write_text("\n".join(full) + "\n")
    (b / "dialogues_topic.txt").write_text("1\n2\n7\n9\n")  # the "Bye" dialog is ambiguous


def test_test_split_is_blinded_until_unblind(tmp_path: Path) -> None:
    _write(tmp_path)
    blinded = load(tmp_path)
    assert blinded["test"].emo is None
    with pytest.raises(RuntimeError, match="blinded"):
        labels(blinded["test"])
    emo, act, topic = labels(load(tmp_path, unblind=True)["test"])
    assert emo.tolist() == [4, 4, 6]
    assert act.tolist() == [0, 0, 1]
    assert topic.tolist() == [6, 6, 6]


def test_topics_by_exact_dialog_text_and_ambiguity(tmp_path: Path) -> None:
    _write(tmp_path)
    tr = load(tmp_path)["train"]
    assert labels(tr)[2].tolist() == [0, 0, -1, -1]  # conflicting topics -> -1
    assert tr.dialog.tolist() == [0, 0, 1, 1]


def test_overlap_with_train_flagged_from_text_alone(tmp_path: Path) -> None:
    _write(tmp_path)
    data = load(tmp_path)
    assert data["validation"].seen_in_train.all()
    assert not data["test"].seen_in_train.any()


def test_cluster_bootstrap_resamples_whole_dialogs() -> None:
    clusters = np.array([0, 0, 0, 1, 2, 2])
    sizes = cluster_bootstrap(lambda i: float(len(i)), clusters, n_boot=200, seed=0)
    assert set(np.unique(sizes)) <= {3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0}
    first = cluster_bootstrap(lambda i: float(i.min()), clusters, n_boot=50, seed=1)
    assert (
        first.tolist()
        == cluster_bootstrap(lambda i: float(i.min()), clusters, n_boot=50, seed=1).tolist()
    )


def test_erasure_variants_never_fit_on_evaluation_rows() -> None:
    rng = np.random.default_rng(0)
    r_tr, r_ev = rng.normal(size=(400, 6)), rng.normal(size=(100, 6))
    concept = one_hot(rng.integers(0, 3, 400), 3)
    (a_tr, _), e1 = leace_pair(r_tr, r_ev, concept, training_data_id="t")
    (b_tr, _), e2 = leace_pair(r_tr, r_ev + 100.0, concept, training_data_id="t")
    assert e1.digest == e2.digest  # evaluation rows do not influence the eraser
    np.testing.assert_allclose(a_tr, b_tr)
    out = variants(
        (r_tr, r_ev),
        (r_tr, r_ev),
        (r_tr, r_ev),
        concept,
        np.zeros(400, np.int64),
        seed=0,
        training_data_id="t",
        names=("taoss", "mono_leace"),
    )
    assert set(out) == {"taoss", "mono_leace"}
    np.testing.assert_allclose(out["taoss"][1], r_ev)
