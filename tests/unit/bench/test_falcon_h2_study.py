# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Preregistered FALCON H2 study: blinding, metric, tests and decoders on synthetic data."""

import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pytest

from esp.bench import falcon_h2_study as st

h5py = pytest.importorskip("h5py")
ROOT = Path(__file__).resolve().parents[3]


def _write(path: Path, cues: list[str], rng: np.random.Generator) -> None:
    n = 60 * len(cues)
    path.parent.mkdir(parents=True, exist_ok=True)
    with h5py.File(path, "w") as f:
        f["acquisition/binned_spikes/data"] = rng.poisson(1.0, size=(n, 8)).astype(np.float32)
        f["acquisition/binned_spikes/timestamps"] = np.arange(n) * 0.02
        f["acquisition/eval_mask/data"] = np.ones(n, bool)
        f["intervals/trials/start_time"] = np.arange(len(cues)) * 1.2
        f["intervals/trials/stop_time"] = np.arange(len(cues)) * 1.2 + 1.19
        f["intervals/trials/cue"] = np.array(cues, dtype=object).astype("S")


@pytest.fixture
def fake_h2(tmp_path: Path) -> Path:
    rng = np.random.default_rng(0)
    for split, day in (
        ("held-in-calib", "20220101"),
        ("held-in-minival", "20220101"),
        ("held-out-calib", "20220301"),
    ):
        _write(
            tmp_path / f"sub-T5-{split}" / f"sub-T5-{split}_ses-{day}.nwb", ["ab", "ba", "aa"], rng
        )
    return tmp_path


def test_loading_is_blinded_by_default(fake_h2: Path) -> None:
    sessions = st.load(fake_h2)
    assert all(t.cue is None for s in sessions for t in s.trials)
    summary = json.dumps(st.dry_run(fake_h2))
    assert "ab" not in summary
    assert "ba" not in summary
    assert st.dry_run(fake_h2)["held-out-calib"]["trials"] == 3
    unblinded = st.load(fake_h2, unblind=True)
    assert [t.cue for t in unblinded[0].trials] == ["ab", "ba", "aa"]


def test_analysis_refuses_blinded_data(fake_h2: Path) -> None:
    with pytest.raises(RuntimeError, match="unblinded"):
        st.analyse(st.load(fake_h2))


def test_normalisation_uses_only_neural_data(fake_h2: Path) -> None:
    blind = st.normalise(st.load(fake_h2))
    unblind = st.normalise(st.load(fake_h2, unblind=True))
    for k in blind:
        for a, b in zip(blind[k], unblind[k], strict=True):
            np.testing.assert_array_equal(a, b)


def test_levenshtein_and_cer() -> None:
    assert st.levenshtein("kitten", "sitting") == 3
    assert st.corpus_cer(["abc", ""], ["abc", "de"]) == pytest.approx(2 / 5)


def test_permutation_test_detects_trial_specific_predictions() -> None:
    targets = ["the cat sat", "a dog ran", "birds fly high", "fish swim"]
    good = [(targets, targets)]
    obs, null, p = st.permutation_test(good + good, n_perm=2000)
    assert obs == 0.0
    assert null > 0.5
    assert p < 0.01
    bad = [(["x" * 5] * 4, targets)]
    _, _, p_bad = st.permutation_test(bad, n_perm=500)
    assert p_bad > 0.5


def test_holm() -> None:
    assert st.holm({"a": 0.01, "b": 0.04, "c": 0.03}) == {"a": True, "b": False, "c": False}
    assert st.holm({"a": 0.01, "b": 0.02}) == {"a": True, "b": True}


def test_greedy_ctc_collapses_repeats_and_blanks() -> None:
    lp = np.log(
        np.array(
            [[0.1, 0.8, 0.1], [0.1, 0.8, 0.1], [0.8, 0.1, 0.1], [0.1, 0.8, 0.1], [0.1, 0.1, 0.8]]
        )
    )
    assert st.greedy(lp, "ab") == "aab"


def test_ctc_decoder_trains_on_a_toy_problem(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("torch")
    monkeypatch.setenv("ESP_DEVICE", "cpu")
    rng = np.random.default_rng(1)
    proto = {"a": rng.normal(size=4), "b": rng.normal(size=4)}

    def sample(word: str) -> np.ndarray:
        rows = [np.zeros(4)] * 4
        for c in word:
            rows += [proto[c]] * 6 + [np.zeros(4)] * 4
        return np.array(rows) + 0.05 * rng.normal(size=(len(rows), 4))

    words = ["ab", "ba", "aab", "bba", "abab", "b", "a"] * 6
    xs = [sample(w) for w in words]
    cfg = st.CtcConfig(
        hidden=32,
        layers=1,
        dropout=0.0,
        max_epochs=60,
        patience=60,
        batch=8,
        noise_sd=0.0,
        offset_sd=0.0,
    )
    dec = st.CtcDecoder(4, "ab", cfg, seed=0).fit(xs, words, xs[:7], words[:7])
    assert st.corpus_cer(dec.decode_all(xs[:7]), words[:7]) < 0.4


def test_runner_refuses_unblinding_without_a_published_preregistration() -> None:
    out = subprocess.run(
        [
            sys.executable,
            "scripts/run_falcon_h2_study.py",
            "--unblind",
            "--prereg-commit",
            "0" * 40,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode != 0
    assert "refusing to unblind" in out.stderr


def test_committed_preregistration_matches_the_analysis_parameters() -> None:
    sys.path.insert(0, str(ROOT / "scripts"))
    import run_falcon_h2_study as runner  # noqa: PLC0415

    body = json.loads((ROOT / "research" / "prereg" / "falcon-h2.json").read_text(encoding="utf-8"))
    assert body["digest"] == runner.preregistration().digest()
    assert body["preregistration"]["hypothesis"] == "L4"
