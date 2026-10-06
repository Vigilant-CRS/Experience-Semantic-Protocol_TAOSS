# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Preregistered FALCON H2 study: attempted handwriting from human intracortical arrays.

Analysis code of the preregistration ``research/prereg/falcon-h2.json`` and
``docs/research/prereg-falcon-h2.md``. **Blinded:** the handwriting cues (labels)
are only read by :func:`load` with ``unblind=True``. That requires a preregistration
committed and published *before* the run (see ``scripts/run_falcon_h2_study.py``).

The pipeline is fixed before unblinding:

- **features:** ``sqrt`` of the 20 ms binned spike counts, causal exponential
  smoothing (``TAU_BINS``), then per-day z-scoring with statistics from unlabelled
  data only (never labels):
  - held-in days use all neural data of their calib session;
  - a held-out session uses its own complete neural recording. This is declared
    transductive, unsupervised adaptation: the released held-out sessions contain only
    3 trials each, so no separate calibration block exists.
- **decoders:**
  - **GRU+CTC:** 2 layers, hidden 256, 2x temporal downsampling, greedy CTC decoding,
    ensemble of seeds 0, 1 and 2 (averaged log-probabilities);
  - **linear+CTC:** the same, with a per-step linear read-out instead of the GRU.
- **alphabet:** the characters in the held-in calib cues (plus the CTC blank).
  Characters outside it can never be produced and count as errors.
- **metric:** corpus character error rate: total Levenshtein distance divided by
  total target characters, over a set of trials.
- **null:** within each session, predictions are permuted across that session's
  test trials (10 000 permutations, seed 0). The p-value is
  ``(1 + #{null CER ≤ observed}) / (1 + N)``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import numpy as np
from numpy.typing import NDArray

from esp.bench.neural_decoders import (
    F64,
    DayStats,
    hardware_record,
    preprocess,
    set_deterministic,
)

TAU_BINS = 2.0
VAL_TRIALS = 3
"""Last trials of each held-in calib session used for early stopping."""
MIN_TRIAL_S = 1.0
N_PERM = 10_000
SEEDS = (0, 1, 2)
SPLITS = ("held-in-calib", "held-in-minival", "held-out-calib")


@dataclass(frozen=True, slots=True)
class Trial:
    session: str
    day: str
    split: str
    index: int
    x: F64
    """Preprocessed, not yet normalised features (bins x channels)."""
    cue: str | None = None
    """``None`` while blinded."""


@dataclass
class SessionData:
    name: str
    day: str
    split: str
    features: F64
    trials: list[Trial] = field(default_factory=list)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while chunk := f.read(1 << 22):
            h.update(chunk)
    return h.hexdigest()


def verify_pins(root: Path, registry: Path) -> None:
    """Every analysed file must match its pinned SHA-256 (``datasets/neural.json``)."""
    reg = json.loads(registry.read_text(encoding="utf-8"))
    pins = next(d for d in reg["datasets"] if d["id"] == "falcon-h2")["files"]
    for rel, entry in pins.items():
        p = root / rel
        if not p.exists() or p.stat().st_size != entry["size"] or _sha256(p) != entry["sha256"]:
            msg = f"file does not match its pin: {rel}"
            raise RuntimeError(msg)


def load(root: Path, *, unblind: bool = False) -> list[SessionData]:
    """Load all sessions. Cues are read only when ``unblind`` is true."""
    import h5py  # noqa: PLC0415 - optional dependency (neural extra)

    out = []
    for split in SPLITS:
        for p in sorted((root / f"sub-T5-{split}").glob("*.nwb")):
            with h5py.File(p, "r") as f:
                counts = np.asarray(f["acquisition/binned_spikes/data"], dtype=np.float64)
                ts = np.asarray(f["acquisition/binned_spikes/timestamps"], dtype=np.float64)
                tr = f["intervals/trials"]
                starts = np.asarray(tr["start_time"], dtype=np.float64)
                stops = np.asarray(tr["stop_time"], dtype=np.float64)
                cues = (
                    [c.decode() if isinstance(c, bytes) else str(c) for c in tr["cue"][:]]
                    if unblind
                    else None
                )
            x = preprocess(counts, sqrt=True, tau_bins=TAU_BINS)
            day = p.stem.split("_ses-")[1][:8]
            sd = SessionData(p.stem, day, split, x)
            for i, (a, b) in enumerate(zip(starts, stops, strict=True)):
                if b - a < MIN_TRIAL_S:
                    continue  # exclusion rule fixed in the preregistration
                sel = (ts >= a) & (ts < b)
                cue = cues[i] if cues is not None else None
                if cue is not None and not cue.strip():
                    continue  # exclusion rule: empty cue
                sd.trials.append(Trial(p.stem, day, split, i, x[sel], cue))
            out.append(sd)
    return out


def dry_run(root: Path) -> dict[str, Any]:
    """Blinded check: sessions, trial counts and shapes only; never any label content."""
    sessions = load(root, unblind=False)
    return {
        split: {
            "sessions": sum(1 for s in sessions if s.split == split),
            "days": len({s.day for s in sessions if s.split == split}),
            "trials": sum(len(s.trials) for s in sessions if s.split == split),
            "channels": sorted({s.features.shape[1] for s in sessions if s.split == split}),
        }
        for split in SPLITS
    }


def normalise(sessions: list[SessionData]) -> dict[str, list[F64]]:
    """Per-day z-scoring from unlabelled neural data (see module doc)."""
    day_stats = {}
    for day in {s.day for s in sessions if s.split == "held-in-calib"}:
        day_stats[day] = DayStats.of(
            np.concatenate(
                [s.features for s in sessions if s.split == "held-in-calib" and s.day == day]
            )
        )
    out = {}
    for s in sessions:
        if s.split == "held-out-calib":
            st = DayStats.of(s.features)  # unlabelled, whole session (transductive)
        else:
            st = day_stats.get(s.day) or DayStats.of(s.features)
        out[s.name] = [st.apply(t.x) for t in s.trials]
    return out


# --- metric and test -----------------------------------------------------------------------------


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def corpus_cer(preds: list[str], targets: list[str]) -> float:
    total = sum(len(t) for t in targets)
    return sum(levenshtein(p, t) for p, t in zip(preds, targets, strict=True)) / max(total, 1)


def permutation_test(
    groups: list[tuple[list[str], list[str]]], n_perm: int = N_PERM, seed: int = 0
) -> tuple[float, float, float]:
    """Observed corpus CER, mean null CER and p-value (predictions permuted within groups)."""
    rng = np.random.default_rng(seed)
    preds = [p for g in groups for p in g[0]]
    targets = [t for g in groups for t in g[1]]
    obs = corpus_cer(preds, targets)
    total = sum(len(t) for t in targets)
    # distance matrix per group makes each permutation cheap
    mats = [
        np.array([[levenshtein(p, t) for t in tg] for p in pg], dtype=np.int64) for pg, tg in groups
    ]
    le = 0
    null_sum = 0.0
    for _ in range(n_perm):
        d = 0
        for m in mats:
            perm = rng.permutation(len(m))
            d += int(m[perm, np.arange(len(m))].sum())
        cer = d / max(total, 1)
        null_sum += cer
        le += cer <= obs
    return obs, null_sum / n_perm, (1 + le) / (1 + n_perm)


def wilcoxon_one_sided(a: NDArray[np.float64], b: NDArray[np.float64]) -> float:
    """p for 'a < b' (paired per trial), scipy's exact/normal Wilcoxon signed-rank."""
    from scipy.stats import wilcoxon  # type: ignore[import-untyped]  # noqa: PLC0415

    if np.allclose(a, b):
        return 1.0
    return float(wilcoxon(a, b, alternative="less").pvalue)


def holm(p: dict[str, float], alpha: float = 0.05) -> dict[str, bool]:
    order = sorted(p, key=lambda k: p[k])
    out, m = {}, len(p)
    stop = False
    for rank, k in enumerate(order):
        ok = not stop and p[k] <= alpha / (m - rank)
        stop = stop or not ok
        out[k] = ok
    return out


# --- CTC decoders --------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class CtcConfig:
    kind: str = "gru"  # "gru" or "linear"
    hidden: int = 256
    layers: int = 2
    dropout: float = 0.3
    downsample: int = 2
    lr: float = 1e-3
    weight_decay: float = 1e-4
    batch: int = 16
    max_epochs: int = 150
    patience: int = 15
    noise_sd: float = 0.1
    offset_sd: float = 0.05


class CtcDecoder:
    def __init__(self, n_in: int, alphabet: str, cfg: CtcConfig, seed: int) -> None:
        import torch  # noqa: PLC0415
        from torch import nn  # noqa: PLC0415

        from esp.bench.neural_decoders import device_name  # noqa: PLC0415

        set_deterministic(seed)
        self.alphabet, self.cfg, self.seed = alphabet, cfg, seed
        self.dev = torch.device(device_name())
        n_out = len(alphabet) + 1  # index 0 = blank
        d_in = n_in * cfg.downsample

        class Net(nn.Module):
            def __init__(self) -> None:
                super().__init__()
                if cfg.kind == "gru":
                    self.core: nn.Module = nn.GRU(
                        d_in,
                        cfg.hidden,
                        num_layers=cfg.layers,
                        batch_first=True,
                        dropout=cfg.dropout,
                    )
                    self.out = nn.Linear(cfg.hidden, n_out)
                else:
                    self.core = nn.Identity()
                    self.out = nn.Linear(d_in, n_out)
                self.drop = nn.Dropout(cfg.dropout)

            def forward(self, x: torch.Tensor) -> torch.Tensor:
                h = self.core(x)
                if isinstance(h, tuple):
                    h = h[0]
                return torch.log_softmax(self.out(self.drop(h)), dim=-1)

        self.net = Net().to(self.dev)

    def _down(self, x: F64) -> F64:
        k = self.cfg.downsample
        n = (len(x) // k) * k
        out: F64 = x[:n].reshape(n // k, k * x.shape[1])
        return out

    def _encode(self, s: str) -> list[int]:
        return [self.alphabet.index(c) + 1 for c in s if c in self.alphabet]

    def fit(self, xs: list[F64], ys: list[str], val_x: list[F64], val_y: list[str]) -> CtcDecoder:
        import torch  # noqa: PLC0415

        cfg = self.cfg
        opt = torch.optim.AdamW(self.net.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)
        ctc = torch.nn.CTCLoss(blank=0, zero_infinity=True)
        gen = np.random.default_rng(self.seed)
        data = [(self._down(x), self._encode(y)) for x, y in zip(xs, ys, strict=True)]
        best, best_state, bad = float("inf"), None, 0
        for _epoch in range(cfg.max_epochs):
            self.net.train()
            order = gen.permutation(len(data))
            for i in range(0, len(order), cfg.batch):
                batch = [data[j] for j in order[i : i + cfg.batch]]
                t_max = max(len(b[0]) for b in batch)
                xb = np.zeros((len(batch), t_max, batch[0][0].shape[1]), dtype=np.float32)
                for j, (x, _) in enumerate(batch):
                    noise = gen.normal(0, cfg.noise_sd, x.shape) + gen.normal(
                        0, cfg.offset_sd, (1, x.shape[1])
                    )
                    xb[j, : len(x)] = x + noise
                lp = self.net(torch.tensor(xb, device=self.dev)).transpose(0, 1)
                targets = torch.tensor([c for _, y in batch for c in y], dtype=torch.long)
                loss = ctc(
                    lp.float().cpu() if self.dev.type == "cuda" else lp,
                    targets,
                    torch.tensor([len(x) for x, _ in batch], dtype=torch.long),
                    torch.tensor([len(y) for _, y in batch], dtype=torch.long),
                )
                opt.zero_grad()
                loss.backward()
                torch.nn.utils.clip_grad_norm_(self.net.parameters(), 1.0)
                opt.step()
            v = corpus_cer(self.decode_all(val_x), val_y)
            if v < best - 1e-4:
                best, bad = v, 0
                best_state = {k: t.detach().clone() for k, t in self.net.state_dict().items()}
            else:
                bad += 1
                if bad >= cfg.patience:
                    break
        if best_state is not None:
            self.net.load_state_dict(best_state)
        return self

    def log_probs(self, x: F64) -> F64:
        import torch  # noqa: PLC0415

        self.net.eval()
        with torch.no_grad():
            lp = self.net(torch.tensor(self._down(x)[None], dtype=torch.float32, device=self.dev))[
                0
            ]
        out: F64 = lp.cpu().numpy().astype(np.float64)
        return out

    def decode_all(self, xs: list[F64]) -> list[str]:
        return [greedy(self.log_probs(x), self.alphabet) for x in xs]


def greedy(log_probs: F64, alphabet: str) -> str:
    best = log_probs.argmax(axis=1)
    out, prev = [], -1
    for k in best:
        if k not in (prev, 0):
            out.append(alphabet[k - 1])
        prev = int(k)
    return "".join(out)


def ensemble_decode(models: list[CtcDecoder], x: F64) -> str:
    lp = np.mean([m.log_probs(x) for m in models], axis=0)
    return greedy(lp, models[0].alphabet)


# --- the preregistered analysis ------------------------------------------------------------------


def analyse(  # noqa: PLR0915 - the preregistered analysis, kept in one readable block
    sessions: list[SessionData], *, cfg_gru: CtcConfig | None = None
) -> dict[str, Any]:
    """Run every preregistered comparison. Requires unblinded sessions."""
    if any(t.cue is None for s in sessions for t in s.trials):
        msg = "analysis requires unblinded data"
        raise RuntimeError(msg)
    z_norm = normalise(sessions)
    z_raw = {s.name: [t.x for t in s.trials] for s in sessions}
    calib = [s for s in sessions if s.split == "held-in-calib"]
    alphabet = "".join(sorted({c for s in calib for t in s.trials for c in (t.cue or "")}))

    def train(z: dict[str, list[F64]], cfg: CtcConfig) -> list[CtcDecoder]:
        xs: list[F64] = []
        vx: list[F64] = []
        ys: list[str] = []
        vy: list[str] = []
        for s in calib:
            for i, t in enumerate(s.trials):
                (vx if i >= len(s.trials) - VAL_TRIALS else xs).append(z[s.name][i])
                (vy if i >= len(s.trials) - VAL_TRIALS else ys).append(t.cue or "")
        n_in = xs[0].shape[1]
        return [CtcDecoder(n_in, alphabet, cfg, seed).fit(xs, ys, vx, vy) for seed in SEEDS]

    gru_cfg = cfg_gru or CtcConfig()
    models = {
        "gru_daynorm": (train(z_norm, gru_cfg), z_norm),
        "gru_raw": (train(z_raw, gru_cfg), z_raw),
        "linear_daynorm": (train(z_norm, CtcConfig(kind="linear")), z_norm),
    }

    def test_trials(split: str) -> list[tuple[SessionData, list[int]]]:
        out = []
        for s in sessions:
            if s.split != split:
                continue
            out.append((s, list(range(len(s.trials)))))
        return out

    def predict(name: str, split: str, shuffle: bool = False) -> list[tuple[list[str], list[str]]]:
        ms, z = models[name]
        rng = np.random.default_rng(0)
        groups = []
        for s, idx in test_trials(split):
            preds, targ = [], []
            for i in idx:
                x = z[s.name][i]
                if shuffle:
                    x = x[rng.permutation(len(x))]
                preds.append(ensemble_decode(ms, x))
                targ.append(s.trials[i].cue or "")
            groups.append((preds, targ))
        return groups

    res: dict[str, Any] = {"alphabet_size": len(alphabet)}
    ho = predict("gru_daynorm", "held-out-calib")
    obs, null, p = permutation_test(ho)
    res["P1_heldout_gru_daynorm"] = {"cer": obs, "null_cer": null, "p": p}
    wi = predict("gru_daynorm", "held-in-minival")
    obs_w, null_w, p_w = permutation_test(wi)
    res["S1_within_day"] = {"cer": obs_w, "null_cer": null_w, "p": p_w}

    def per_trial(groups: list[tuple[list[str], list[str]]]) -> NDArray[np.float64]:
        return np.array(
            [levenshtein(p, t) / max(len(t), 1) for g in groups for p, t in zip(*g, strict=True)]
        )

    raw = predict("gru_raw", "held-out-calib")
    res["S2_daynorm_vs_raw"] = {
        "cer_raw": corpus_cer([p for g in raw for p in g[0]], [t for g in raw for t in g[1]]),
        "p": wilcoxon_one_sided(per_trial(ho), per_trial(raw)),
    }
    lin = predict("linear_daynorm", "held-out-calib")
    res["S3_gru_vs_linear"] = {
        "cer_linear": corpus_cer([p for g in lin for p in g[0]], [t for g in lin for t in g[1]]),
        "p": wilcoxon_one_sided(per_trial(ho), per_trial(lin)),
    }
    shuf = predict("gru_daynorm", "held-out-calib", shuffle=True)
    res["control_time_shuffled_cer"] = corpus_cer(
        [p for g in shuf for p in g[0]], [t for g in shuf for t in g[1]]
    )
    secondary = {k: res[k]["p"] for k in ("S1_within_day", "S2_daynorm_vs_raw", "S3_gru_vs_linear")}
    res["holm_secondary"] = holm(secondary)
    res["primary_supported"] = bool(p < 0.05 and obs < null)
    res["hardware"] = hardware_record()
    return res
