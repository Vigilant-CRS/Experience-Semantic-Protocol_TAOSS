# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Preregistered H2 leakage study on GoEmotions (real, openly licensed text).

V13 hypothesis H2: *typed decomposition reduces cross-type leakage versus baselines at
comparable utility.* This module is the analysis code of
``research/prereg/goemotions-h2.json`` and ``docs/research/prereg-goemotions-h2.md``.
**Blinded:** the labels of the official *test* split (emotions and subreddit) are read
only with ``unblind=True``, which the script allows only after the preregistration is
public on ``origin/main``.

Typed mapping (stated honestly):

- **EMO:** the 27 emotion categories plus neutral, annotated by raters *about the text*.
  This is content-side affect (``affect_scope = CONTENT``), not an inference about the
  writer.
- **CTX:** the subreddit, i.e. the community and situation the comment was posted in
  (483 classes).
- **KNO:** the general semantic content of the comment, operationalised as the frozen
  sentence embedding the typed encoder must reconstruct. The embedding also carries
  emotion; that tension is exactly what H2 is about.

Pipeline, fixed before unblinding:

1. ``x`` = L2-normalised ``all-MiniLM-L6-v2`` embedding (pinned revision), computed frozen.
2. Encoders (MLP 384 → 256 → 112, GELU), trained on the official *train* split:
   - **TAOSS:** blocks KNO (64) | CTX (32) | EMO (16). The EMO head reads only the EMO
     block, the CTX head only the CTX block, and the KNO decoder only the KNO block. A
     covariance penalty is applied between released and EMO blocks, and an adversary
     reads the released blocks through gradient reversal.
   - **monolithic:** the same network and heads, but every head reads the full latent and
     there are no penalties. Masking drops the post-hoc EMO partition (the last 16 dims).
3. **Released representation** when EMO is masked:
   - TAOSS: KNO‖CTX;
   - monolithic: the first 96 dims;
   - LEACE: monolithic released, with the emotion concept erased (fit on train);
   - learned filter: monolithic released through ``esp.bench.filter.learned_filter``
     (fit on train);
   - raw: ``x`` itself (descriptive only).
4. **Leakage:** probes trained on *train* released representations predict the 28-dim
   emotion multi-hot; a linear (one-vs-rest logistic) and an MLP (one hidden layer, 256)
   probe. Score = the strongest probe's macro-AUROC on the evaluation split (chance 0.5).
   Per-item probe scores are averaged over the encoder seeds.
5. **Utility:** subreddit accuracy of the strongest probe (linear or MLP) on the
   evaluation split. Content fidelity (ridge R² of ``x`` from the released
   representation) is reported, not tested.
6. **Tests:** paired bootstrap over evaluation items (10 000 resamples, seed 0).
   - Leakage: one-sided ``p = (1 + #{AUROC_base - AUROC_taoss ≤ 0}) / (1 + B)``.
   - Utility non-inferiority: the 5 % bootstrap quantile of ``acc_taoss - acc_base`` must
     exceed ``-DELTA``.
"""

from __future__ import annotations

import csv
import hashlib
import json
import os
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import numpy as np
from numpy.typing import NDArray

F64 = NDArray[np.float64]
I64 = NDArray[np.int64]
BOOL = NDArray[np.bool_]

MODEL = "sentence-transformers/all-MiniLM-L6-v2"
MODEL_REVISION = "1110a243fdf4706b3f48f1d95db1a4f5529b4d41"
SPLITS = ("train", "dev", "test")
N_EMO = 28
DELTA = 0.02
"""Utility non-inferiority margin (absolute subreddit accuracy)."""
N_BOOT = 10_000
SEEDS = (0, 1, 2)


@dataclass(frozen=True, slots=True)
class EncoderConfig:
    hidden: int = 256
    d_kno: int = 64
    d_ctx: int = 32
    d_emo: int = 16
    lam_cov: float = 1.0
    lam_adv: float = 1.0
    epochs: int = 30
    batch: int = 512
    lr: float = 1e-3
    weight_decay: float = 1e-4

    @property
    def d_released(self) -> int:
        return self.d_kno + self.d_ctx

    @property
    def d_total(self) -> int:
        return self.d_kno + self.d_ctx + self.d_emo


@dataclass(frozen=True, slots=True)
class ProbeConfig:
    epochs: int = 20
    batch: int = 1024
    lr: float = 2e-3
    weight_decay: float = 1e-4
    hidden: int = 256


@dataclass(frozen=True, slots=True)
class SplitData:
    name: str
    ids: tuple[str, ...]
    texts: tuple[str, ...]
    unseen_author_thread: BOOL
    """Items whose author and thread do not occur in the official train split (metadata)."""
    emo: F64 | None = None
    """``(n, 28)`` multi-hot; ``None`` while blinded."""
    ctx: I64 | None = None
    """Subreddit index into the train vocabulary (``-1`` if unseen); ``None`` while blinded."""


# --- data -----------------------------------------------------------------------------------------


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_pins(root: Path) -> None:
    """Every file must match the SHA-256 recorded at download (``MANIFEST.json``)."""
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    for name, entry in manifest["files"].items():
        if _sha256(root / name) != entry["sha256"]:
            msg = f"file does not match its pin: {name}"
            raise RuntimeError(msg)


def _metadata(root: Path) -> dict[str, tuple[str, str, str]]:
    meta: dict[str, tuple[str, str, str]] = {}
    for i in (1, 2, 3):
        with (root / f"goemotions_{i}.csv").open(encoding="utf-8", newline="") as f:
            for row in csv.DictReader(f):
                meta.setdefault(row["id"], (row["subreddit"], row["author"], row["link_id"]))
    return meta


def load(root: Path, *, unblind: bool = False) -> dict[str, SplitData]:
    """The official splits. Test labels (emotions and subreddit) only with ``unblind``."""
    meta = _metadata(root)
    rows: dict[str, list[list[str]]] = {}
    for s in SPLITS:
        with (root / f"{s}.tsv").open(encoding="utf-8") as f:
            rows[s] = [line.rstrip("\n").split("\t") for line in f]
    train_authors = {meta[r[2]][1] for r in rows["train"]}
    train_threads = {meta[r[2]][2] for r in rows["train"]}
    vocab = sorted({meta[r[2]][0] for r in rows["train"]})
    index = {name: i for i, name in enumerate(vocab)}
    out = {}
    for s in SPLITS:
        r = rows[s]
        ids = tuple(x[2] for x in r)
        unseen = np.array(
            [meta[i][1] not in train_authors and meta[i][2] not in train_threads for i in ids],
            dtype=bool,
        )
        labelled = s != "test" or unblind
        emo = ctx = None
        if labelled:
            emo = np.zeros((len(r), N_EMO))
            for k, x in enumerate(r):
                emo[k, [int(e) for e in x[1].split(",")]] = 1.0
            ctx = np.array([index.get(meta[i][0], -1) for i in ids], dtype=np.int64)
        out[s] = SplitData(s, ids, tuple(x[0] for x in r), unseen, emo, ctx)
    return out


def dry_run(root: Path) -> dict[str, Any]:
    """Blinded check: counts and metadata only, never a test label."""
    data = load(root, unblind=False)
    return {
        s: {
            "items": len(d.ids),
            "unseen_author_and_thread": int(d.unseen_author_thread.sum()),
            "labels_loaded": d.emo is not None,
        }
        for s, d in data.items()
    }


def embed(texts: Sequence[str], cache: Path, device: str) -> F64:
    """Frozen, L2-normalised sentence embeddings, cached by model revision and text digest."""
    h = hashlib.sha256(MODEL_REVISION.encode())
    for t in texts:
        h.update(t.encode())
        h.update(b"\x00")
    path = cache / f"goemotions-minilm-{h.hexdigest()[:24]}.npy"
    if path.exists():
        out: F64 = np.load(path)
        return out
    from sentence_transformers import (  # type: ignore[import-not-found]  # noqa: PLC0415
        SentenceTransformer,  # optional dependency, installed only in the GPU environment
    )

    model = SentenceTransformer(MODEL, revision=MODEL_REVISION, device=device)
    vec = model.encode(
        list(texts), batch_size=256, normalize_embeddings=True, convert_to_numpy=True
    )
    out = np.asarray(vec, dtype=np.float64)
    cache.mkdir(parents=True, exist_ok=True)
    np.save(path, out)
    return out


# --- metrics --------------------------------------------------------------------------------------


def auroc(y: F64, s: F64) -> float:
    """Rank-based ROC-AUC of one binary label (ties averaged); NaN without both classes."""
    pos = y > 0.5
    n1, n0 = int(pos.sum()), int((~pos).sum())
    if n1 == 0 or n0 == 0:
        return float("nan")
    order = np.argsort(s, kind="mergesort")
    ranks = np.empty(len(s))
    sorted_s = s[order]
    i = 0
    while i < len(s):
        j = i
        while j + 1 < len(s) and sorted_s[j + 1] == sorted_s[i]:
            j += 1
        ranks[order[i : j + 1]] = (i + j) / 2.0 + 1.0
        i = j + 1
    return float((ranks[pos].sum() - n1 * (n1 + 1) / 2.0) / (n1 * n0))


def macro_auroc(y: F64, s: F64) -> float:
    vals = [auroc(y[:, k], s[:, k]) for k in range(y.shape[1])]
    return float(np.nanmean(vals))


def paired_bootstrap(
    stat: Any,  # noqa: ANN401 - callable(index array) -> float
    n: int,
    *,
    n_boot: int = N_BOOT,
    seed: int = 0,
) -> F64:
    rng = np.random.default_rng(seed)
    return np.array([stat(rng.integers(0, n, n)) for _ in range(n_boot)])


def holm(p: dict[str, float], alpha: float = 0.05) -> dict[str, bool]:
    order = sorted(p, key=lambda k: p[k])
    out = dict.fromkeys(p, False)
    for rank, k in enumerate(order):
        if p[k] <= alpha / (len(p) - rank):
            out[k] = True
        else:
            break
    return out


# --- models (torch) -------------------------------------------------------------------------------


def device_name() -> str:
    import torch  # noqa: PLC0415

    forced = os.environ.get("ESP_DEVICE")
    if forced:
        return forced
    return "cuda" if torch.cuda.is_available() else "cpu"


def _set_seed(seed: int) -> None:
    import torch  # noqa: PLC0415

    torch.manual_seed(seed)
    np.random.default_rng(seed)
    torch.use_deterministic_algorithms(True, warn_only=False)


def train_encoder(
    x: F64,
    emo: F64,
    ctx: I64,
    n_ctx: int,
    *,
    typed: bool,
    cfg: EncoderConfig,
    seed: int,
    device: str = "cpu",
) -> Any:  # noqa: ANN401 - torch module
    """Train the TAOSS (``typed``) or the monolithic encoder on train rows; returns the encoder."""
    import torch  # noqa: PLC0415
    from torch import nn  # noqa: PLC0415

    from esp.training.encoder import grl  # noqa: PLC0415

    _set_seed(seed)
    d_in = x.shape[1]
    enc = nn.Sequential(nn.Linear(d_in, cfg.hidden), nn.GELU(), nn.Linear(cfg.hidden, cfg.d_total))
    d_emo_in = cfg.d_emo if typed else cfg.d_total
    d_ctx_in = cfg.d_ctx if typed else cfg.d_total
    d_kno_in = cfg.d_kno if typed else cfg.d_total
    emo_head = nn.Linear(d_emo_in, N_EMO)
    ctx_head = nn.Linear(d_ctx_in, n_ctx)
    kno_head = nn.Linear(d_kno_in, d_in)
    adv = nn.Sequential(nn.Linear(cfg.d_released, 128), nn.GELU(), nn.Linear(128, N_EMO))
    mods = nn.ModuleList([enc, emo_head, ctx_head, kno_head, adv]).to(device)
    opt = torch.optim.AdamW(mods.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)
    xt = torch.tensor(x, dtype=torch.float32, device=device)
    et = torch.tensor(emo, dtype=torch.float32, device=device)
    keep = ctx >= 0
    ct = torch.tensor(np.where(keep, ctx, 0), dtype=torch.long, device=device)
    kt = torch.tensor(keep, dtype=torch.bool, device=device)
    gen = torch.Generator(device="cpu").manual_seed(seed)
    bce, ce = nn.BCEWithLogitsLoss(), nn.CrossEntropyLoss()
    for _ in range(cfg.epochs):
        perm = torch.randperm(len(xt), generator=gen)
        for start in range(0, len(xt), cfg.batch):
            idx = perm[start : start + cfg.batch].to(device)
            z = enc(xt[idx])
            kno, cx, em = (
                z[:, : cfg.d_kno],
                z[:, cfg.d_kno : cfg.d_released],
                z[:, cfg.d_released :],
            )
            sel = kt[idx]
            if typed:
                loss = bce(emo_head(em), et[idx]) + ce(ctx_head(cx)[sel], ct[idx][sel])
                loss = loss + (1.0 - nn.functional.cosine_similarity(kno_head(kno), xt[idx])).mean()
                rel = z[:, : cfg.d_released]
                if cfg.lam_cov > 0:
                    rc, ec = rel - rel.mean(0), em - em.mean(0)
                    cov = rc.T @ ec / max(1, len(idx) - 1)
                    loss = loss + cfg.lam_cov * (cov**2).mean()
                if cfg.lam_adv > 0:
                    loss = loss + cfg.lam_adv * bce(adv(grl(rel, 1.0)), et[idx])
            else:
                loss = bce(emo_head(z), et[idx]) + ce(ctx_head(z)[sel], ct[idx][sel])
                loss = loss + (1.0 - nn.functional.cosine_similarity(kno_head(z), xt[idx])).mean()
            opt.zero_grad()
            loss.backward()
            opt.step()
    enc.eval()
    return enc


def encode(enc: Any, x: F64, device: str = "cpu") -> F64:  # noqa: ANN401 - torch module
    import torch  # noqa: PLC0415

    with torch.no_grad():
        z = enc(torch.tensor(x, dtype=torch.float32, device=device))
    out: F64 = z.cpu().numpy().astype(np.float64)
    return out


def _probe_scores(
    r_train: F64,
    y_train: F64 | I64,
    r_eval: F64,
    *,
    multilabel: bool,
    n_out: int,
    mlp: bool,
    cfg: ProbeConfig,
    seed: int,
    device: str = "cpu",
) -> F64:
    import torch  # noqa: PLC0415
    from torch import nn  # noqa: PLC0415

    _set_seed(seed)
    mu, sd = r_train.mean(0), r_train.std(0) + 1e-6
    xt = torch.tensor((r_train - mu) / sd, dtype=torch.float32, device=device)
    xe = torch.tensor((r_eval - mu) / sd, dtype=torch.float32, device=device)
    d = xt.shape[1]
    model = (
        nn.Sequential(nn.Linear(d, cfg.hidden), nn.GELU(), nn.Linear(cfg.hidden, n_out))
        if mlp
        else nn.Linear(d, n_out)
    ).to(device)
    opt = torch.optim.AdamW(model.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)
    if multilabel:
        yt = torch.tensor(np.asarray(y_train), dtype=torch.float32, device=device)
        loss_fn: Any = nn.BCEWithLogitsLoss()
    else:
        y = np.asarray(y_train)
        keep = y >= 0
        xt, yt = xt[torch.tensor(keep, device=device)], torch.tensor(y[keep], device=device)
        loss_fn = nn.CrossEntropyLoss()
    gen = torch.Generator(device="cpu").manual_seed(seed)
    for _ in range(cfg.epochs):
        perm = torch.randperm(len(xt), generator=gen)
        for start in range(0, len(xt), cfg.batch):
            idx = perm[start : start + cfg.batch].to(device)
            loss = loss_fn(model(xt[idx]), yt[idx])
            opt.zero_grad()
            loss.backward()
            opt.step()
    with torch.no_grad():
        out = model(xe)
        out = torch.sigmoid(out) if multilabel else torch.softmax(out, dim=1)
    res: F64 = out.cpu().numpy().astype(np.float64)
    return res


def ridge_r2(r_train: F64, x_train: F64, r_eval: F64, x_eval: F64, alpha: float = 1.0) -> float:
    """Content fidelity: R² of reconstructing the embedding from the released representation."""
    mu, sd = r_train.mean(0), r_train.std(0) + 1e-6
    a, b = (r_train - mu) / sd, (r_eval - mu) / sd
    w = np.linalg.solve(a.T @ a + alpha * np.eye(a.shape[1]), a.T @ (x_train - x_train.mean(0)))
    pred = b @ w + x_train.mean(0)
    ss_res = float(((x_eval - pred) ** 2).sum())
    ss_tot = float(((x_eval - x_eval.mean(0)) ** 2).sum())
    return 1.0 - ss_res / ss_tot


@dataclass
class Released:
    """Per-method item scores on the evaluation split, averaged over seeds."""

    emo_lin: F64
    emo_mlp: F64
    ctx_lin: F64
    ctx_mlp: F64
    fidelity: float


def evaluate_released(  # noqa: PLR0917 - one released pair plus its references
    r_train: F64,
    r_eval: F64,
    train: SplitData,
    x_train: F64,
    x_eval: F64,
    n_ctx: int,
    *,
    cfg: ProbeConfig,
    seed: int,
    device: str,
) -> Released:
    emo_tr, ctx_tr = labels(train)

    def probe(y: F64 | I64, *, multilabel: bool, n_out: int, mlp: bool) -> F64:
        return _probe_scores(
            r_train,
            y,
            r_eval,
            multilabel=multilabel,
            n_out=n_out,
            mlp=mlp,
            cfg=cfg,
            seed=seed,
            device=device,
        )

    return Released(
        emo_lin=probe(emo_tr, multilabel=True, n_out=N_EMO, mlp=False),
        emo_mlp=probe(emo_tr, multilabel=True, n_out=N_EMO, mlp=True),
        ctx_lin=probe(ctx_tr, multilabel=False, n_out=n_ctx, mlp=False),
        ctx_mlp=probe(ctx_tr, multilabel=False, n_out=n_ctx, mlp=True),
        fidelity=ridge_r2(r_train, x_train, r_eval, x_eval),
    )


def labels(d: SplitData) -> tuple[F64, I64]:
    """The split's labels; refuses while the split is blinded."""
    if d.emo is None or d.ctx is None:
        msg = f"split {d.name} is blinded"
        raise RuntimeError(msg)
    return d.emo, d.ctx


def mean_released(items: list[Released]) -> Released:
    return Released(
        emo_lin=np.mean([r.emo_lin for r in items], axis=0),
        emo_mlp=np.mean([r.emo_mlp for r in items], axis=0),
        ctx_lin=np.mean([r.ctx_lin for r in items], axis=0),
        ctx_mlp=np.mean([r.ctx_mlp for r in items], axis=0),
        fidelity=float(np.mean([r.fidelity for r in items])),
    )


def summarize(r: Released, emo: F64, ctx: I64, rows: I64 | None = None) -> dict[str, float]:
    """Leakage: strongest emotion probe's macro-AUROC. Utility: strongest subreddit accuracy."""
    sel = np.arange(len(ctx)) if rows is None else rows
    y, c = emo[sel], ctx[sel]
    leak_lin, leak_mlp = macro_auroc(y, r.emo_lin[sel]), macro_auroc(y, r.emo_mlp[sel])
    acc_lin = float(np.mean(r.ctx_lin[sel].argmax(1) == c))
    acc_mlp = float(np.mean(r.ctx_mlp[sel].argmax(1) == c))
    return {
        "leak_auroc": max(leak_lin, leak_mlp),
        "leak_auroc_linear": leak_lin,
        "leak_auroc_mlp": leak_mlp,
        "ctx_acc": max(acc_lin, acc_mlp),
        "ctx_acc_linear": acc_lin,
        "ctx_acc_mlp": acc_mlp,
        "fidelity_r2": r.fidelity,
    }


def compare(
    taoss: Released,
    base: Released,
    emo: F64,
    ctx: I64,
    *,
    rows: I64 | None = None,
    n_boot: int = N_BOOT,
    seed: int = 0,
) -> dict[str, float]:
    """Paired bootstrap: leakage reduction (one-sided p) and utility non-inferiority."""
    sel = np.arange(len(ctx)) if rows is None else rows
    t_sum, b_sum = summarize(taoss, emo, ctx, sel), summarize(base, emo, ctx, sel)
    t_probe = "emo_mlp" if t_sum["leak_auroc_mlp"] >= t_sum["leak_auroc_linear"] else "emo_lin"
    b_probe = "emo_mlp" if b_sum["leak_auroc_mlp"] >= b_sum["leak_auroc_linear"] else "emo_lin"
    t_ctx = "ctx_mlp" if t_sum["ctx_acc_mlp"] >= t_sum["ctx_acc_linear"] else "ctx_lin"
    b_ctx = "ctx_mlp" if b_sum["ctx_acc_mlp"] >= b_sum["ctx_acc_linear"] else "ctx_lin"
    ts, bs = getattr(taoss, t_probe)[sel], getattr(base, b_probe)[sel]
    t_ok = (getattr(taoss, t_ctx)[sel].argmax(1) == ctx[sel]).astype(float)
    b_ok = (getattr(base, b_ctx)[sel].argmax(1) == ctx[sel]).astype(float)
    y = emo[sel]
    n = len(sel)

    def leak_diff(i: I64) -> float:
        return macro_auroc(y[i], bs[i]) - macro_auroc(y[i], ts[i])

    def acc_diff(i: I64) -> float:
        return float(t_ok[i].mean() - b_ok[i].mean())

    dl = paired_bootstrap(leak_diff, n, n_boot=n_boot, seed=seed)
    da = paired_bootstrap(acc_diff, n, n_boot=n_boot, seed=seed + 1)
    return {
        "leak_taoss": t_sum["leak_auroc"],
        "leak_base": b_sum["leak_auroc"],
        "leak_reduction": b_sum["leak_auroc"] - t_sum["leak_auroc"],
        "p_leak": float((1 + np.sum(dl <= 0)) / (1 + len(dl))),
        "acc_taoss": t_sum["ctx_acc"],
        "acc_base": b_sum["ctx_acc"],
        "acc_diff_q05": float(np.quantile(da, 0.05)),
        "noninferior": bool(np.quantile(da, 0.05) > -DELTA),
    }


def config_record() -> dict[str, Any]:
    return {
        "model": MODEL,
        "model_revision": MODEL_REVISION,
        "encoder": asdict(TAOSS_CONFIG),
        "probe": asdict(ProbeConfig()),
        "delta": DELTA,
        "n_boot": N_BOOT,
        "seeds": list(SEEDS),
    }


TAOSS_CONFIG = EncoderConfig(lam_cov=3.0, lam_adv=3.0)
"""Frozen after dev tuning by the fixed rule in ``scripts/run_goemotions_dev.py``: the lowest
dev leakage among settings within ``DELTA`` of the monolithic subreddit accuracy
(``artifacts/research/goemotions_dev.json``). The monolithic baseline uses the same
architecture and training budget without penalties."""


# --- pipeline -------------------------------------------------------------------------------------

METHODS = ("taoss", "mono", "mono_leace", "mono_filter", "raw")


def run_methods(
    train: SplitData,
    ev: SplitData,
    x_train: F64,
    x_eval: F64,
    n_ctx: int,
    *,
    enc_cfg: EncoderConfig,
    probe_cfg: ProbeConfig | None = None,
    device: str = "cpu",
    seeds: Sequence[int] = SEEDS,
    methods: Sequence[str] = METHODS,
) -> dict[str, Released]:
    """Train every method on ``train`` and score its released representation on ``ev``.

    Labels of ``ev`` are never used here: LEACE and the learned filter are fitted on the
    train rows only (evaluation rows get zero placeholders that the fit ignores).
    """
    from esp.bench.filter import learned_filter  # noqa: PLC0415
    from esp.bench.smoke import leace_erase  # noqa: PLC0415

    pcfg = probe_cfg or ProbeConfig()
    emo_tr, ctx_tr = labels(train)
    n_tr, n_ev = len(x_train), len(x_eval)
    mask = np.r_[np.ones(n_tr, bool), np.zeros(n_ev, bool)]
    emo_pad = np.vstack([emo_tr, np.zeros((n_ev, N_EMO))])
    ctx_pad = np.r_[ctx_tr, np.zeros(n_ev, dtype=np.int64)]
    d = enc_cfg.d_released
    per: dict[str, list[Released]] = {m: [] for m in methods}
    for seed in seeds:
        reps: dict[str, tuple[F64, F64]] = {}
        if "taoss" in methods:
            enc = train_encoder(
                x_train, emo_tr, ctx_tr, n_ctx, typed=True, cfg=enc_cfg, seed=seed, device=device
            )
            reps["taoss"] = (
                encode(enc, x_train, device)[:, :d],
                encode(enc, x_eval, device)[:, :d],
            )
        if {"mono", "mono_leace", "mono_filter"} & set(methods):
            enc = train_encoder(
                x_train, emo_tr, ctx_tr, n_ctx, typed=False, cfg=enc_cfg, seed=seed, device=device
            )
            m_tr, m_ev = encode(enc, x_train, device)[:, :d], encode(enc, x_eval, device)[:, :d]
            reps["mono"] = (m_tr, m_ev)
            stacked = np.vstack([m_tr, m_ev])
            if "mono_leace" in methods:
                erased = leace_erase(stacked, emo_pad, train=mask)
                reps["mono_leace"] = (erased[:n_tr], erased[n_tr:])
            if "mono_filter" in methods:
                filt = learned_filter(stacked, ctx_pad, emo_pad, train=mask, seed=seed)
                reps["mono_filter"] = (filt[:n_tr], filt[n_tr:])
        if "raw" in methods:
            reps["raw"] = (x_train, x_eval)
        for m in methods:
            r_tr, r_ev = reps[m]
            per[m].append(
                evaluate_released(
                    r_tr, r_ev, train, x_train, x_eval, n_ctx, cfg=pcfg, seed=seed, device=device
                )
            )
    return {m: mean_released(v) for m, v in per.items()}


def analyse(
    data: dict[str, SplitData],
    x: dict[str, F64],
    *,
    device: str,
    seeds: Sequence[int] = SEEDS,
    n_boot: int = N_BOOT,
) -> dict[str, Any]:
    """The preregistered confirmatory analysis on the official test split."""
    train, test = data["train"], data["test"]
    emo_te, ctx_te = labels(test)
    n_ctx = int(labels(train)[1].max()) + 1
    res = run_methods(
        train, test, x["train"], x["test"], n_ctx, enc_cfg=TAOSS_CONFIG, device=device, seeds=seeds
    )
    unseen = np.flatnonzero(test.unseen_author_thread)
    out: dict[str, Any] = {
        "summary": {m: summarize(r, emo_te, ctx_te) for m, r in res.items()},
        "P1_taoss_vs_mono": compare(res["taoss"], res["mono"], emo_te, ctx_te, n_boot=n_boot),
    }
    sec = {
        "S1_taoss_vs_mono_leace": compare(
            res["taoss"], res["mono_leace"], emo_te, ctx_te, n_boot=n_boot
        ),
        "S2_taoss_vs_mono_filter": compare(
            res["taoss"], res["mono_filter"], emo_te, ctx_te, n_boot=n_boot
        ),
        "S3_taoss_vs_mono_unseen_author_thread": compare(
            res["taoss"], res["mono"], emo_te, ctx_te, rows=unseen, n_boot=n_boot
        ),
    }
    out.update(sec)
    p1 = out["P1_taoss_vs_mono"]
    out["primary_supported"] = bool(p1["p_leak"] < 0.05 and p1["noninferior"])
    rejected = holm({k: v["p_leak"] for k, v in sec.items()})
    out["holm_secondary"] = {k: bool(rejected[k] and sec[k]["noninferior"]) for k in sec}
    out["n_test"] = len(test.ids)
    out["n_test_unseen_author_thread"] = len(unseen)
    out["config"] = config_record()
    return out
