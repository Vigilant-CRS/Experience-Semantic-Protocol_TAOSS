# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Preregistered typing-plus-erasure study on DailyDialog (H2 follow-up, claims level 5 track).

Question: when EMO is masked, does a typed encoder **plus** LEACE erasure of EMO
(:mod:`esp.privacy.erasure`) leak less emotion from the released parts than LEACE alone on
an untyped latent of the same size, at non-inferior utility?

Data: DailyDialog (Li et al., IJCNLP 2017), CC BY-NC-SA 4.0. Official train, validation and
test segmentations.

| Type | Mapping | Note |
|---|---|---|
| EMO | per-utterance emotion annotation (7 classes) | content-side, not a felt state |
| INT | per-utterance dialog act (inform, question, directive, commissive) | |
| CTX | per-dialog topic (10 classes) | taken from the full corpus file by exact dialog text |
| KNO | content, the frozen all-MiniLM-L6-v2 embedding the encoder must reconstruct | |

The analysis unit is the utterance. The bootstrap resamples **dialogs** (clusters), because
utterances of one dialog are not independent. Test labels (emotion, act, topic) are only
loaded with ``unblind=True``. Test dialogs whose exact text also occurs in train are flagged
from text alone, without labels, so a secondary test can exclude them.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Final

import numpy as np
from numpy.typing import NDArray

from esp.bench.erasure_methods import variants
from esp.bench.goemotions_study import (
    MODEL,
    MODEL_REVISION,
    ProbeConfig,
    _probe_scores,
    _set_seed,
    holm,
    macro_auroc,
    ridge_r2,
)

F64 = NDArray[np.float64]
I64 = NDArray[np.int64]
BOOL = NDArray[np.bool_]
SPLITS: Final = ("train", "validation", "test")
N_EMO: Final = 7
N_ACT: Final = 4
N_TOPIC: Final = 10
DELTA: Final = 0.02
N_BOOT: Final = 10_000
SEEDS: Final = (0, 1, 2)
METHODS: Final = ("taoss", "taoss_leace", "mono", "mono_leace", "mono_filter", "raw_leace")


@dataclass(frozen=True, slots=True)
class EncoderConfig:
    hidden: int = 256
    d_kno: int = 64
    d_ctx: int = 16
    d_int: int = 16
    d_emo: int = 16
    lam_cov: float = 3.0
    lam_adv: float = 3.0
    epochs: int = 20
    batch: int = 512
    lr: float = 1e-3
    weight_decay: float = 1e-4

    @property
    def d_released(self) -> int:
        return self.d_kno + self.d_ctx + self.d_int

    @property
    def d_total(self) -> int:
        return self.d_released + self.d_emo


@dataclass(frozen=True, slots=True)
class SplitData:
    name: str
    dialog: I64
    """Dialog index of each utterance (bootstrap cluster)."""
    texts: tuple[str, ...]
    seen_in_train: BOOL
    """Utterance belongs to a dialog whose exact text also occurs in train (text only)."""
    emo: I64 | None = None
    act: I64 | None = None
    topic: I64 | None = None
    """``-1`` where the dialog text is ambiguous or missing in the full corpus file."""


# --- data -----------------------------------------------------------------------------------------


def _norm(dialog_line: str) -> str:
    return re.sub(r"\s+", " ", dialog_line).strip()


def _utterances(line: str) -> list[str]:
    parts = [u.strip() for u in line.rstrip("\n").split("__eou__")]
    return [u for u in parts if u]


def _base(root: Path) -> Path:
    return root / "ijcnlp_dailydialog"


def verify_pins(root: Path) -> None:
    manifest = json.loads((root / "MANIFEST.json").read_text(encoding="utf-8"))
    for rel, digest in manifest["files"].items():
        if hashlib.sha256((root / rel).read_bytes()).hexdigest() != digest["sha256"]:
            msg = f"pinned file changed: {rel}"
            raise RuntimeError(msg)


def _topic_index(root: Path) -> dict[str, int]:
    b = _base(root)
    texts = (b / "dialogues_text.txt").read_text(encoding="utf-8").splitlines()
    topics = (b / "dialogues_topic.txt").read_text(encoding="utf-8").split()
    out: dict[str, int] = {}
    for t, k in zip(texts, topics, strict=True):
        key, val = _norm(t), int(k) - 1
        out[key] = val if out.get(key, val) == val else -1  # conflicting topics: ambiguous
    return out


def load(root: Path, *, unblind: bool = False) -> dict[str, SplitData]:
    """Official segmentations; test labels only with ``unblind``."""
    b = _base(root)
    raw: dict[str, list[str]] = {}
    for s in SPLITS:
        raw[s] = (b / s / f"dialogues_{s}.txt").read_text(encoding="utf-8").splitlines()
    train_keys = {_norm(t) for t in raw["train"]}
    topics = _topic_index(root)
    out = {}
    for s in SPLITS:
        labelled = s != "test" or unblind
        acts = (b / s / f"dialogues_act_{s}.txt").read_text(encoding="utf-8").splitlines()
        emos = (b / s / f"dialogues_emotion_{s}.txt").read_text(encoding="utf-8").splitlines()
        texts, dialog, seen, emo, act, topic = [], [], [], [], [], []
        for k, line in enumerate(raw[s]):
            utts = _utterances(line)
            a, e = acts[k].split(), emos[k].split()
            if not (len(utts) == len(a) == len(e)):
                continue  # documented exclusion: annotation/utterance count mismatch
            key = _norm(line)
            texts += utts
            dialog += [k] * len(utts)
            seen += [s != "train" and key in train_keys] * len(utts)
            if labelled:
                emo += [int(x) for x in e]
                act += [int(x) - 1 for x in a]
                topic += [topics.get(key, -1)] * len(utts)
        out[s] = SplitData(
            s,
            np.array(dialog, dtype=np.int64),
            tuple(texts),
            np.array(seen, dtype=bool),
            np.array(emo, dtype=np.int64) if labelled else None,
            np.array(act, dtype=np.int64) if labelled else None,
            np.array(topic, dtype=np.int64) if labelled else None,
        )
    return out


def dry_run(root: Path) -> dict[str, Any]:
    data = load(root, unblind=False)
    return {
        s: {
            "utterances": len(d.texts),
            "dialogs": len(np.unique(d.dialog)),
            "utterances_in_dialogs_seen_in_train": int(d.seen_in_train.sum()),
            "labels_loaded": d.emo is not None,
        }
        for s, d in data.items()
    }


def embed(texts: Sequence[str], cache: Path, device: str) -> F64:
    """Frozen, L2-normalised sentence embeddings (same model and revision as GoEmotions)."""
    h = hashlib.sha256(MODEL_REVISION.encode())
    for t in texts:
        h.update(t.encode())
        h.update(b"\x00")
    path = cache / f"dailydialog-minilm-{h.hexdigest()[:24]}.npy"
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


def labels(d: SplitData) -> tuple[I64, I64, I64]:
    if d.emo is None or d.act is None or d.topic is None:
        msg = f"split {d.name} is blinded"
        raise RuntimeError(msg)
    return d.emo, d.act, d.topic


def one_hot(y: I64, n: int) -> F64:
    out = np.zeros((len(y), n))
    out[np.arange(len(y)), y] = 1.0
    return out


# --- encoder --------------------------------------------------------------------------------------


def train_encoder(
    x: F64,
    emo: I64,
    act: I64,
    topic: I64,
    *,
    typed: bool,
    cfg: EncoderConfig,
    seed: int,
    device: str = "cpu",
) -> Any:  # noqa: ANN401 - torch module
    import torch  # noqa: PLC0415
    from torch import nn  # noqa: PLC0415

    from esp.training.encoder import grl  # noqa: PLC0415

    _set_seed(seed)
    d_in = x.shape[1]
    enc = nn.Sequential(nn.Linear(d_in, cfg.hidden), nn.GELU(), nn.Linear(cfg.hidden, cfg.d_total))
    k, c, i, r = cfg.d_kno, cfg.d_ctx, cfg.d_int, cfg.d_released
    full = cfg.d_total
    heads = nn.ModuleDict(
        {
            "kno": nn.Linear(k if typed else full, d_in),
            "ctx": nn.Linear(c if typed else full, N_TOPIC),
            "int": nn.Linear(i if typed else full, N_ACT),
            "emo": nn.Linear(cfg.d_emo if typed else full, N_EMO),
        }
    )
    adv = nn.Sequential(nn.Linear(r, 128), nn.GELU(), nn.Linear(128, N_EMO))
    mods = nn.ModuleList([enc, heads, adv]).to(device)
    opt = torch.optim.AdamW(mods.parameters(), lr=cfg.lr, weight_decay=cfg.weight_decay)
    xt = torch.tensor(x, dtype=torch.float32, device=device)
    et = torch.tensor(emo, dtype=torch.long, device=device)
    at = torch.tensor(act, dtype=torch.long, device=device)
    keep = torch.tensor(topic >= 0, device=device)
    tt = torch.tensor(np.where(topic >= 0, topic, 0), dtype=torch.long, device=device)
    gen = torch.Generator(device="cpu").manual_seed(seed)
    ce = nn.CrossEntropyLoss()
    for _ in range(cfg.epochs):
        perm = torch.randperm(len(xt), generator=gen)
        for start in range(0, len(xt), cfg.batch):
            idx = perm[start : start + cfg.batch].to(device)
            z = enc(xt[idx])
            parts = {
                "kno": z[:, :k],
                "ctx": z[:, k : k + c],
                "int": z[:, k + c : r],
                "emo": z[:, r:],
            }
            src = parts if typed else dict.fromkeys(parts, z)
            sel = keep[idx]
            loss = ce(heads["emo"](src["emo"]), et[idx]) + ce(heads["int"](src["int"]), at[idx])
            loss = loss + ce(heads["ctx"](src["ctx"])[sel], tt[idx][sel])
            loss = (
                loss
                + (1 - nn.functional.cosine_similarity(heads["kno"](src["kno"]), xt[idx])).mean()
            )
            if typed:
                rel, em = z[:, :r], parts["emo"]
                if cfg.lam_cov > 0:
                    cov = (rel - rel.mean(0)).T @ (em - em.mean(0)) / max(1, len(idx) - 1)
                    loss = loss + cfg.lam_cov * (cov**2).mean()
                if cfg.lam_adv > 0:
                    loss = loss + cfg.lam_adv * ce(adv(grl(rel, 1.0)), et[idx])
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


# --- evaluation -----------------------------------------------------------------------------------


@dataclass
class Scores:
    emo_lin: F64
    emo_mlp: F64
    ctx_lin: F64
    ctx_mlp: F64
    int_lin: F64
    int_mlp: F64
    fidelity: float


def score(
    r_tr: F64, r_ev: F64, train: SplitData, x_tr: F64, x_ev: F64, *, seed: int, device: str
) -> Scores:
    emo, act, topic = labels(train)
    cfg = ProbeConfig()

    def probe(y: I64, n: int, mlp: bool) -> F64:
        return _probe_scores(
            r_tr, y, r_ev, multilabel=False, n_out=n, mlp=mlp, cfg=cfg, seed=seed, device=device
        )

    return Scores(
        probe(emo, N_EMO, False),
        probe(emo, N_EMO, True),
        probe(topic, N_TOPIC, False),
        probe(topic, N_TOPIC, True),
        probe(act, N_ACT, False),
        probe(act, N_ACT, True),
        ridge_r2(r_tr, x_tr, r_ev, x_ev),
    )


def mean_scores(items: list[Scores]) -> Scores:
    def avg(name: str) -> F64:
        out: F64 = np.mean([getattr(s, name) for s in items], axis=0)
        return out

    return Scores(
        avg("emo_lin"),
        avg("emo_mlp"),
        avg("ctx_lin"),
        avg("ctx_mlp"),
        avg("int_lin"),
        avg("int_mlp"),
        float(np.mean([s.fidelity for s in items])),
    )


def _best(s: Scores, kind: str, y: I64, rows: I64, *, auroc: bool) -> tuple[str, float]:
    best = ("", -np.inf)
    for p in ("lin", "mlp"):
        v = getattr(s, f"{kind}_{p}")[rows]
        m = (
            macro_auroc(one_hot(y[rows], v.shape[1]), v)
            if auroc
            else float(np.mean(v.argmax(1) == y[rows]))
        )
        best = max(best, (f"{kind}_{p}", m), key=lambda t: t[1])
    return best


def summarize(s: Scores, ev: SplitData, rows: I64 | None = None) -> dict[str, float]:
    emo, act, topic = labels(ev)
    sel = np.arange(len(emo)) if rows is None else rows
    known = sel[topic[sel] >= 0]
    return {
        "leak_auroc": _best(s, "emo", emo, sel, auroc=True)[1],
        "ctx_acc": _best(s, "ctx", topic, known, auroc=False)[1],
        "int_acc": _best(s, "int", act, sel, auroc=False)[1],
        "fidelity_r2": s.fidelity,
    }


def cluster_bootstrap(stat: Any, clusters: I64, *, n_boot: int = N_BOOT, seed: int = 0) -> F64:  # noqa: ANN401
    """Resample whole dialogs with replacement; ``stat`` receives utterance row indices."""
    rng = np.random.default_rng(seed)
    ids, inv = np.unique(clusters, return_inverse=True)
    members = [np.flatnonzero(inv == k) for k in range(len(ids))]
    out = []
    for _ in range(n_boot):
        pick = rng.integers(0, len(ids), len(ids))
        out.append(stat(np.concatenate([members[k] for k in pick])))
    return np.array(out)


def compare(
    a: Scores,
    b: Scores,
    ev: SplitData,
    *,
    rows: I64 | None = None,
    n_boot: int = N_BOOT,
    seed: int = 0,
) -> dict[str, Any]:
    """``a`` (the mechanism) against ``b``: leakage reduction p, CTX and INT non-inferiority."""
    emo, act, topic = labels(ev)
    sel = np.arange(len(emo)) if rows is None else rows
    known = sel[topic[sel] >= 0]
    pa, pb = _best(a, "emo", emo, sel, auroc=True)[0], _best(b, "emo", emo, sel, auroc=True)[0]
    ca, cb = (
        _best(a, "ctx", topic, known, auroc=False)[0],
        _best(b, "ctx", topic, known, auroc=False)[0],
    )
    ia, ib = _best(a, "int", act, sel, auroc=False)[0], _best(b, "int", act, sel, auroc=False)[0]
    sa, sb = getattr(a, pa), getattr(b, pb)
    ok_ca = (getattr(a, ca).argmax(1) == topic).astype(float)
    ok_cb = (getattr(b, cb).argmax(1) == topic).astype(float)
    ok_ia = (getattr(a, ia).argmax(1) == act).astype(float)
    ok_ib = (getattr(b, ib).argmax(1) == act).astype(float)
    y = one_hot(emo, N_EMO)
    has_topic = topic >= 0

    def leak(i: I64) -> float:
        return macro_auroc(y[i], sb[i]) - macro_auroc(y[i], sa[i])

    def ctx(i: I64) -> float:
        k = i[has_topic[i]]
        return float(ok_ca[k].mean() - ok_cb[k].mean())

    def int_(i: I64) -> float:
        return float(ok_ia[i].mean() - ok_ib[i].mean())

    cl = ev.dialog[sel]
    dl = cluster_bootstrap(lambda i: leak(sel[i]), cl, n_boot=n_boot, seed=seed)
    dc = cluster_bootstrap(lambda i: ctx(sel[i]), cl, n_boot=n_boot, seed=seed + 1)
    di = cluster_bootstrap(lambda i: int_(sel[i]), cl, n_boot=n_boot, seed=seed + 2)
    sum_a, sum_b = summarize(a, ev, sel), summarize(b, ev, sel)
    return {
        "leak_mechanism": sum_a["leak_auroc"],
        "leak_baseline": sum_b["leak_auroc"],
        "leak_reduction": sum_b["leak_auroc"] - sum_a["leak_auroc"],
        "p_leak": float((1 + np.sum(dl <= 0)) / (1 + len(dl))),
        "ctx_diff_q05": float(np.quantile(dc, 0.05)),
        "int_diff_q05": float(np.quantile(di, 0.05)),
        "noninferior": bool(np.quantile(dc, 0.05) > -DELTA and np.quantile(di, 0.05) > -DELTA),
        "acc": {
            "ctx": [sum_a["ctx_acc"], sum_b["ctx_acc"]],
            "int": [sum_a["int_acc"], sum_b["int_acc"]],
        },
    }


# --- pipeline -------------------------------------------------------------------------------------

CONFIG = EncoderConfig(lam_cov=1.0, lam_adv=1.0)
"""Frozen after validation by the fixed rule in ``scripts/run_dailydialog_erasure_dev.py``.

The rule chose ``cov=1.0,adv=1.0`` (``artifacts/research/erasure_dailydialog_dev.json``); the
lower-leakage ``cov=3.0,adv=3.0`` failed the CTX and INT utility gate."""


def run(
    train: SplitData,
    ev: SplitData,
    x_tr: F64,
    x_ev: F64,
    *,
    cfg: EncoderConfig = CONFIG,
    device: str = "cpu",
    seeds: Sequence[int] = SEEDS,
    methods: Sequence[str] = METHODS,
) -> dict[str, Scores]:
    """Fit everything on train only and score the released parts on ``ev``."""
    emo, act, topic = labels(train)
    r = cfg.d_released
    per: dict[str, list[Scores]] = {m: [] for m in methods}
    for seed in seeds:
        enc_t = train_encoder(x_tr, emo, act, topic, typed=True, cfg=cfg, seed=seed, device=device)
        enc_m = train_encoder(x_tr, emo, act, topic, typed=False, cfg=cfg, seed=seed, device=device)
        typed = (encode(enc_t, x_tr, device)[:, :r], encode(enc_t, x_ev, device)[:, :r])
        mono = (encode(enc_m, x_tr, device)[:, :r], encode(enc_m, x_ev, device)[:, :r])
        reps = variants(
            typed,
            mono,
            (x_tr, x_ev),
            one_hot(emo, N_EMO),
            act,
            seed=seed,
            training_data_id="dailydialog:train",
            names=methods,
        )
        for m, (a, b) in reps.items():
            per[m].append(score(a, b, train, x_tr, x_ev, seed=seed, device=device))
    return {m: mean_scores(v) for m, v in per.items()}


def config_record() -> dict[str, Any]:
    return {
        "model": MODEL,
        "model_revision": MODEL_REVISION,
        "encoder": asdict(CONFIG),
        "probe": asdict(ProbeConfig()),
        "delta": DELTA,
        "n_boot": N_BOOT,
        "seeds": list(SEEDS),
        "methods": list(METHODS),
    }


def analyse(
    data: dict[str, SplitData], x: dict[str, F64], *, device: str, n_boot: int = N_BOOT
) -> dict[str, Any]:
    """The preregistered confirmatory analysis on the official test split."""
    train, test = data["train"], data["test"]
    res = run(train, test, x["train"], x["test"], device=device)
    unseen = np.flatnonzero(~test.seen_in_train)
    out: dict[str, Any] = {
        "summary": {m: summarize(s, test) for m, s in res.items()},
        "P1_taoss_leace_vs_mono_leace": compare(
            res["taoss_leace"], res["mono_leace"], test, n_boot=n_boot
        ),
    }
    sec = {
        "S1_taoss_leace_vs_raw_leace": compare(
            res["taoss_leace"], res["raw_leace"], test, n_boot=n_boot
        ),
        "S2_taoss_leace_vs_mono_filter": compare(
            res["taoss_leace"], res["mono_filter"], test, n_boot=n_boot
        ),
        "S3_P1_on_dialogs_unseen_in_train": compare(
            res["taoss_leace"], res["mono_leace"], test, rows=unseen, n_boot=n_boot
        ),
        "S4_taoss_leace_vs_taoss": compare(res["taoss_leace"], res["taoss"], test, n_boot=n_boot),
    }
    out.update(sec)
    p1 = out["P1_taoss_leace_vs_mono_leace"]
    out["primary_supported"] = bool(p1["p_leak"] < 0.05 and p1["noninferior"])
    rejected = holm({k: v["p_leak"] for k, v in sec.items()})
    out["holm_secondary"] = {k: bool(rejected[k] and sec[k]["noninferior"]) for k in sec}
    out["n_test_utterances"] = len(test.texts)
    out["n_test_dialogs"] = len(np.unique(test.dialog))
    out["n_test_unseen_utterances"] = len(unseen)
    out["config"] = config_record()
    return out
