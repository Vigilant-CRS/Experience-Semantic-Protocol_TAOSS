# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""ExperienceBench: nine task families as plugins (WP-034) and H1/H2/H3 evaluators (WP-035..037).

Split discipline (V13): train/test split by *split unit* (session), never by
frame; every probe and preprocessing step is fit on train only.

Baselines that cannot run offline (frontier LLM text-only, CLIP/SigLIP-class)
are reported as ``not_run``; a hypothesis is only *claimable* when every
required baseline ran and the run is confirmatory (preregistered, WP-083).
Smoke runs are never claimable.
"""

from __future__ import annotations

import itertools
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

import numpy as np
from numpy.typing import NDArray

from esp.audit.suite import v_information_ladder
from esp.bench.filter import learned_filter
from esp.bench.prereg import Label
from esp.bench.smoke import TYPES, SmokeCorpus, encode, leace_erase

F64 = NDArray[np.float64]
Latents = Mapping[str, F64]
REQUIRED_BASELINES = (
    "text_llm",
    "clip_class",
    "mono",
    "mono_leace",
    "mono_learned_filter",
    "taoss_cov_only",
)
EXTERNAL_BASELINES = frozenset({"text_llm", "clip_class"})


@dataclass(frozen=True, slots=True)
class TaskResult:
    task: str
    family: int
    metrics: dict[str, float]
    status: str = "ran"
    notes: tuple[str, ...] = ()


def unit_split(
    corpus: SmokeCorpus, *, test_fraction: float = 0.3, seed: int = 0
) -> tuple[NDArray[np.bool_], NDArray[np.bool_]]:
    """Train/test masks by split unit (session); OOD items are excluded from both."""
    units = np.unique(corpus.units[~corpus.ood])
    test_units = np.random.default_rng(seed).choice(
        units, max(1, round(units.size * test_fraction)), replace=False
    )
    test = np.isin(corpus.units, test_units) & ~corpus.ood
    train = ~np.isin(corpus.units, test_units) & ~corpus.ood
    return train, test


def _cos(a: F64, b: F64) -> F64:
    return np.sum(a * b, axis=1) / (np.linalg.norm(a, axis=1) * np.linalg.norm(b, axis=1) + 1e-12)


def _ridge(xtr: F64, ytr: F64, xte: F64, alpha: float = 1.0) -> F64:
    mu, sd = xtr.mean(0), xtr.std(0) + 1e-12
    a, b = (xtr - mu) / sd, (xte - mu) / sd
    w = np.linalg.solve(a.T @ a + alpha * np.eye(a.shape[1]), a.T @ (ytr - ytr.mean(0)))
    return b @ w + ytr.mean(0)


def _centroid_accuracy(
    x: F64, y: NDArray[np.int64], train: NDArray[np.bool_], test: NDArray[np.bool_]
) -> float:
    classes = np.unique(y[train])
    cents = np.stack([x[train & (y == c)].mean(0) for c in classes])
    pred = classes[np.argmin(((x[test][:, None, :] - cents[None]) ** 2).sum(-1), axis=1)]
    return float(np.mean(pred == y[test]))


def ndcg_at_k(relevance: F64, scores: F64, k: int = 10) -> float:
    order = np.argsort(-scores)[:k]
    gains = (2 ** relevance[order] - 1) / np.log2(np.arange(2, order.size + 2))
    ideal = np.sort(relevance)[::-1][:k]
    ideal_gain = np.sum((2**ideal - 1) / np.log2(np.arange(2, ideal.size + 2)))
    return float(gains.sum() / ideal_gain) if ideal_gain > 0 else 0.0


# --- the nine families -----------------------------------------------------------------------


def typed_retrieval(c: SmokeCorpus, z: Latents, seed: int = 0) -> TaskResult:
    """1. Per-type predicates (EMO anchor + CTX metadata); nDCG@10 with graded relevance."""
    rng = np.random.default_rng(seed)
    _, test = unit_split(c, seed=seed)
    idx = np.nonzero(test)[0]
    scores = []
    for q in rng.choice(idx, 20, replace=False):
        rel = (c.scene[idx] == c.scene[q]).astype(float) + (
            _cos(c.factors["EMO"][idx], np.repeat(c.factors["EMO"][q : q + 1], idx.size, 0)) > 0.8
        )
        s = _cos(z["EMO"][idx], np.repeat(z["EMO"][q : q + 1], idx.size, 0)) + _cos(
            z["CTX"][idx], np.repeat(z["CTX"][q : q + 1], idx.size, 0)
        )
        scores.append(ndcg_at_k(rel, s))
    return TaskResult("typed_retrieval", 1, {"ndcg@10": float(np.mean(scores))})


def intent_transfer(c: SmokeCorpus, z: Latents, seed: int = 0) -> TaskResult:
    """2. Actions from INT alone (all other types masked); top-1 accuracy."""
    train, test = unit_split(c, seed=seed)
    return TaskResult(
        "intent_transfer", 2, {"top1": _centroid_accuracy(z["INT"], c.actions, train, test)}
    )


def context_preservation(c: SmokeCorpus, z: Latents, seed: int = 0) -> TaskResult:
    """3. Mask EMO/CTX/SEN, keep KNO+TEM; cosine of visible types to the oracle encoding."""
    oracle = encode(c, "taoss", noise=0.0)
    return TaskResult(
        "context_preservation",
        3,
        {f"cos_{t}": float(np.mean(_cos(z[t], oracle[t]))) for t in ("KNO", "TEM")},
    )


def temporal_reconstruction(c: SmokeCorpus, z: Latents, seed: int = 0) -> TaskResult:
    """4. Beat events from TEM alone; F1."""
    train, test = unit_split(c, seed=seed)
    score = _ridge(z["TEM"][train], c.beats[train, None].astype(float), z["TEM"][test])[:, 0]
    pred, truth = score > 0.5, c.beats[test] == 1
    tp = float(np.sum(pred & truth))
    f1 = 2 * tp / (np.sum(pred) + np.sum(truth)) if np.sum(pred) + np.sum(truth) else 0.0
    return TaskResult("temporal_reconstruction", 4, {"f1": float(f1)})


def leakage_probe(c: SmokeCorpus, z: Latents, seed: int = 0) -> TaskResult:
    """5. Predict masked EMO from visible types; held-out R^2 and V-information (bits)."""
    train, test = unit_split(c, seed=seed)
    visible = np.concatenate([z[t] for t in TYPES if t != "EMO"], axis=1)
    pred = _ridge(visible[train], z["EMO"][train], visible[test])
    y = z["EMO"][test]
    r2 = 1 - np.sum((y - pred) ** 2) / np.sum((y - z["EMO"][train].mean(0)) ** 2)
    bits = v_information_ladder(visible[~c.ood], z["EMO"][~c.ood], degrees=(1,), seed=seed)[-1]
    return TaskResult("leakage_probe", 5, {"r2": float(r2), "v_info_bits": float(bits)})


def ood_anchor_shift(c: SmokeCorpus, z: Latents, seed: int = 0) -> TaskResult:
    """6. Retrieval-style EMO similarity task in-distribution vs shifted anchors (<= 10 %)."""
    train, test = unit_split(c, seed=seed)
    labels = np.argmax(c.factors["EMO"][:, :2], axis=1)
    iid = _centroid_accuracy(z["EMO"], labels, train, test)
    ood = _centroid_accuracy(z["EMO"], labels, train, c.ood)
    degradation = (iid - ood) / iid if iid > 0 else 1.0
    return TaskResult(
        "ood_anchor_shift", 6, {"iid": iid, "ood": ood, "relative_degradation": float(degradation)}
    )


def encoder_drift(c: SmokeCorpus, z: Latents, seed: int = 0) -> TaskResult:
    """7. Two encoder versions (different seeds): per-type alignment after orthogonal Procrustes."""
    other = encode(c, "taoss", seed=seed + 7)
    out = {}
    for t in TYPES:
        u, _, vt = np.linalg.svd(other[t].T @ z[t], full_matrices=False)
        aligned = other[t] @ (u @ vt)
        out[f"compat_{t}"] = float(np.mean(_cos(aligned, z[t])))
    return TaskResult("encoder_drift", 7, out)


def human_interpretability(
    c: SmokeCorpus, z: Latents, seed: int = 0, *, ethics_approval: str = ""
) -> TaskResult:
    """8. Human study: requires ethics approval (WP-038 DEFERRED); never simulated as evidence."""
    del c, z, seed
    if not ethics_approval:
        return TaskResult(
            "human_interpretability",
            8,
            {},
            status="deferred",
            notes=("requires IRB/ethics approval, informed consent, stimulus screening (T13)",),
        )
    return TaskResult(
        "human_interpretability",
        8,
        {},
        status="protocol_ready",
        notes=(f"approval {ethics_approval}",),
    )


def consent_granularity(
    c: SmokeCorpus, z: Latents, seed: int = 0, *, u_min: float = 0.5, l_max_bits: float = 0.1
) -> TaskResult:
    """9. Effective policies: subsets S with U_visible(S) >= U_min and L_masked(S) <= L_max."""
    train, test = unit_split(c, seed=seed)
    effective, candidates = 0, 0
    for r in range(1, len(TYPES) + 1):
        for s in itertools.combinations(TYPES, r):
            candidates += 1
            visible = np.concatenate([z[t] for t in s], axis=1)
            if "INT" in s:
                utility = _centroid_accuracy(z["INT"], c.actions, train, test)
            else:
                utility = _centroid_accuracy(visible, c.actions, train, test)
            masked = [t for t in TYPES if t not in s]
            leak = max(
                (
                    v_information_ladder(visible[~c.ood], z[m][~c.ood], degrees=(1,), seed=seed)[-1]
                    for m in masked
                ),
                default=0.0,
            )
            effective += utility >= u_min and leak <= l_max_bits
    return TaskResult(
        "consent_granularity",
        9,
        {"effective_policies": float(effective), "candidates": float(candidates)},
    )


FAMILIES: dict[int, Callable[..., TaskResult]] = {
    1: typed_retrieval,
    2: intent_transfer,
    3: context_preservation,
    4: temporal_reconstruction,
    5: leakage_probe,
    6: ood_anchor_shift,
    7: encoder_drift,
    8: human_interpretability,
    9: consent_granularity,
}


def run_all(c: SmokeCorpus, variant: str = "taoss", seed: int = 0) -> list[TaskResult]:
    z = encode(c, variant, seed=seed)
    return [FAMILIES[k](c, z, seed) for k in sorted(FAMILIES)]


# --- hypotheses ---------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class HypothesisResult:
    hypothesis: str
    values: dict[str, float]
    baselines_run: tuple[str, ...]
    baselines_missing: tuple[str, ...]
    label: Label
    notes: tuple[str, ...] = field(default=())

    @property
    def claimable(self) -> bool:
        return self.label.confirmatory and not self.baselines_missing


def _missing(ran: set[str], required: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(b for b in required if b not in ran)


def h1(c: SmokeCorpus, label: Label, seed: int = 0) -> HypothesisResult:
    """H1: consent granularity at Pareto-comparable utility (effective-policy criterion)."""
    vals, ran = {}, set()
    for variant in ("taoss", "mono", "taoss_cov_only"):
        z = encode(c, variant, seed=seed)
        if variant == "mono":  # V13 pinned baseline: task heads read the full monolithic latent
            train, test = unit_split(c, seed=seed)
            full = np.concatenate([z[t] for t in TYPES], axis=1)
            vals["mono_utility"] = _centroid_accuracy(full, c.actions, train, test)
        else:
            vals[f"{variant}_utility"] = intent_transfer(c, z, seed).metrics["top1"]
        vals[f"{variant}_effective_policies"] = consent_granularity(c, z, seed).metrics[
            "effective_policies"
        ]
        ran.add(variant)
    vals["ratio_vs_mono"] = vals["taoss_effective_policies"] / max(
        1.0, vals["mono_effective_policies"]
    )
    vals["utility_loss_vs_mono"] = vals["mono_utility"] - vals["taoss_utility"]
    return HypothesisResult(
        "H1", vals, tuple(sorted(ran)), _missing(ran, REQUIRED_BASELINES), label
    )


def pairwise_leakage_bits(
    c: SmokeCorpus, z: Latents, seed: int = 0
) -> dict[tuple[str, str], float]:
    keep = ~c.ood
    return {
        (s, t): v_information_ladder(z[t][keep], z[s][keep], degrees=(1, 2), seed=seed)[-1]
        for s in TYPES
        for t in TYPES
        if s != t
    }


def h2(c: SmokeCorpus, label: Label, seed: int = 0) -> HypothesisResult:
    """H2: cross-type leakage reduction >= 2x vs every baseline (mean, worst pair, joint)."""
    vals, ran = {}, set()
    for variant in ("taoss", "mono", "taoss_cov_only"):
        pl = pairwise_leakage_bits(c, encode(c, variant, seed=seed), seed)
        vals[f"{variant}_mean_bits"] = float(np.mean(list(pl.values())))
        vals[f"{variant}_worst_bits"] = float(max(pl.values()))
        ran.add(variant)
    mono = encode(c, "mono", seed=seed)
    erased = {
        t: leace_erase(mono[t], np.concatenate([mono[u] for u in TYPES if u != t], axis=1))
        for t in TYPES
    }
    pl = pairwise_leakage_bits(c, erased, seed)
    vals["mono_leace_mean_bits"] = float(np.mean(list(pl.values())))
    ran.add("mono_leace")
    full = np.concatenate([mono[t] for t in TYPES], axis=1)
    filtered = learned_filter(full, c.actions, c.factors["EMO"], seed=seed)
    keep = ~c.ood
    vals["mono_learned_filter_emo_bits"] = v_information_ladder(
        filtered[keep], c.factors["EMO"][keep], degrees=(1, 2), seed=seed
    )[-1]
    ran.add("mono_learned_filter")
    vals["factor_vs_mono"] = vals["mono_mean_bits"] / max(1e-3, vals["taoss_mean_bits"])
    return HypothesisResult(
        "H2",
        vals,
        tuple(sorted(ran)),
        _missing(ran, REQUIRED_BASELINES),
        label,
        ("LEACE covers linear erasure only; the learned filter protects the EMO factors",),
    )


def causal_controls(
    c: SmokeCorpus, z: Latents, seed: int = 0, permutations: int = 500
) -> dict[str, tuple[float, float]]:
    """H3 controls: accuracy with z_true vs z_zero, z_shuffled, z_moment; paired permutation p."""
    train, test = unit_split(c, seed=seed)
    rng = np.random.default_rng(seed)
    x = z["INT"]
    controls = {
        "zero": np.zeros_like(x),
        "shuffled": x[rng.permutation(x.shape[0])],
        "moment": rng.normal(size=x.shape) * x.std(0) + x.mean(0),
    }

    def correct(features: F64) -> NDArray[np.bool_]:
        classes = np.unique(c.actions[train])
        cents = np.stack([x[train & (c.actions == k)].mean(0) for k in classes])
        pred = classes[np.argmin(((features[test][:, None, :] - cents[None]) ** 2).sum(-1), axis=1)]
        hits: NDArray[np.bool_] = pred == c.actions[test]
        return hits

    base = correct(x)
    out = {}
    for name, feat in controls.items():
        other = correct(feat)
        gap = float(base.mean() - other.mean())
        diff = base.astype(float) - other.astype(float)
        exceed = sum(
            abs(np.mean(diff * rng.choice([-1.0, 1.0], diff.size))) >= abs(gap)
            for _ in range(permutations)
        )
        out[name] = (gap, (exceed + 1) / (permutations + 1))
    return out


def h3(c: SmokeCorpus, label: Label, seed: int = 0, alpha: float = 0.05) -> HypothesisResult:
    """H3: one primary task (intent transfer) + causal controls with Holm correction."""
    from esp.bench.prereg import holm  # noqa: PLC0415

    z = encode(c, "taoss", seed=seed)
    ctrl = causal_controls(c, z, seed)
    rejected = holm([p for _, p in ctrl.values()], alpha)
    vals = {f"gap_{k}": g for k, (g, _) in ctrl.items()} | {
        f"p_{k}": p for k, (_, p) in ctrl.items()
    }
    vals["all_controls_significant_holm"] = float(all(rejected))
    vals["taoss_top1"] = intent_transfer(c, z, seed).metrics["top1"]
    vals["mono_top1"] = intent_transfer(c, encode(c, "mono", seed=seed), seed).metrics["top1"]
    ran = {"taoss", "mono"}
    return HypothesisResult(
        "H3", vals, tuple(sorted(ran)), _missing(ran, REQUIRED_BASELINES), label
    )


def smoke_label() -> Label:
    return Label(False, ("smoke data", "no preregistration"))
