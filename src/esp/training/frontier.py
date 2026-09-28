# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Type-discovery frontier and ablations (WP-074; V13 eq. frontier). EXPLORATORY.

``max_{T_K} Utility_T(T_K) - lambda_p * Leak_V(T_K)`` over the decompositions of
:mod:`esp.training.type_profiles` (K = 3, 6, 8, 12), on a **synthetic world**:
twelve semantic atoms with planted dependence (siblings within a TAOSS-6 type,
and three cross-type couplings: readiness-arousal, arousal-social context,
auditory-rhythm), mixed into three modalities.

- ``Utility_T``: R^2 of the typed latents against their typed targets on an
  independent evaluation draw, pooled over all 36 target dimensions (the same
  total for every profile);
- ``Leak_V``: the fixed-null predictive V-information ladder of
  :func:`esp.audit.suite.v_information_ladder` (linear and quadratic probes) for
  every directed type pair, **in bits per masked dimension** so profiles with
  different type sizes are comparable. V13 aggregates over directed pairs (the
  mean enters the objective); the max and the joint criterion (each type from
  all the others) are reported separately and the frontier is recomputed under
  each, because the mean dilutes as K grows (most fine-grained pairs are
  uncoupled). The leakage already present in the targets is reported as
  ``inherent``;
- privacy granularity: which V13 consent scenarios each profile can express.

Ablations (TAOSS-6):

- covariance-only vs adversarial-only vs both vs neither;
- EMO default-masked: V-information of EMO from all visible types, and R^2 of
  the EMO *content* from the visible latents vs from the visible targets;
- width of the shared pooled vector (``d_model`` 32 < sum d_t = 36, 48, 96):
  every head reads the same pooled vector, so a narrow one makes each type a
  near-linear function of the others (joint leakage the pairwise penalties do
  not address);
- per-session pseudonyms on/off: who can link a subject's two sessions, by
  sender id or (with pseudonyms) only by content, for several strengths of a
  subject signature, including none (negative control).

Everything here is exploratory: synthetic data, no preregistration, no
H1/H2/H3 claim (:func:`esp.bench.prereg.label_run` would label it exploratory).
"""

from __future__ import annotations

import dataclasses
import math
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from itertools import permutations
from typing import Any, Final

import numpy as np
import torch
from numpy.typing import NDArray

from esp.audit.suite import v_information_ladder
from esp.codec.tlv import encode_tlv
from esp.crypto.identity import new_session_identity
from esp.crypto.primitives import SigningKey
from esp.training.encoder import EncoderConfig, TaossEncoder
from esp.training.harness import train_step
from esp.training.leakage import Split as LeakSplit
from esp.training.leakage import probe
from esp.training.stability import StabilityConfig
from esp.training.type_profiles import ATOMS, PROFILES, SCENARIOS, DecompositionProfile

F64 = NDArray[np.float64]
SIBLINGS: Final = tuple(zip(ATOMS[::2], ATOMS[1::2], strict=True))
CROSS: Final = (("INTR", "EMOD"), ("EMOD", "CTXS"), ("SENA", "TEMR"))
LAMBDAS: Final = (0.0, 0.5, 1.0, 2.0, 5.0)
AGGREGATES: Final = ("mean", "max", "joint")
REGULARIZATION: Final = {
    "both": (5.0, 0.1),
    "cov_only": (5.0, 0.0),
    "adv_only": (0.0, 0.1),
    "neither": (0.0, 0.0),
}
OFFSET_SCALES: Final = (0.0, 0.1, 0.25, 0.5)
LABEL: Final = {
    "label": "exploratory",
    "reasons": [
        "no preregistration",
        "synthetic world (planted dependence), not an ExperienceBench corpus",
    ],
    "claims": "NOT preregistered evidence; no H1/H2/H3 claim",
}


@dataclass(frozen=True, slots=True)
class WorldConfig:
    n: int = 1024
    """Training samples."""
    eval_n: int = 4000
    """Independent evaluation draw (V-information probes are sample-hungry)."""
    factor_dim: int = 3
    noise: float = 0.05
    sibling_rho: float = 0.4
    cross_rho: float = 0.25
    seed: int = 1
    modality_dims: Mapping[str, int] = field(
        default_factory=lambda: {"audio": 12, "physio": 8, "text": 16}
    )


@dataclass(frozen=True, slots=True)
class Split:
    factors: dict[str, F64]
    inputs: dict[str, F64]


@dataclass(frozen=True, slots=True)
class World:
    cfg: WorldConfig
    mixing: dict[str, F64]
    train: Split
    eval: Split

    def inputs_for(self, factors: Mapping[str, F64], rng: np.random.Generator) -> dict[str, F64]:
        stacked = np.concatenate([factors[a] for a in ATOMS], axis=1)
        return {
            m: stacked @ w + self.cfg.noise * rng.normal(size=(stacked.shape[0], w.shape[1]))
            for m, w in sorted(self.mixing.items())
        }


def targets(profile: DecompositionProfile, factors: Mapping[str, F64]) -> dict[str, F64]:
    return {
        t: np.concatenate([factors[a] for a in atoms], axis=1) for t, atoms in profile.types.items()
    }


def sample_factors(cfg: WorldConfig, n: int, rng: np.random.Generator) -> dict[str, F64]:
    """Unit-variance atom factors; each coupling ``(a, b, rho)`` gives ``corr(a, b) = rho``."""
    couplings = [(a, b, cfg.sibling_rho) for a, b in SIBLINGS] + [
        (a, b, cfg.cross_rho) for a, b in CROSS
    ]
    load = dict.fromkeys(ATOMS, 0.0)
    factors = {a: np.zeros((n, cfg.factor_dim)) for a in ATOMS}
    for a, b, rho in couplings:
        common = rng.normal(size=(n, cfg.factor_dim))
        for x in (a, b):
            factors[x] += math.sqrt(rho) * common
            load[x] += rho
    if max(load.values()) > 1.0:
        msg = "couplings exceed unit variance"
        raise ValueError(msg)
    for a in ATOMS:
        factors[a] += math.sqrt(1.0 - load[a]) * rng.normal(size=(n, cfg.factor_dim))
    return factors


def make_world(cfg: WorldConfig) -> World:
    rng = np.random.default_rng(cfg.seed)
    width = cfg.factor_dim * len(ATOMS)
    mixing = {
        m: rng.normal(size=(width, d)) / math.sqrt(width)
        for m, d in sorted(cfg.modality_dims.items())
    }
    world = World(cfg, mixing, Split({}, {}), Split({}, {}))
    for split, n in ((world.train, cfg.n), (world.eval, cfg.eval_n)):
        split.factors.update(sample_factors(cfg, n, rng))
        split.inputs.update(world.inputs_for(split.factors, rng))
    return world


def _t(a: F64) -> torch.Tensor:
    return torch.from_numpy(np.ascontiguousarray(a, dtype=np.float32))


def train_encoder(
    profile: DecompositionProfile,
    world: World,
    *,
    lambda_cov: float,
    beta_adv: float,
    steps: int,
    seed: int,
    d_model: int = 48,
    stability: StabilityConfig | None = None,
    batch: int = 64,
    lr: float = 3e-3,
) -> TaossEncoder[str]:
    """Deterministic CPU training of one decomposition on the training draw."""
    torch.use_deterministic_algorithms(True)
    torch.manual_seed(seed)
    st = stability or StabilityConfig()
    fd = world.cfg.factor_dim
    cfg: EncoderConfig[str] = EncoderConfig(
        modality_dims=dict(world.cfg.modality_dims),
        d_model=d_model,
        heads=4,
        type_dims={t: fd * len(atoms) for t, atoms in profile.types.items()},
        disc_hidden=32,
        lambda_cov=lambda_cov,
        beta_adv=beta_adv,
        disc_capacities=st.disc_capacities,
        standardize_fusion_input=st.standardize_fusion_input,
        r_max=None if st.certified is None else st.certified.r_max,
    )
    model = TaossEncoder(cfg)
    opt = torch.optim.Adam(model.parameters(), lr=lr)
    gen = torch.Generator().manual_seed(seed)
    n = world.cfg.n
    xs = {m: _t(x) for m, x in world.train.inputs.items()}
    ys = {t: _t(y) for t, y in targets(profile, world.train.factors).items()}
    per_epoch = max(1, math.ceil(n / batch))
    model.train()
    for step in range(steps):
        idx = torch.randint(0, n, (batch,), generator=gen)
        train_step(
            model,
            opt,
            {m: x[idx] for m, x in xs.items()},
            {t: y[idx] for t, y in ys.items()},
            st,
            step=step,
            steps=steps,
            steps_per_epoch=per_epoch,
            gen=gen,
        )
    return model.eval()


@torch.no_grad()
def encode(model: TaossEncoder[str], inputs: Mapping[str, F64]) -> dict[str, F64]:
    model.eval()
    out = model({m: _t(x) for m, x in inputs.items()})
    return {t: z.numpy().astype(np.float64) for t, z in out.items()}


def utility(latents: Mapping[str, F64], target: Mapping[str, F64]) -> float:
    """Pooled R^2 over all target dimensions."""
    z = np.concatenate([latents[t] for t in target], axis=1)
    y = np.concatenate([target[t] for t in target], axis=1)
    return float(1.0 - np.sum((z - y) ** 2) / np.sum((y - y.mean(0)) ** 2))


def _joint_source(z: Mapping[str, F64], s: str) -> F64:
    return np.concatenate([z[t] for t in z if t != s], axis=1)


def leakage(z: Mapping[str, F64], *, seed: int = 0) -> dict[str, float]:
    """V-information leakage in bits per masked dimension (directed pairs; joint criterion)."""
    directed = {
        (s, t): v_information_ladder(z[t], z[s], degrees=(1, 2), seed=seed)[-1] / z[s].shape[1]
        for s, t in permutations(z, 2)
    }
    joint = [
        v_information_ladder(_joint_source(z, s), z[s], degrees=(1,), seed=seed)[-1] / z[s].shape[1]
        for s in z
    ]
    return {
        "mean": float(np.mean(list(directed.values()))),
        "max": float(max(directed.values())),
        "joint": float(np.mean(joint)),
    }


def evaluate(
    model: TaossEncoder[str], profile: DecompositionProfile, world: World
) -> dict[str, Any]:
    target = targets(profile, world.eval.factors)
    z = encode(model, world.eval.inputs)
    return {"utility": utility(z, target), "leak": leakage(z)}


def _emo_leak(src: Mapping[str, F64], degrees: Sequence[int]) -> float:
    bits = v_information_ladder(_joint_source(src, "EMO"), src["EMO"], degrees=degrees)[-1]
    return float(bits / src["EMO"].shape[1])


def _emo_r2(src: Mapping[str, F64], world: World) -> float:
    target = targets(PROFILES["TAOSS-6"], world.eval.factors)["EMO"]
    return probe(_joint_source(src, "EMO"), target, LeakSplit.fixed(world.cfg.eval_n), n_boot=20).r2


def emo_inherent(world: World, degrees: Sequence[int] = (1, 2)) -> dict[str, float]:
    """What the visible TAOSS-6 *targets* imply about EMO (the world, not the encoder)."""
    target = targets(PROFILES["TAOSS-6"], world.eval.factors)
    return {
        "inherent_emo_leak_bits_per_dim": _emo_leak(target, degrees),
        "emo_target_r2_from_visible_targets": _emo_r2(target, world),
    }


def emo_default_masked(
    model: TaossEncoder[str], world: World, degrees: Sequence[int] = (1, 2)
) -> dict[str, float]:
    """TAOSS-6 with EMO withheld: what the visible types still reveal about EMO.

    Besides V-information of the EMO *latent*, the interpretable consent metric:
    out-of-sample R^2 of the EMO *target* (the emotional content itself) from the
    visible latents; compare with :func:`emo_inherent` (the same probe on the
    visible targets). The difference is encoder-induced leakage.
    """
    target = targets(PROFILES["TAOSS-6"], world.eval.factors)
    z = encode(model, world.eval.inputs)
    visible = [t for t in z if t != "EMO"]
    return {
        "visible_utility": utility({t: z[t] for t in visible}, {t: target[t] for t in visible}),
        "emo_leak_bits_per_dim": _emo_leak(z, degrees),
        "emo_target_r2_from_visible_latents": _emo_r2(z, world),
    }


def pseudonym_linkage(
    model: TaossEncoder[str],
    world: World,
    *,
    subjects: int = 20,
    frames: int = 16,
    offset_scales: Sequence[float] = OFFSET_SCALES,
    seed: int = 0,
) -> dict[str, Any]:
    """Can an observer link a subject's two sessions? By sender id, else by (visible) content.

    Each subject has a stable input signature (an offset per modality, scaled by
    ``offset_scale``; 0 is the negative control). Without per-session pseudonyms
    the sender id is stable and links trivially; with them (fresh Ed25519 keys,
    :func:`esp.crypto.identity.new_session_identity`) only the EMO-masked content
    remains to link on (V13 threat T9 residual).
    """

    def id_linked(first: Sequence[bytes], second: Sequence[bytes]) -> float:
        hits = [
            second.count(first[i]) == 1 and second.index(first[i]) == i for i in range(subjects)
        ]
        return float(np.mean(hits))

    stable = [SigningKey.from_seed(bytes([i + 1]) * 32).public_bytes for i in range(subjects)]
    fresh = [[new_session_identity().public_bytes for _ in range(subjects)] for _ in (0, 1)]
    off, on = id_linked(stable, stable), id_linked(*fresh)
    content: dict[str, float] = {}
    for scale in offset_scales:
        rng = np.random.default_rng(seed + 7919)
        offsets = {
            m: scale * rng.normal(size=(subjects, d)) for m, d in world.cfg.modality_dims.items()
        }
        means: list[list[F64]] = [[], []]
        for session in (0, 1):
            for i in range(subjects):
                inputs = world.inputs_for(sample_factors(world.cfg, frames, rng), rng)
                z = encode(model, {m: x + offsets[m][i] for m, x in inputs.items()})
                means[session].append(
                    np.concatenate([v.mean(0) for t, v in z.items() if t != "EMO"])
                )
        a, b = np.array(means[0]), np.array(means[1])
        both = np.concatenate([a, b])
        mu, sd = both.mean(0), both.std(0) + 1e-12
        a, b = (a - mu) / sd, (b - mu) / sd
        nearest = np.argmin(((a[:, None, :] - b[None, :, :]) ** 2).sum(-1), axis=1)
        content[f"{scale:g}"] = float(np.mean(nearest == np.arange(subjects)))
    return {
        "subjects": subjects,
        "chance": 1.0 / subjects,
        "pseudonyms_off": {"linked_by_id": off},
        "pseudonyms_on": {"linked_by_id": on, "content_accuracy_by_offset_scale": content},
    }


@dataclass(frozen=True, slots=True)
class FrontierConfig:
    steps: int = 300
    seeds: tuple[int, ...] = (0,)
    world: WorldConfig = field(default_factory=WorldConfig)
    lambdas: tuple[float, ...] = LAMBDAS
    d_model: int = 48
    """> sum of type dims (36), so the rank-bottleneck ablation is the only bottlenecked run."""
    stable: bool = False
    """Train with :meth:`StabilityConfig.recommended` (slower) instead of plain GRL training."""
    emo_degrees: tuple[int, ...] = (1, 2)
    """Probe ladder for the EMO default-masked V-information (degree 2 on 30 inputs is costly)."""


def _frontier(profiles: Mapping[str, Mapping[str, Any]], lambdas: Sequence[float]) -> list[Any]:
    rows = []
    for aggregate in AGGREGATES:
        for lp in lambdas:
            scores = {n: p["utility"] - lp * p["leak"][aggregate] for n, p in profiles.items()}
            best = max(scores, key=lambda n: scores[n])
            rows.append({"aggregate": aggregate, "lambda_p": lp, "scores": scores, "best": best})
    return rows


def run(cfg: FrontierConfig) -> dict[str, Any]:
    """The frontier and all ablations; a JSON-serializable, exploratory result."""
    world = make_world(cfg.world)
    st = StabilityConfig.recommended() if cfg.stable else StabilityConfig()
    st = dataclasses.replace(st, early_stop=None)  # the frontier loop has no holdout
    lam, beta = REGULARIZATION["both"]

    def train(
        profile: DecompositionProfile,
        seed: int,
        *,
        lambda_cov: float = lam,
        beta_adv: float = beta,
        d_model: int = cfg.d_model,
    ) -> TaossEncoder[str]:
        return train_encoder(
            profile,
            world,
            lambda_cov=lambda_cov,
            beta_adv=beta_adv,
            d_model=d_model,
            steps=cfg.steps,
            seed=seed,
            stability=st,
        )

    profiles: dict[str, Any] = {}
    models: dict[tuple[str, int], TaossEncoder[str]] = {}
    for name, profile in PROFILES.items():
        runs = []
        for seed in cfg.seeds:
            models[(name, seed)] = train(profile, seed)
            runs.append(evaluate(models[(name, seed)], profile, world))
        tlv = profile.tlv()
        profiles[name] = {
            "k": profile.k,
            "profile_id": str(profile.profile_id),
            "registry_digest": profile.digest().hex(),
            "type_profile_tlv": encode_tlv(tlv.code, tlv.value).hex(),
            "types": {t: list(a) for t, a in profile.types.items()},
            "utility": float(np.mean([r["utility"] for r in runs])),
            "utility_sd": float(np.std([r["utility"] for r in runs])),
            "leak": {a: float(np.mean([r["leak"][a] for r in runs])) for a in AGGREGATES},
            "inherent_leak": leakage(targets(profile, world.eval.factors)),
            "scenarios_expressible": {s: profile.expressible(a) for s, a in SCENARIOS.items()},
            "per_seed": runs,
        }
    six, seed0 = PROFILES["TAOSS-6"], cfg.seeds[0]
    regularization: dict[str, Any] = {}
    masked: dict[str, Any] = {}
    for name, (lc, ba) in REGULARIZATION.items():
        model = (
            models[("TAOSS-6", seed0)]
            if name == "both"
            else train(six, seed0, lambda_cov=lc, beta_adv=ba)
        )
        result = evaluate(model, six, world)
        regularization[name] = {
            "lambda_cov": lc,
            "beta_adv": ba,
            "utility": result["utility"],
            "leak": result["leak"],
        }
        masked[name] = emo_default_masked(model, world, cfg.emo_degrees)
    bottleneck = {
        cfg.d_model: {
            "utility": regularization["both"]["utility"],
            "leak": regularization["both"]["leak"],
            "emo_masked": masked["both"],
        }
    }
    for d in (32, 2 * cfg.d_model):  # 32 < sum of TAOSS-6 type dims (36)
        m = train(six, seed0, d_model=d)
        r = evaluate(m, six, world)
        bottleneck[d] = {
            "utility": r["utility"],
            "leak": r["leak"],
            "emo_masked": emo_default_masked(m, world, cfg.emo_degrees),
        }
    return {
        **LABEL,
        "wp": "WP-074",
        "config": asdict(cfg),
        "objective": "Utility_T - lambda_p * Leak_V; Leak_V in bits per masked dimension",
        "profiles": profiles,
        "frontier": _frontier(profiles, cfg.lambdas),
        "ablations": {
            "regularization": regularization,
            "emo_default_masked": masked,
            "emo_inherent": emo_inherent(world, cfg.emo_degrees),
            "rank_bottleneck": {
                "sum_type_dims": 36,
                **{f"d_model={d}": bottleneck[d] for d in sorted(bottleneck)},
            },
            "pseudonyms": pseudonym_linkage(models[("TAOSS-6", seed0)], world, seed=seed0),
        },
    }
