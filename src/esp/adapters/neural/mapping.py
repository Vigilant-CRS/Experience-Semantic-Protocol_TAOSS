# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Neural→TAOSS mapping profile ``esp-neural-mapping-v1`` and reference decoders (M18, WP-089).

A neural decoder produces **task-defined proxy targets**, not thoughts. The
mapping profile fixes which target may populate which TAOSS type:

| Target kind | TAOSS | Why |
|---|---|---|
| ``ATTEMPTED_MOVEMENT`` (decoded velocity or goal) | INT | attempted action = goal by design |
| ``GRASP_STATE`` | INT | intended grasp or release |
| ``HANDWRITING_SYMBOL`` | INT | intended communicative symbol |
| ``SPEECH_ARTICULATION`` | INT | intended articulation (communication goal) |
| ``MEASURED_KINEMATICS`` | SEN | measured body state, **not** intention |
| ``NATURAL_MOVEMENT`` (pose) | SEN | measured body state |
| ``TASK_CONTEXT`` | CTX | cue, block or condition |
| ``TIMING`` | TEM | phase, onset or rhythm |

**EMO and KNO are never populated from neural features.** No v1 target kind
maps to them, and :func:`check_mapping` rejects any profile that tries.

Decoded vectors are embedded into the L1 type dimension ``d_t`` by a fixed,
seeded orthonormal embedding (``esp-neural-embed-v1``), so the wire carries
standard typed latents. The embedding is documented as a transport
placeholder, not a trained TAOSS encoder.

Reference decoder: :class:`RidgeDecoder`, a linear Wiener filter over lagged
features fitted in closed form. Its calibration digest is part of its id, so
every recalibration is versioned.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

import numpy as np
from numpy.typing import NDArray

from esp.adapters.neural.interface import NeuralFeatures
from esp.core.provenance import Provenance, SourceKind
from esp.core.taoss_types import L1_DIMS, TaossType

F64 = NDArray[np.float64]
PROFILE_ID: Final = "esp-neural-mapping-v1"
EMBED_ID: Final = "esp-neural-embed-v1"
NEVER_FROM_NEURAL: Final = frozenset({TaossType.EMO, TaossType.KNO})


class TargetKind(StrEnum):
    ATTEMPTED_MOVEMENT = "attempted_movement"
    GRASP_STATE = "grasp_state"
    HANDWRITING_SYMBOL = "handwriting_symbol"
    SPEECH_ARTICULATION = "speech_articulation"
    MEASURED_KINEMATICS = "measured_kinematics"
    NATURAL_MOVEMENT = "natural_movement"
    TASK_CONTEXT = "task_context"
    TIMING = "timing"


V1_RULES: Final[Mapping[TargetKind, TaossType]] = {
    TargetKind.ATTEMPTED_MOVEMENT: TaossType.INT,
    TargetKind.GRASP_STATE: TaossType.INT,
    TargetKind.HANDWRITING_SYMBOL: TaossType.INT,
    TargetKind.SPEECH_ARTICULATION: TaossType.INT,
    TargetKind.MEASURED_KINEMATICS: TaossType.SEN,
    TargetKind.NATURAL_MOVEMENT: TaossType.SEN,
    TargetKind.TASK_CONTEXT: TaossType.CTX,
    TargetKind.TIMING: TaossType.TEM,
}


class MappingError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class MappingProfile:
    rules: Mapping[TargetKind, TaossType] = field(default_factory=lambda: dict(V1_RULES))
    profile_id: str = PROFILE_ID

    def digest(self) -> str:
        body = ";".join(f"{k.value}={v.name}" for k, v in sorted(self.rules.items()))
        return hashlib.blake2b(f"{self.profile_id}|{body}".encode(), digest_size=32).hexdigest()


def check_mapping(profile: MappingProfile) -> None:
    """A mapping may only use v1 target kinds, with their v1 type, and never EMO or KNO."""
    for kind, t in profile.rules.items():
        if t in NEVER_FROM_NEURAL:
            msg = f"{kind.value} -> {t.name}: {t.name} is never populated from neural features"
            raise MappingError(msg)
        if V1_RULES.get(kind) is not t:
            msg = f"{kind.value} -> {t.name} deviates from {PROFILE_ID}"
            raise MappingError(msg)


def embedding(t: TaossType, in_dim: int) -> F64:
    """Fixed orthonormal ``(d_t, in_dim)`` embedding, seeded by ``EMBED_ID``, type and width."""
    d = L1_DIMS[t]
    if in_dim > d:
        msg = f"{t.name}: {in_dim} target dimensions exceed d_t = {d}"
        raise MappingError(msg)
    seed = int.from_bytes(
        hashlib.blake2b(f"{EMBED_ID}|{t.name}|{in_dim}".encode(), digest_size=8).digest(), "big"
    )
    q, _ = np.linalg.qr(np.random.default_rng(seed).normal(size=(d, in_dim)))
    out: F64 = q[:, :in_dim]
    return out


def to_typed(profile: MappingProfile, targets: Mapping[TargetKind, F64]) -> dict[TaossType, F64]:
    """Map decoded targets to typed L1 latents (targets of one type are concatenated in order)."""
    check_mapping(profile)
    grouped: dict[TaossType, list[F64]] = {}
    for kind in sorted(targets):
        if kind not in profile.rules:
            msg = f"target {kind.value} is not in the mapping profile"
            raise MappingError(msg)
        vec = np.asarray(targets[kind], dtype=np.float64).ravel()
        if not np.isfinite(vec).all():
            msg = f"target {kind.value} is not finite"
            raise MappingError(msg)
        grouped.setdefault(profile.rules[kind], []).append(vec)
    out = {}
    for t, parts in grouped.items():
        v = np.concatenate(parts)
        out[t] = embedding(t, v.size) @ v
    return out


# --- reference decoder ---------------------------------------------------------------------------


def lagged(x: F64, lags: int) -> F64:
    """Stack ``x[t], x[t-1], …, x[t-lags]`` (zero-padded at the start), shape (T, C·(lags+1))."""
    cols = [x]
    for k in range(1, lags + 1):
        shifted = np.zeros_like(x)
        shifted[k:] = x[:-k]
        cols.append(shifted)
    return np.concatenate(cols, axis=1)


def r2_score(y: F64, pred: F64) -> float:
    """Variance-weighted R² over all target dimensions."""
    ss_res = float(np.sum((y - pred) ** 2))
    ss_tot = float(np.sum((y - y.mean(axis=0)) ** 2))
    return 1.0 - ss_res / ss_tot if ss_tot > 0 else 0.0


@dataclass
class RidgeDecoder:
    """Linear Wiener filter ``y_t = W · [x_t, …, x_{t-L}] + b``, closed-form ridge fit."""

    target: TargetKind
    lags: int = 5
    alpha: float = 1.0
    weights: F64 | None = None
    bias: F64 | None = None
    x_mean: F64 | None = None
    x_std: F64 | None = None
    calibration: str = ""

    def fit(self, x: F64, y: F64, *, session_ids: Sequence[str] = ()) -> RidgeDecoder:
        z = lagged(np.asarray(x, dtype=np.float64), self.lags)
        self.x_mean, self.x_std = z.mean(axis=0), z.std(axis=0) + 1e-9
        zs = (z - self.x_mean) / self.x_std
        y = np.asarray(y, dtype=np.float64).reshape(len(zs), -1)
        self.bias = y.mean(axis=0)
        a = zs.T @ zs + self.alpha * np.eye(zs.shape[1])
        self.weights = np.linalg.solve(a, zs.T @ (y - self.bias))
        h = hashlib.blake2b(digest_size=16)
        for arr in (self.weights, self.bias, self.x_mean, self.x_std):
            h.update(np.ascontiguousarray(arr).tobytes())
        h.update("|".join(session_ids).encode())
        self.calibration = h.hexdigest()
        return self

    @property
    def decoder_id(self) -> str:
        return f"esp-ridge-{self.target.value}@{self.calibration[:12] or 'unfitted'}"

    def predict(self, x: F64) -> F64:
        if self.weights is None or self.bias is None or self.x_mean is None or self.x_std is None:
            msg = "decoder is not calibrated"
            raise MappingError(msg)
        z = (lagged(np.asarray(x, dtype=np.float64), self.lags) - self.x_mean) / self.x_std
        out: F64 = z @ self.weights + self.bias
        return out


@dataclass
class MappedNeuralDecoder:
    """Adapts target decoders to the V13 ``f_decode`` boundary through a mapping profile.

    ``decode`` expects the features of one window whose values are the latest
    ``lags + 1`` feature rows flattened in time order (oldest first). The
    boundary check (:func:`~esp.adapters.neural.interface.decode_boundary`)
    validates the output.
    """

    decoders: Sequence[RidgeDecoder]
    profile: MappingProfile = field(default_factory=MappingProfile)
    n_features: int = 0
    version: str = "1.0.0"

    def __post_init__(self) -> None:
        check_mapping(self.profile)
        kinds = [d.target for d in self.decoders]
        if len(set(kinds)) != len(kinds) or not kinds:
            msg = "one decoder per target kind"
            raise MappingError(msg)

    @property
    def decoder_id(self) -> str:
        return "+".join(d.decoder_id for d in self.decoders)

    @property
    def output_types(self) -> frozenset[TaossType]:
        return frozenset(self.profile.rules[d.target] for d in self.decoders)

    def decode(self, features: NeuralFeatures, types: frozenset[TaossType]) -> dict[TaossType, F64]:
        if self.n_features <= 0 or features.values.size % self.n_features:
            msg = "feature window does not match the decoder's feature count"
            raise MappingError(msg)
        window = features.values.reshape(-1, self.n_features)
        targets = {
            d.target: d.predict(window)[-1]
            for d in self.decoders
            if self.profile.rules[d.target] in types
        }
        return to_typed(self.profile, targets)

    def provenance(self, source_refs: Sequence[str]) -> Provenance:
        return Provenance(
            source_kind=SourceKind.MODEL_INFERENCE,
            producer_id="esp-neural-ridge",
            producer_version=self.version,
            source_refs=tuple(source_refs),
        )
