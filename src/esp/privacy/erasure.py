# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Masked-type erasure: typing plus concept erasure (follow-up to the GoEmotions H2 study).

The preregistered GoEmotions study (``docs/research/result-goemotions-h2.md``) showed that
typed heads leak less of a masked type than naive masking, but more than concept erasure
(LEACE) or an adversarial filter. Masking a type removes its block from the wire; it does not
remove what the *released* blocks still say about it. This module adds that second step:

- :class:`LeaceEraser` is the closed-form least-squares concept eraser of Belrose et al.
  (2023), ``x' = x - (x - mu) M^T``. It is fitted on **training data only** for one masked
  type and one ordered set of released types. After erasure, no linear predictor of the
  concept beats a constant on the fitting distribution. Nonlinear predictors may still
  succeed, which is why the audit suite keeps measuring residual leakage.
- Every eraser is **versioned**: its digest covers the concept, the released types and
  their dimensions, the fitted parameters and the training-data identifier.
- :class:`ErasureProfile` is applied by the sender after disclosure. When an eraser's
  concept is masked in the disclosed frame, the released latents are erased and the frame
  provenance carries ``erasure:<TYPE>:leace:<digest>``. These declaration references are
  kept even when evidence references are otherwise stripped.
- A declared eraser that cannot be applied (for example, the released types differ) is an
  error. The sender never silently sends un-erased latents under an erasure profile.
- Receivers may require erasure for masked types (``ReceiverHardening.require_erasure``).
  A frame without the declaration is then refused.

No wire change: the declaration travels in the frame provenance (addendum ``0x95``).
"""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Final

import numpy as np
from numpy.typing import NDArray

from esp.core.taoss_types import TaossType
from esp.frame.model import ExperienceFrame, FrameProvenance, TypeBlock

F64 = NDArray[np.float64]
ERASURE_PREFIX: Final = "erasure:"
METHOD: Final = "leace"


class ErasureError(ValueError):
    pass


def erasure_ref(concept: TaossType, digest: str) -> str:
    return f"{ERASURE_PREFIX}{concept.name}:{METHOD}:{digest[:32]}"


def declared_erasures(refs: Sequence[str]) -> frozenset[TaossType]:
    """Types whose erasure a frame's provenance declares."""
    out = set()
    for r in refs:
        if r.startswith(ERASURE_PREFIX):
            name = r[len(ERASURE_PREFIX) :].split(":", 1)[0]
            if name in TaossType.__members__:
                out.add(TaossType[name])
    return frozenset(out)


def leace_fit(x: F64, concept: F64) -> tuple[F64, F64]:
    """Closed-form LEACE parameters ``(mu, M)`` for erasing ``concept`` from ``x``.

    ``M = W^+ P W`` with whitening ``W = Sigma_xx^{-1/2}`` and ``P`` the orthogonal
    projection onto ``span(W Sigma_xz)`` (Belrose et al. 2023).
    """
    x = np.asarray(x, dtype=np.float64)
    z = np.asarray(concept, dtype=np.float64).reshape(len(x), -1)
    if len(x) < 2:
        msg = "LEACE needs at least two training rows"
        raise ErasureError(msg)
    mu = x.mean(0)
    xc, zc = x - mu, z - z.mean(0)
    sxx = xc.T @ xc / (len(x) - 1)
    sxz = xc.T @ zc / (len(x) - 1)
    evals, evecs = np.linalg.eigh(sxx)
    keep = evals > 1e-10 * max(float(evals.max()), 1e-300)
    w = evecs[:, keep] @ np.diag(evals[keep] ** -0.5) @ evecs[:, keep].T
    w_pinv = evecs[:, keep] @ np.diag(evals[keep] ** 0.5) @ evecs[:, keep].T
    u, s, _ = np.linalg.svd(w @ sxz, full_matrices=False)
    u = u[:, s > 1e-10 * s.max()] if s.size and s.max() > 0 else u[:, :0]
    m: F64 = w_pinv @ (u @ u.T) @ w
    return mu, m


@dataclass(frozen=True, slots=True)
class LeaceEraser:
    concept: TaossType
    released: tuple[TaossType, ...]
    dims: tuple[int, ...]
    mean: F64
    matrix: F64
    training_data_id: str

    def __post_init__(self) -> None:
        if self.concept in self.released:
            msg = "the erased concept cannot be one of the released types"
            raise ErasureError(msg)
        d = sum(self.dims)
        if len(self.released) != len(self.dims) or self.mean.shape != (d,):
            msg = "released types, dimensions and mean do not match"
            raise ErasureError(msg)
        if self.matrix.shape != (d, d) or not np.isfinite(self.matrix).all():
            msg = "eraser matrix must be finite and square in the released dimension"
            raise ErasureError(msg)
        if not self.training_data_id:
            msg = "an eraser must name its training data"
            raise ErasureError(msg)

    @classmethod
    def fit(
        cls,
        released: Sequence[F64],
        concept_values: F64,
        *,
        concept: TaossType,
        released_types: Sequence[TaossType],
        training_data_id: str,
    ) -> LeaceEraser:
        """Fit on training rows: ``released`` holds one ``(n, d_t)`` array per released type."""
        blocks = [np.asarray(b, dtype=np.float64) for b in released]
        x = np.concatenate(blocks, axis=1)
        mu, m = leace_fit(x, concept_values)
        return cls(
            concept=concept,
            released=tuple(released_types),
            dims=tuple(b.shape[1] for b in blocks),
            mean=mu,
            matrix=m,
            training_data_id=training_data_id,
        )

    @property
    def digest(self) -> str:
        h = hashlib.blake2b(digest_size=32)
        h.update(b"esp/v1/erasure/leace")
        h.update(self.concept.name.encode())
        h.update(
            ",".join(
                f"{t.name}:{d}" for t, d in zip(self.released, self.dims, strict=True)
            ).encode()
        )
        h.update(np.ascontiguousarray(self.mean, dtype=">f8").tobytes())
        h.update(np.ascontiguousarray(self.matrix, dtype=">f8").tobytes())
        h.update(self.training_data_id.encode())
        return h.hexdigest()

    @property
    def ref(self) -> str:
        return erasure_ref(self.concept, self.digest)

    def apply(self, x: F64) -> F64:
        """Erase from ``(n, d)`` (or ``(d,)``) concatenated released latents."""
        arr = np.asarray(x, dtype=np.float64)
        out: F64 = arr - (arr - self.mean) @ self.matrix.T
        return out


@dataclass(frozen=True, slots=True)
class ErasureProfile:
    """The sender's declared erasers, one per maskable concept type."""

    erasers: tuple[LeaceEraser, ...]

    def __post_init__(self) -> None:
        concepts = [e.concept for e in self.erasers]
        if not concepts or len(set(concepts)) != len(concepts):
            msg = "an erasure profile needs one eraser per concept type"
            raise ErasureError(msg)

    def apply(self, frame: ExperienceFrame) -> ExperienceFrame:
        """Erase every masked concept from the released latents and declare it."""
        masked = set(frame.masked_types)
        latents = {b.type: b for b in frame.types if b.latent is not None}
        refs = list(frame.provenance.evidence_refs)
        for e in self.erasers:
            if e.concept not in masked:
                continue  # the concept is disclosed: nothing to erase
            present = tuple(sorted(latents, key=lambda t: t.value))
            if present != e.released:
                got, want = [t.name for t in present], [t.name for t in e.released]
                msg = f"eraser for {e.concept.name} expects released {want}, frame has {got}"
                raise ErasureError(msg)
            vecs = [np.asarray(latents[t].latent, dtype=np.float64) for t in e.released]
            if tuple(v.shape[0] for v in vecs) != e.dims:
                msg = f"eraser for {e.concept.name}: latent dimensions differ"
                raise ErasureError(msg)
            erased = e.apply(np.concatenate(vecs))
            start = 0
            for t, d in zip(e.released, e.dims, strict=True):
                latents[t] = latents[t].model_copy(
                    update={"latent": tuple(float(v) for v in erased[start : start + d])}
                )
                start += d
            refs.append(e.ref)
        if len(refs) == len(frame.provenance.evidence_refs):
            return frame
        blocks: list[TypeBlock] = [latents.get(b.type, b) for b in frame.types]
        provenance = FrameProvenance(
            encoder_id=frame.provenance.encoder_id,
            model_digest=frame.provenance.model_digest,
            evidence_refs=tuple(refs),
        )
        return frame.model_copy(update={"types": tuple(blocks), "provenance": provenance})


def missing_erasures(
    frame: ExperienceFrame, required: frozenset[TaossType]
) -> frozenset[TaossType]:
    """Required masked types whose erasure the frame does not declare."""
    masked = frozenset(frame.masked_types) & required
    return masked - declared_erasures(frame.provenance.evidence_refs)
