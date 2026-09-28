# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Content-side affect pipeline (WP-079; V13 section 6.4, eq. affect).

``A_t = alpha_a * g_audio(a_t) + alpha_f * g_face(Phi_face(v_t)) + alpha_s * g_text(s_t)``

- ``alpha = softmax(w)``, renormalized per time step over the modalities that are
  present; the **face gate** sets ``alpha_f = 0`` where no face is detected;
- extractors ``g_*`` are pluggable (vendor-implemented, typically pretrained);
- the curve is smoothed with a Gaussian kernel;
- the output is always ``affect_scope = CONTENT``: it describes what the
  media *expresses*, never a viewer's state. Using it to infer a natural
  person's emotion would be subject affect (L2, WP-081) and is out of scope here.

Extractors return per-step ``(valence, arousal)`` arrays of shape ``(T, 2)``
with valence in [-1, 1] and arousal in [0, 1].
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final, Protocol

import numpy as np
from numpy.typing import NDArray

from esp.core.provenance import AffectScope, Provenance, SourceKind
from esp.semantics.affect import AffectiveDescriptor

F64 = NDArray[np.float64]
MODALITIES: Final = ("audio", "face", "text")
PRODUCER: Final = "esp-content-affect"
VERSION: Final = "0.1.0"


class AffectExtractor(Protocol):
    @property
    def extractor_id(self) -> str: ...

    def extract(self, segment: object) -> F64:
        """Per-step (valence, arousal), shape (T, 2)."""
        ...


@dataclass(frozen=True, slots=True)
class ContentAffectCurve:
    valence: F64
    arousal: F64
    weights: F64
    """Effective per-step weights, shape (T, 3) in MODALITIES order."""
    extractors: tuple[str, ...]


def _gaussian_smooth(x: F64, sigma: float) -> F64:
    if sigma <= 0 or x.size < 2:
        return x
    radius = max(1, int(3 * sigma))
    k = np.exp(-0.5 * (np.arange(-radius, radius + 1) / sigma) ** 2)
    k /= k.sum()
    padded = np.pad(x, radius, mode="edge")
    return np.convolve(padded, k, mode="valid")


class ContentAffectPipeline:
    def __init__(
        self,
        extractors: Mapping[str, AffectExtractor],
        w: Mapping[str, float] | None = None,
        sigma: float = 2.0,
    ) -> None:
        unknown = set(extractors) - set(MODALITIES)
        if unknown:
            msg = f"unknown modalities {sorted(unknown)}"
            raise ValueError(msg)
        self._extractors = dict(extractors)
        self._w = np.array([(w or {}).get(m, 0.0) for m in MODALITIES])
        self._sigma = sigma

    def curve(
        self, segments: Mapping[str, object], face_present: NDArray[np.bool_] | None = None
    ) -> ContentAffectCurve:
        outs: dict[str, F64] = {}
        for m, ex in self._extractors.items():
            if m in segments and segments[m] is not None:
                va = np.asarray(ex.extract(segments[m]), dtype=np.float64)
                if va.ndim != 2 or va.shape[1] != 2:
                    msg = f"{m} extractor must return shape (T, 2)"
                    raise ValueError(msg)
                outs[m] = va
        if not outs:
            msg = "no modality produced an affect curve"
            raise ValueError(msg)
        t = {v.shape[0] for v in outs.values()}
        if len(t) != 1:
            msg = "all modality curves must have the same length"
            raise ValueError(msg)
        n = t.pop()
        present = np.stack([np.full(n, m in outs) for m in MODALITIES], axis=1)
        if face_present is not None:
            present[:, MODALITIES.index("face")] &= np.asarray(
                face_present, dtype=bool
            )  # face gate
        logits = np.where(present, self._w[None, :], -np.inf)
        with np.errstate(invalid="ignore"):
            alpha = np.exp(logits - np.max(logits, axis=1, keepdims=True))
            alpha /= alpha.sum(axis=1, keepdims=True)
        alpha = np.nan_to_num(alpha)  # steps where nothing is present get zero weight
        stacked = np.stack([outs.get(m, np.zeros((n, 2))) for m in MODALITIES], axis=1)  # (T, 3, 2)
        combined = np.einsum("tm,tmc->tc", alpha, stacked)
        return ContentAffectCurve(
            valence=np.clip(_gaussian_smooth(combined[:, 0], self._sigma), -1.0, 1.0),
            arousal=np.clip(_gaussian_smooth(combined[:, 1], self._sigma), 0.0, 1.0),
            weights=alpha,
            extractors=tuple(sorted(self._extractors[m].extractor_id for m in outs)),
        )

    def descriptor(
        self,
        curve: ContentAffectCurve,
        segment_ref: str,
        vocabulary_id: str = "esp-emo-v13-basic8-v1",
    ) -> AffectiveDescriptor:
        """Segment-level content affect (mean of the curve), always ``affect_scope=CONTENT``."""
        return AffectiveDescriptor(
            vocabulary_id=vocabulary_id,
            affect_scope=AffectScope.CONTENT,
            provenance=Provenance(
                source_kind=SourceKind.DERIVED,
                producer_id=PRODUCER,
                producer_version=VERSION,
                source_refs=(
                    segment_ref,
                    *(f"extractor:{e.replace('@', '.')}" for e in curve.extractors),
                ),
            ),
            valence=float(np.mean(curve.valence)),
            arousal=float(np.mean(curve.arousal)),
        )


def segment_ref(media_id: str, start_s: float, end_s: float) -> str:
    return f"media.{media_id}.{int(start_s * 1000)}-{int(end_s * 1000)}ms"


def new_media_id() -> str:
    return uuid.uuid4().hex[:12]
