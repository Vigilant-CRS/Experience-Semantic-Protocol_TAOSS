# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Anchor projection ``π_t`` (WP-050; V13 section 5.4, definition "anchor coordinates").

``π_t(E_t) = (s_1, …, s_m)`` with ``s_i`` a similarity to the encoder-specific
realization ``a_i`` of anchor ``i`` (in anchor-set order):

- ``COSINE``: ``<z, a> / (|z| |a|)``;
- ``PROJECTION``: least-squares coefficients ``c = A^+ z`` of ``z`` on the anchor
  span, normalized as ``c / max(1, max|c|)`` so they stay in ``[-1, 1]``
  (invariant to components orthogonal to every anchor);
- ``RBF``: ``exp(-gamma |z - a|^2)``.

Coordinates are computed in float64 and rounded to binary32 (the wire
precision), so identical inputs give bit-identical coordinates. Three modes
(V13): coordinates *alongside* latents, *instead of* latents
(interpretation-only), or computed *locally* by the receiver from a
received latent and the pinned anchor set. Anchors are not the latent
state: different latents can share coordinates.
"""

from __future__ import annotations

from collections.abc import Sequence
from enum import IntEnum, StrEnum, unique

import numpy as np

from esp.core.taoss_types import TaossType
from esp.frame.model import AnchorCoordinate, ExperienceFrame, TypeBlock
from esp.ontology.registry import Registry


@unique
class SimilarityKind(IntEnum):
    COSINE = 0
    PROJECTION = 1
    RBF = 2


class Mode(StrEnum):
    ALONGSIDE = "alongside"
    INSTEAD = "instead"


class ProjectionError(ValueError):
    pass


def realizations_for(
    registry: Registry, anchor_set_id: str, encoder_id: str
) -> list[tuple[str, np.ndarray]]:
    """Realization vectors of one encoder, in anchor-set order (all anchors required)."""
    anchor_set = registry.anchor_set(anchor_set_id)
    by_anchor = {r.anchor_id: r for r in registry.realizations if r.encoder_id == encoder_id}
    missing = [a for a in anchor_set.anchors if a not in by_anchor]
    if missing:
        msg = f"encoder {encoder_id} has no realization for {missing}"
        raise ProjectionError(msg)
    return [(a, np.asarray(by_anchor[a].vector, dtype=np.float64)) for a in anchor_set.anchors]


def project(
    latent: Sequence[float],
    anchors: Sequence[tuple[str, np.ndarray]],
    kind: SimilarityKind = SimilarityKind.COSINE,
    *,
    gamma: float = 0.5,
) -> tuple[AnchorCoordinate, ...]:
    z = np.asarray(latent, dtype=np.float64)
    ids = [anchor_id for anchor_id, _ in anchors]
    basis = np.stack([a for _, a in anchors])
    if basis.shape[1] != z.shape[0]:
        msg = "latent and realization dimensions differ"
        raise ProjectionError(msg)
    if kind is SimilarityKind.COSINE:
        norms = np.linalg.norm(basis, axis=1) * np.linalg.norm(z)
        sims = np.where(norms > 0, (basis @ z) / np.where(norms > 0, norms, 1.0), 0.0)
    elif kind is SimilarityKind.PROJECTION:
        coef = np.linalg.lstsq(basis.T, z, rcond=None)[0]
        sims = coef / max(1.0, float(np.max(np.abs(coef))))
    else:
        sims = np.exp(-gamma * np.sum((basis - z) ** 2, axis=1))
    out = [
        AnchorCoordinate(anchor_id=a, similarity=float(np.float32(np.clip(v, -1.0, 1.0))))
        for a, v in zip(ids, sims, strict=True)
    ]
    return tuple(out)


def with_anchor_coordinates(
    frame: ExperienceFrame,
    t: TaossType,
    registry: Registry,
    anchor_set_id: str,
    encoder_id: str,
    *,
    mode: Mode = Mode.ALONGSIDE,
    kind: SimilarityKind = SimilarityKind.COSINE,
) -> ExperienceFrame:
    block = frame.block(t)
    if block is None or block.latent is None:
        msg = f"frame has no {t.name} latent to project"
        raise ProjectionError(msg)
    coords = project(block.latent, realizations_for(registry, anchor_set_id, encoder_id), kind)
    new = TypeBlock.model_validate(
        block.model_dump()
        | {
            "anchor_set_id": anchor_set_id,
            "anchors": coords,
            "similarity_kind": kind.name.lower(),
            "latent": block.latent if mode is Mode.ALONGSIDE else None,
        }
    )
    blocks = tuple(new if b.type is t else b for b in frame.types)
    return ExperienceFrame.model_validate(frame.model_dump() | {"types": blocks})


def local_coordinates(  # noqa: PLR0917 - mirrors with_anchor_coordinates
    frame: ExperienceFrame,
    t: TaossType,
    registry: Registry,
    anchor_set_id: str,
    encoder_id: str,
    kind: SimilarityKind = SimilarityKind.COSINE,
) -> tuple[AnchorCoordinate, ...]:
    """Receiver-side mode: compute coordinates from a received latent and the pinned set."""
    block = frame.block(t)
    if block is None or block.latent is None:
        msg = f"no {t.name} latent received"
        raise ProjectionError(msg)
    return project(block.latent, realizations_for(registry, anchor_set_id, encoder_id), kind)
