# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Receiver-side output space ``Y`` as a tagged union (V13 section 7.2).

Each variant has a comparison functional ``d_Y``. Not every functional is a
metric (V13: "no claim is made that every admissible d_Y satisfies the
axioms of a metric"); cosine dissimilarity, for instance, is not.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from enum import StrEnum

import numpy as np


class OutputTag(StrEnum):
    TEXT = "text"
    VECTOR = "vector"
    MEDIA = "media"
    ACTION = "action"


@dataclass(frozen=True, slots=True)
class TextOutput:
    text: str
    tag: OutputTag = OutputTag.TEXT


@dataclass(frozen=True, slots=True)
class VectorOutput:
    values: tuple[float, ...]
    tag: OutputTag = OutputTag.VECTOR


@dataclass(frozen=True, slots=True)
class MediaOutput:
    """A pixel array ``H x W x C`` or a waveform ``N x 1`` (row-major, float in [0, 1])."""

    shape: tuple[int, ...]
    data: tuple[float, ...]
    tag: OutputTag = OutputTag.MEDIA

    def __post_init__(self) -> None:
        if math.prod(self.shape) != len(self.data):
            msg = "media shape does not match data length"
            raise ValueError(msg)


@dataclass(frozen=True, slots=True)
class ActionOutput:
    discrete: tuple[int, ...] = ()
    continuous: tuple[float, ...] = ()
    tag: OutputTag = OutputTag.ACTION


Output = TextOutput | VectorOutput | MediaOutput | ActionOutput


def edit_distance(a: str, b: str) -> float:
    """Normalized Levenshtein distance in [0, 1]."""
    if a == b:
        return 0.0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1] / max(len(a), len(b))


def l2(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    return float(np.linalg.norm(np.asarray(a) - np.asarray(b)))


def cosine_dissimilarity(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    """``1 - cos``; not a metric (no triangle inequality)."""
    x, y = np.asarray(a), np.asarray(b)
    nx, ny = float(np.linalg.norm(x)), float(np.linalg.norm(y))
    if nx == 0.0 or ny == 0.0:
        return 0.0 if nx == ny else 1.0
    return 1.0 - float(x @ y) / (nx * ny)


def ssim_dissimilarity(a: MediaOutput, b: MediaOutput) -> float:
    """``(1 - SSIM) / 2`` with global statistics (constants for data range 1)."""
    if a.shape != b.shape:
        return 1.0
    x, y = np.asarray(a.data), np.asarray(b.data)
    c1, c2 = 0.01**2, 0.03**2
    mx, my = x.mean(), y.mean()
    vx, vy = x.var(), y.var()
    cov = float(((x - mx) * (y - my)).mean())
    ssim = ((2 * mx * my + c1) * (2 * cov + c2)) / ((mx**2 + my**2 + c1) * (vx + vy + c2))
    return float((1.0 - ssim) / 2.0)


def action_distance(a: ActionOutput, b: ActionOutput) -> float:
    """Hamming distance (discrete) plus l2 (continuous)."""
    if len(a.discrete) != len(b.discrete) or len(a.continuous) != len(b.continuous):
        return math.inf
    hamming = sum(x != y for x, y in zip(a.discrete, b.discrete, strict=True))
    return hamming + (l2(a.continuous, b.continuous) if a.continuous else 0.0)


def default_distance(a: Output, b: Output) -> float:
    """Same-tag comparison functional. Heterogeneous tags need mediated compatibility."""
    if isinstance(a, TextOutput) and isinstance(b, TextOutput):
        return edit_distance(a.text, b.text)
    if isinstance(a, VectorOutput) and isinstance(b, VectorOutput):
        return l2(a.values, b.values)
    if isinstance(a, MediaOutput) and isinstance(b, MediaOutput):
        return ssim_dissimilarity(a, b)
    if isinstance(a, ActionOutput) and isinstance(b, ActionOutput):
        return action_distance(a, b)
    msg = f"no direct comparison between {a.tag} and {b.tag}; use mediated compatibility"
    raise TypeError(msg)
