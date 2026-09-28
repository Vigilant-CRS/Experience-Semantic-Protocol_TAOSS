# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Decoder version drift (WP-060, T15).

A :class:`DecoderArchive` pins a decoder's id and version together with its
outputs on archived reference frames (for example anchor realizations).
:func:`check_drift` replays the archive: a changed version must be
re-baselined explicitly; the same version must reproduce its outputs within
``epsilon`` (same-tag comparison functional).
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass

from esp.decoder.core import Decoder, DecoderPolicyError, run_decoder
from esp.decoder.outputs import Output, default_distance
from esp.frame.model import ExperienceFrame


@dataclass(frozen=True, slots=True)
class DecoderArchive:
    decoder_id: str
    version: str
    references: tuple[ExperienceFrame, ...]
    outputs: tuple[Output, ...]


@dataclass(frozen=True, slots=True)
class DriftReport:
    worst: float
    drifted: tuple[int, ...]
    """Indices of references whose output moved more than epsilon."""

    @property
    def ok(self) -> bool:
        return not self.drifted


def archive(decoder: Decoder, references: Sequence[ExperienceFrame]) -> DecoderArchive:
    outs = tuple(run_decoder(decoder, r).output for r in references)
    p = decoder.profile
    return DecoderArchive(p.decoder_id, p.version, tuple(references), outs)


def check_drift(
    decoder: Decoder,
    pinned: DecoderArchive,
    *,
    epsilon: float = 0.0,
    distance: Callable[[Output, Output], float] = default_distance,
) -> DriftReport:
    p = decoder.profile
    if (p.decoder_id, p.version) != (pinned.decoder_id, pinned.version):
        msg = (
            f"decoder {p.decoder_id}@{p.version} does not match the archive "
            f"{pinned.decoder_id}@{pinned.version}; re-baseline explicitly"
        )
        raise DecoderPolicyError(msg)
    ds = [
        distance(run_decoder(decoder, r).output, o)
        for r, o in zip(pinned.references, pinned.outputs, strict=True)
    ]
    return DriftReport(
        worst=max(ds, default=0.0), drifted=tuple(i for i, d in enumerate(ds) if d > epsilon)
    )
