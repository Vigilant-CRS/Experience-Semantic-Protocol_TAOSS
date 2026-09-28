# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Reference renderers and the decoder transparency panel (WP-059).

Renderers show what arrived: text, a vector visualization, machine-readable
JSON, or all three (mixed mode). The transparency panel states what is
present, what was masked, what was simply not sent, which decoder/renderer
ran, and what *cannot* be reconstructed on this receiver.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any

import numpy as np

from esp.core.taoss_types import TaossType
from esp.decoder.core import DecodeResult
from esp.frame.model import ExperienceFrame

_BARS = "▁▂▃▄▅▆▇█"


def sparkline(values: Sequence[float], width: int = 32) -> str:
    x = np.asarray(values, dtype=np.float64)
    if x.size == 0:
        return ""
    chunks = np.array_split(x, min(width, x.size))
    means = np.array([c.mean() for c in chunks])
    lo, hi = float(means.min()), float(means.max())
    if hi == lo:
        return _BARS[len(_BARS) // 2] * len(means)
    idx = ((means - lo) / (hi - lo) * (len(_BARS) - 1)).round().astype(int)
    return "".join(_BARS[i] for i in idx)


def render_text(frame: ExperienceFrame) -> str:
    lines = [f"frame {frame.frame_id} (timeline {frame.timeline_id}, seq {frame.sequence})"]
    lines.append("present: " + (", ".join(t.name for t in frame.present_types) or "none"))
    lines.append("masked:  " + (", ".join(t.name for t in frame.masked_types) or "none"))
    for block in frame.types:
        for d in block.affect:
            cats = ", ".join(f"{c.label} {c.intensity:.2f}" for c in d.categories)
            lines.append(
                f"affect [{d.affect_scope.value}] valence={d.valence} arousal={d.arousal}"
                + (f" categories: {cats}" if cats else "")
            )
        for s in block.intention:
            tendencies = ", ".join(f"{r.tendency} {r.intensity:.2f}" for r in s.readiness)
            lines.append(f"intention readiness: {tendencies or 'none'}")
        if block.anchors:
            top = sorted(block.anchors, key=lambda a: -a.similarity)[:3]
            lines.append(
                f"{block.type.name} anchors: "
                + ", ".join(f"{a.anchor_id} {a.similarity:.2f}" for a in top)
            )
    for b in frame.bindings:
        lines.append(f"binding: {b.source.type.name} {b.relation.value} {b.target.type.name}")
    lines.append(f"provenance: encoder {frame.provenance.encoder_id}")
    return "\n".join(lines)


def render_vectors(frame: ExperienceFrame) -> str:
    return "\n".join(
        f"{b.type.name:>3} {sparkline(b.latent)}" for b in frame.types if b.latent is not None
    )


def render_machine(frame: ExperienceFrame) -> str:
    return frame.canonical_json().decode()


def render_mixed(frame: ExperienceFrame) -> str:
    return "\n\n".join([render_text(frame), render_vectors(frame), render_machine(frame)])


RENDERERS = {
    "text": render_text,
    "vector": render_vectors,
    "machine": render_machine,
    "mixed": render_mixed,
}


def transparency_panel(
    frame: ExperienceFrame, results: Sequence[DecodeResult], renderer: str
) -> dict[str, Any]:
    present = set(frame.present_types)
    masked = set(frame.masked_types)
    interpreted = {t for r in results for t in r.used}
    return {
        "present": [t.name for t in sorted(present)],
        "masked_by_sender": [t.name for t in sorted(masked)],
        "not_sent": [t.name for t in TaossType if t not in present and t not in masked],
        "renderer": renderer,
        "decoders": [
            {
                "decoder_id": r.decoder_id,
                "used": [t.name for t in r.used],
                "absent_graceful": [
                    {"type": a.type.name, "intentional": a.intentional} for a in r.absent
                ],
                "imputed_from_prior": [t.name for t in r.imputed],
                "received_unused": [t.name for t in r.unused],
            }
            for r in results
        ],
        "cannot_reconstruct": sorted(
            {t.name for t in masked}
            | {t.name for t in TaossType if t not in present}
            | {t.name for t in present - interpreted}
        ),
    }


def panel_json(panel: dict[str, Any]) -> str:
    return json.dumps(panel, indent=2, sort_keys=True)
