# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Release minimization (WP-060, T19: latent inversion / semantic over-recovery).

Anchor-only mode releases anchor coordinates (similarities to public,
registry-pinned anchors) instead of raw latents. Types without anchor
coordinates are withheld and listed as masked. This bounds what an
authorized receiver can recover; it does not prove non-invertibility
(V13 section 19: the T19 audit is empirical, WP-058).
"""

from __future__ import annotations

from esp.frame.model import ExperienceFrame, TypeBlock


def anchor_only(frame: ExperienceFrame) -> ExperienceFrame:
    kept: list[TypeBlock] = []
    withheld = set(frame.masked_types)
    for block in frame.types:
        if block.anchors:
            kept.append(
                TypeBlock(
                    type=block.type,
                    anchor_set_id=block.anchor_set_id,
                    anchors=block.anchors,
                )
            )
        else:
            withheld.add(block.type)
    kept_types = {b.type for b in kept}
    return ExperienceFrame.model_validate(
        frame.model_dump()
        | {
            "types": tuple(kept),
            "masked_types": tuple(sorted(withheld)),
            "bindings": tuple(b for b in frame.bindings if b.endpoint_types <= kept_types),
        }
    )
