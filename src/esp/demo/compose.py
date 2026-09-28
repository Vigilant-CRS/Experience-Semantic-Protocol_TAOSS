# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Structured demo input -> ExperienceFrame (WP-025).

The input is a *structured* self-report (Likert answers, action readiness,
context tags, knowledge references) — never free text. Latents come from a
fixed random projection (``esp-demo-projection``). It is deterministic and
documented as a placeholder, **not** a trained encoder (WP-066 replaces it).
"""

from __future__ import annotations

import hashlib
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field

import numpy as np

from esp.core.clock import ClockStamp
from esp.core.provenance import Provenance, SourceKind
from esp.core.taoss_types import L1_DIMS, TaossType
from esp.frame.model import (
    AnchorCoordinate,
    ConsentRef,
    ExperienceFrame,
    FrameProvenance,
    TypeBlock,
)
from esp.ontology.profiles import BASIC8_ID, basic8_registry
from esp.semantics.bindings import RelationClass, SemanticBinding, TypedEndpoint
from esp.semantics.self_report import Construct, SelfReport, SelfReportItem

ENCODER_ID = "esp-demo-projection@0.1.0"
_NS = uuid.UUID("3c0e5a8b-7f21-4d6e-9b4a-1e2f3a4b5c6d")


@dataclass(frozen=True, slots=True)
class DemoState:
    """What the sender UI collects. Scales are 1..5."""

    emotions: Mapping[str, int] = field(default_factory=dict)
    """basic-8 label -> rating, e.g. ``{"fear": 4}``."""
    valence: int = 3
    arousal: int = 3
    readiness: Mapping[str, int] = field(default_factory=dict)
    """action tendency -> rating, e.g. ``{"avoid": 5}``."""
    context: tuple[str, ...] = ()
    """Context tags, e.g. ``("work", "meeting")``."""
    knowledge: tuple[str, ...] = ()
    """Knowledge references (opaque ids), e.g. ``("possible_dismissal",)``."""


def _uuid4(name: str) -> uuid.UUID:
    """Deterministic identifier with RFC 4122 version-4 bits (ids must be v4)."""
    return uuid.UUID(bytes=uuid.uuid5(_NS, name).bytes, version=4)


def _projection(t: TaossType, features: np.ndarray) -> tuple[float, ...]:
    seed = int.from_bytes(
        hashlib.blake2b(f"{ENCODER_ID}/{t.name}".encode(), digest_size=8).digest()
    )
    rng = np.random.default_rng(seed)
    w = rng.normal(0.0, 1.0, size=(L1_DIMS[t], features.size))
    z = w @ features
    norm = float(np.linalg.norm(z))
    return tuple(float(x) for x in (z / norm if norm > 0 else z))


def _hash_features(tokens: tuple[str, ...], n: int = 32) -> np.ndarray:
    v = np.zeros(n)
    for tok in tokens:
        h = hashlib.blake2b(tok.encode(), digest_size=4).digest()
        v[int.from_bytes(h) % n] += 1.0
    return v if tokens else np.full(n, 1e-3)


def self_report_of(state: DemoState, stamp: ClockStamp, report_id: uuid.UUID) -> SelfReport:
    items = [
        SelfReportItem(kind=Construct.EMOTION_CATEGORY, label=k, raw=v, scale_min=1, scale_max=5)
        for k, v in sorted(state.emotions.items())
    ]
    items += [
        SelfReportItem(kind=Construct.ACTION_READINESS, label=k, raw=v, scale_min=1, scale_max=5)
        for k, v in sorted(state.readiness.items())
    ]
    items.append(
        SelfReportItem(kind=Construct.VALENCE, raw=state.valence, scale_min=1, scale_max=5)
    )
    items.append(
        SelfReportItem(kind=Construct.AROUSAL, raw=state.arousal, scale_min=1, scale_max=5)
    )
    return SelfReport(
        id=report_id,
        instrument="esp-demo-likert5",
        vocabulary_id=BASIC8_ID,
        timestamp=stamp,
        items=tuple(items),
    )


def compose_frame(
    state: DemoState,
    *,
    timeline_id: uuid.UUID,
    sequence: int,
    now_ns: int,
    capability_id: uuid.UUID | None = None,
) -> ExperienceFrame:
    """KNO, INT, EMO, CTX blocks plus an EMO -> KNO binding (if both exist)."""
    stamp = ClockStamp(
        source_ns=now_ns, monotonic_ns=now_ns, clock_domain="demo:wall", sequence=sequence
    )
    ident = f"{timeline_id}:{sequence}"
    report = self_report_of(state, stamp, _uuid4("report:" + ident))
    anchors = basic8_registry().anchor_set(BASIC8_ID).anchors
    ratings = {f"esp:emo:{k}:v1": (v - 1) / 4 for k, v in state.emotions.items()}
    unknown = set(ratings) - set(anchors)
    if unknown:
        msg = f"not in the basic-8 vocabulary: {sorted(unknown)}"
        raise ValueError(msg)
    emo_features = np.array(
        [ratings.get(a, 0.0) for a in anchors] + [(state.valence - 3) / 2, (state.arousal - 3) / 2]
    )
    readiness = np.array([v / 5 for _, v in sorted(state.readiness.items())] or [1e-3])
    blocks = [
        TypeBlock(
            type=TaossType.KNO,
            latent=_projection(TaossType.KNO, _hash_features(state.knowledge)),
        ),
        TypeBlock(
            type=TaossType.INT,
            latent=_projection(TaossType.INT, readiness),
            intention=(report.to_intention_state(),),
        ),
        TypeBlock(
            type=TaossType.EMO,
            latent=_projection(TaossType.EMO, emo_features),
            anchor_set_id=BASIC8_ID,
            anchors=tuple(
                AnchorCoordinate(anchor_id=a, similarity=ratings.get(a, 0.0)) for a in anchors
            ),
            affect=(report.to_affective_descriptor(),),
        ),
        TypeBlock(
            type=TaossType.CTX, latent=_projection(TaossType.CTX, _hash_features(state.context))
        ),
    ]
    bindings: tuple[SemanticBinding, ...] = ()
    if state.knowledge and state.emotions:
        bindings = (
            SemanticBinding(
                binding_id=_uuid4("binding:" + ident),
                relation=RelationClass.ELICITED_BY,
                source=TypedEndpoint(type=TaossType.EMO, ref="self_report_emotion"),
                target=TypedEndpoint(type=TaossType.KNO, ref=state.knowledge[0]),
                confidence=0.8,
                provenance=Provenance(source_kind=SourceKind.SELF_REPORT),
            ),
        )
    return ExperienceFrame(
        frame_id=_uuid4("frame:" + ident),
        timeline_id=timeline_id,
        sequence=sequence,
        timestamp=stamp,
        types=tuple(blocks),
        bindings=bindings,
        provenance=FrameProvenance(encoder_id=ENCODER_ID, evidence_refs=(f"self_report:{ident}",)),
        consent=ConsentRef(capability_id=capability_id),
    )
