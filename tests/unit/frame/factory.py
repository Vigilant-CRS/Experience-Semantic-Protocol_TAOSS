# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Builders for complete ExperienceFrames used across tests."""

import uuid

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
from esp.semantics.bindings import RelationClass, SemanticBinding, TypedEndpoint
from esp.semantics.self_report import Construct, SelfReport, SelfReportItem

TIMELINE = uuid.UUID("5f0c6a8e-3b7d-4c4e-9a53-2f6a1d9e8b10")
FRAME = uuid.UUID("0b6f2c1e-9d4a-4f7b-8e21-6c3d5a7b9e02")
BINDING = uuid.UUID("d2a1c3e4-5b6f-4a7c-8d9e-0f1a2b3c4d5e")
CAPABILITY = uuid.UUID("7e8f9a0b-1c2d-4e3f-8a4b-5c6d7e8f9a0b")
STAMP = ClockStamp(
    source_ns=1_727_000_000_000_000_000,
    monotonic_ns=42_000_000,
    clock_domain="host:monotonic",
    sequence=123,
    uncertainty_ns=1_000,
)


def self_report() -> SelfReport:
    return SelfReport(
        id=uuid.UUID("a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"),
        instrument="esp-wizard-of-oz-likert5",
        vocabulary_id="esp-emo-v13-basic8-v1",
        timestamp=STAMP,
        items=(
            SelfReportItem(
                kind=Construct.EMOTION_CATEGORY, label="fear", raw=4, scale_min=1, scale_max=5
            ),
            SelfReportItem(
                kind=Construct.EMOTION_CATEGORY, label="sadness", raw=2, scale_min=1, scale_max=5
            ),
            SelfReportItem(
                kind=Construct.ACTION_READINESS, label="avoid", raw=5, scale_min=1, scale_max=5
            ),
            SelfReportItem(kind=Construct.VALENCE, raw=1, scale_min=1, scale_max=5),
        ),
    )


def latents(seed: int = 7) -> dict[TaossType, tuple[float, ...]]:
    rng = np.random.default_rng(seed)
    return {t: tuple(float(x) for x in rng.normal(size=d)) for t, d in L1_DIMS.items()}


def full_frame(*, with_binding: bool = True) -> ExperienceFrame:
    report = self_report()
    lat = latents()
    blocks = [
        TypeBlock(type=TaossType.KNO, latent=lat[TaossType.KNO]),
        TypeBlock(
            type=TaossType.INT, latent=lat[TaossType.INT], intention=(report.to_intention_state(),)
        ),
        TypeBlock(
            type=TaossType.EMO,
            latent=lat[TaossType.EMO],
            anchor_set_id="esp-emo-v13-basic8-v1",
            anchors=(
                AnchorCoordinate(anchor_id="esp:emo:fear:v1", similarity=0.71),
                AnchorCoordinate(anchor_id="esp:emo:sadness:v1", similarity=0.44),
            ),
            affect=(report.to_affective_descriptor(),),
        ),
        TypeBlock(type=TaossType.CTX, latent=lat[TaossType.CTX]),
        TypeBlock(type=TaossType.SEN, latent=lat[TaossType.SEN]),
        TypeBlock(type=TaossType.TEM, latent=lat[TaossType.TEM]),
    ]
    bindings = ()
    if with_binding:
        bindings = (
            SemanticBinding(
                binding_id=BINDING,
                relation=RelationClass.ELICITED_BY,
                source=TypedEndpoint(type=TaossType.EMO, ref="emotion_episode_17"),
                target=TypedEndpoint(type=TaossType.KNO, ref="possible_dismissal"),
                confidence=0.84,
                provenance=Provenance(source_kind=SourceKind.SELF_REPORT),
            ),
        )
    return ExperienceFrame(
        frame_id=FRAME,
        timeline_id=TIMELINE,
        sequence=123,
        timestamp=STAMP,
        types=tuple(blocks),
        bindings=bindings,
        provenance=FrameProvenance(
            encoder_id="esp-reference-encoder@0.1.0",
            evidence_refs=("self_report_22", "obs_eda_441"),
        ),
        consent=ConsentRef(capability_id=CAPABILITY),
    )
