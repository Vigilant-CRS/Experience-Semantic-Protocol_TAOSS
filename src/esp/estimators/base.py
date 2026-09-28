# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Estimator interfaces and the semantic estimate container."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Annotated, Protocol, runtime_checkable

from pydantic import Field

from esp.core.ids import RegistryName
from esp.core.model import EspModel
from esp.core.scalars import UInt64
from esp.evidence.claim import EvidenceClaim
from esp.observation.model import Observation


class EstimationContext(EspModel):
    at_ns: UInt64
    """Reference time the estimate refers to."""
    profile: Annotated[int, Field(ge=0x01, le=0xFF)] = 0x01
    vocabulary_id: RegistryName = "esp-emo-v13-basic8-v1"


class SemanticEstimate(EspModel):
    """Provenance-carrying claims from one estimator run. Claims are never merged here."""

    claims: tuple[EvidenceClaim, ...] = ()


@runtime_checkable
class StateEstimator(Protocol):
    """Plan section 20.1."""

    @property
    def estimator_id(self) -> str: ...

    @property
    def estimator_version(self) -> str: ...

    def estimate(
        self, observations: Sequence[Observation], context: EstimationContext
    ) -> SemanticEstimate: ...
