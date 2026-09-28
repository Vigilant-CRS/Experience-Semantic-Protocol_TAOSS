# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Machine Experience Adapter ``g_mach(S, U, M)`` (V13 definition machadapter, eq. gmach).

``g_mach : S_{1:T} x U_{1:T} x M_{1:T} → ⊕_{t ∈ T_mach} R^{d_t}``, where S is the
sensor stream, U the action history and M the task model. The adapter is
vendor-implemented. ESP fixes only its output shape and its consent semantics:

- declared output types ⊆ ``T_mach`` (never EMO);
- the output has exactly the declared types, the L1 dimensions and finite values;
- a machine frame always lists EMO in ``masked_types``, so the header carries
  ``EMO_MASKED=1``, and it carries the adapter id as ``encoder_id`` provenance.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from typing import Protocol

import numpy as np
from numpy.typing import NDArray

from esp.core.clock import ClockStamp
from esp.core.taoss_types import L1_DIMS, TaossType
from esp.frame.model import ExperienceFrame, FrameProvenance, TypeBlock
from esp.meb.profiles import DomainProfile, MebError, check_machine_types

F64 = NDArray[np.float64]


class MachineAdapter(Protocol):
    @property
    def adapter_id(self) -> str:
        """Encoder id ``name@major.minor.patch`` (registry form)."""
        ...

    @property
    def types(self) -> frozenset[TaossType]: ...

    def encode(self, sensors: F64, actions: F64, task: F64) -> Mapping[TaossType, F64]:
        """``g_mach(S_{1:T}, U_{1:T}, M_{1:T})``; each input has shape ``(T, n)``."""
        ...


def validate_output(
    adapter: MachineAdapter, out: Mapping[TaossType, F64]
) -> dict[TaossType, tuple[float, ...]]:
    """Check the adapter contract; return canonical per-type latents."""
    declared = check_machine_types(adapter.types)
    produced = frozenset(out)
    check_machine_types(produced)
    if produced != declared:
        msg = (
            f"adapter {adapter.adapter_id} produced {sorted(t.name for t in produced)} "
            f"but declares {sorted(t.name for t in declared)}"
        )
        raise MebError(msg)
    latents: dict[TaossType, tuple[float, ...]] = {}
    for t, v in out.items():
        arr = np.asarray(v, dtype=np.float64)
        if arr.shape != (L1_DIMS[t],):
            msg = f"{t.name} latent must have shape ({L1_DIMS[t]},), got {arr.shape}"
            raise MebError(msg)
        if not np.all(np.isfinite(arr)):
            msg = f"{t.name} latent is not finite"
            raise MebError(msg)
        latents[t] = tuple(float(x) for x in arr)
    return latents


def machine_frame(
    adapter: MachineAdapter,
    sensors: F64,
    actions: F64,
    task: F64,
    *,
    profile: DomainProfile,
    timeline_id: uuid.UUID,
    sequence: int,
    now_ns: int,
    frame_id: uuid.UUID | None = None,
) -> ExperienceFrame:
    """Run ``g_mach`` and build a machine-authored frame for ``profile``."""
    latents = validate_output(adapter, adapter.encode(sensors, actions, task))
    allowed = profile.types
    missing = profile.type_set.required - frozenset(latents)
    if missing:
        msg = f"{profile.name} requires {sorted(t.name for t in missing)} from the adapter"
        raise MebError(msg)
    stamp = ClockStamp(
        source_ns=now_ns, monotonic_ns=now_ns, clock_domain="meb:machine", sequence=sequence
    )
    return ExperienceFrame(
        frame_id=frame_id or uuid.uuid4(),
        timeline_id=timeline_id,
        sequence=sequence,
        timestamp=stamp,
        types=tuple(TypeBlock(type=t, latent=v) for t, v in latents.items() if t in allowed),
        masked_types=(TaossType.EMO,),  # machines never author EMO: always an explicit mask
        provenance=FrameProvenance(encoder_id=adapter.adapter_id),
    )
