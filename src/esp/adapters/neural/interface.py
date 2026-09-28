# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Neural adapter interface and the V13 decoder interface boundary (WP-045).

V13 (section "L2-L3 — With Sensor Integration") separates:

- the **source**: a neural device or recording. It yields neutral
  :class:`~esp.adapters.physio.stream.SampleBlock` objects (voltages, optical
  densities), exactly like the physiology adapters. It never yields emotions,
  intentions or labels;
- the **feature step**: ``SampleBlock -> NeuralFeatures``, named numeric
  features with provenance;
- the **decoder boundary** ``f_decode : NeuralFeatures -> ⊕_t R^{d_t}``,
  implemented by vendors or research stacks. ESP handles consent, privacy,
  transport and storage *above* this boundary. :func:`decode_boundary` calls
  the decoder only for consented types and refuses undeclared or malformed
  output.

Class ``FUTURE``: this module defines interfaces and a conformance contract
that a simulator passes. It claims nothing about real neural devices.
Invasive sources (V13 L4) are refused by the v1 contract: no v1 profile covers
them.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final, Protocol, runtime_checkable

import numpy as np
from numpy.typing import NDArray

from esp.adapters.physio.stream import ChannelSpec, SampleBlock
from esp.core.provenance import Provenance
from esp.core.taoss_types import L1_DIMS, TaossType
from esp.observation.model import DeviceMetadata, Modality
from esp.observation.units import UNITS

CLAIM_CLASS: Final = "FUTURE"
"""Plan class of WP-045: interface and simulator contract, no functional claim."""

NEURAL_MODALITIES: Final = frozenset({Modality.EEG, Modality.EMG, Modality.EYE})
"""Modalities a v1 neural source may emit (fNIRS etc. need a registry entry first)."""

_INTERPRETIVE: Final = re.compile(
    r"(^|[_.\-])(emo|emotion|affect|mood|valence|arousal|intensity|intent|intention|"
    r"joy|trust|fear|surprise|sadness|anger|disgust|anticipation|stress|thought|mind)"
    r"($|[_.\-])"
)
"""Channel/feature names that would smuggle an interpretation into a neutral stream."""


class NeuralLevel(StrEnum):
    """V13 integration levels for neural inputs."""

    L3_NON_INVASIVE = "L3"
    L4_INVASIVE = "L4"


@dataclass(frozen=True, slots=True)
class NeuralAdapterInfo:
    adapter_id: str
    device: DeviceMetadata
    channels: tuple[ChannelSpec, ...]
    nominal_rate_hz: float
    level: NeuralLevel
    clock_domain: str


@runtime_checkable
class NeuralAdapter(Protocol):
    """A neural source. ``read`` returns the next block or ``None`` at the end."""

    @property
    def info(self) -> NeuralAdapterInfo: ...

    def start(self) -> None: ...

    def read(self, max_samples: int) -> SampleBlock | None: ...

    def stop(self) -> None: ...


@dataclass(frozen=True, slots=True)
class NeuralFeatures:
    """Named, neutral numeric features computed from one window of a neural stream."""

    names: tuple[str, ...]
    values: NDArray[np.float64]
    window_start_ns: int
    window_end_ns: int
    provenance: Provenance

    def __post_init__(self) -> None:
        if self.values.shape != (len(self.names),):
            msg = "one value per feature name"
            raise ValueError(msg)
        if len(set(self.names)) != len(self.names):
            msg = "feature names must be unique"
            raise ValueError(msg)
        if self.window_end_ns <= self.window_start_ns:
            msg = "empty feature window"
            raise ValueError(msg)


@runtime_checkable
class NeuralDecoder(Protocol):
    """V13 ``f_decode``: neural features to typed latents (vendor-implemented)."""

    @property
    def decoder_id(self) -> str: ...

    @property
    def output_types(self) -> frozenset[TaossType]: ...

    def decode(
        self, features: NeuralFeatures, types: frozenset[TaossType]
    ) -> Mapping[TaossType, NDArray[np.float64]]: ...


@dataclass(frozen=True, slots=True)
class ContractViolation:
    rule: str
    detail: str


@dataclass(frozen=True, slots=True)
class ContractReport:
    subject: str
    blocks: int = 0
    samples: int = 0
    violations: tuple[ContractViolation, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return not self.violations


class ContractError(ValueError):
    pass


def _interpretive(name: str) -> bool:
    return bool(_INTERPRETIVE.search(name.lower()))


def _check_info(info: NeuralAdapterInfo) -> list[ContractViolation]:
    v: list[ContractViolation] = []
    if info.level is not NeuralLevel.L3_NON_INVASIVE:
        v.append(
            ContractViolation("level", "invasive (L4) sources have no v1 profile and are refused")
        )
    if not info.channels:
        v.append(ContractViolation("channels", "no channels declared"))
    if not info.nominal_rate_hz > 0:
        v.append(ContractViolation("rate", "nominal rate must be positive"))
    for c in info.channels:
        if c.modality not in NEURAL_MODALITIES:
            v.append(
                ContractViolation("modality", f"{c.name}: {c.modality} is not a neural signal")
            )
        if c.unit not in UNITS:
            v.append(ContractViolation("unit", f"{c.name}: unit {c.unit!r} not normalized"))
        if _interpretive(c.name):
            v.append(ContractViolation("neutral", f"channel {c.name!r} names an interpretation"))
    return v


def check_adapter_contract(
    adapter: NeuralAdapter, *, reads: int = 8, max_samples: int = 256
) -> ContractReport:
    """Run an adapter and check the v1 source contract.

    The adapter must emit only :class:`SampleBlock`s whose channels, device and
    clock domain match its declaration, with strictly increasing integer
    nanosecond timestamps across blocks, and must name no interpretation.
    """
    info = adapter.info
    violations = _check_info(info)
    blocks = samples = 0
    last_ts: int | None = None
    adapter.start()
    try:
        for _ in range(reads):
            block: object = adapter.read(max_samples)  # untrusted vendor code: check the type
            if block is None:
                break
            if not isinstance(block, SampleBlock):
                violations.append(
                    ContractViolation("output", f"read() returned {type(block).__name__}")
                )
                break
            blocks += 1
            samples += block.n_samples
            if block.channels != info.channels:
                violations.append(ContractViolation("channels", "block channels differ"))
            if block.device != info.device or block.clock_domain != info.clock_domain:
                violations.append(ContractViolation("identity", "device or clock domain differs"))
            if block.n_samples > max_samples:
                violations.append(ContractViolation("size", "block exceeds max_samples"))
            if block.timestamps_ns.dtype != np.int64:
                violations.append(ContractViolation("clock", "timestamps must be int64 ns"))
            ts = block.timestamps_ns.astype(np.int64)
            if ts.size and (
                bool((np.diff(ts) <= 0).any()) or (last_ts is not None and int(ts[0]) <= last_ts)
            ):
                violations.append(ContractViolation("clock", "timestamps not strictly increasing"))
            if ts.size:
                last_ts = int(ts[-1])
    finally:
        adapter.stop()
    if blocks == 0:
        violations.append(ContractViolation("output", "adapter produced no block"))
    return ContractReport(info.adapter_id, blocks, samples, tuple(violations))


def check_decoder_contract(decoder: NeuralDecoder, features: NeuralFeatures) -> ContractReport:
    """Every declared output type decodes to a finite vector of the L1 dimension."""
    violations: list[ContractViolation] = []
    for name in features.names:
        if _interpretive(name):
            violations.append(
                ContractViolation("neutral", f"feature {name!r} names an interpretation")
            )
    try:
        decode_boundary(decoder, features, decoder.output_types)
    except ContractError as exc:
        violations.append(ContractViolation("decode", str(exc)))
    return ContractReport(decoder.decoder_id, violations=tuple(violations))


def decode_boundary(
    decoder: NeuralDecoder, features: NeuralFeatures, consented: frozenset[TaossType]
) -> dict[TaossType, NDArray[np.float64]]:
    """Call ``f_decode`` for consented types only and validate its output.

    Types outside ``consented`` are never requested. The decoder must return
    exactly the requested types, each as a finite float vector of dimension
    ``d_t`` (L1). Anything else raises :class:`ContractError`: the output is
    discarded before any use, as V13 requires for L3+ neural profiles.
    """
    wanted = frozenset(consented) & decoder.output_types
    if not wanted:
        return {}
    out = decoder.decode(features, wanted)
    if set(out) != set(wanted):
        got, asked = sorted(t.name for t in out), sorted(t.name for t in wanted)
        msg = f"decoder returned {got}, requested {asked}"
        raise ContractError(msg)
    result: dict[TaossType, NDArray[np.float64]] = {}
    for t, vec in out.items():
        arr = np.asarray(vec, dtype=np.float64)
        if arr.shape != (L1_DIMS[t],) or not np.isfinite(arr).all():
            msg = f"{t.name}: expected a finite vector of dimension {L1_DIMS[t]}"
            raise ContractError(msg)
        result[t] = arr
    return result
