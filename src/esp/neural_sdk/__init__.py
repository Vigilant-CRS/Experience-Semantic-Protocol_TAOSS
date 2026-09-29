# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""ESP neural vendor SDK (WP-090, M18): the stable contract for device makers.

Implement :class:`NeuralAdapter` (a source of neutral :class:`SampleBlock`s) and,
if you ship your own decoder, :class:`NeuralDecoder` (``f_decode``). Then prove
it with::

    uv run esp-conformance run --neural-adapter your_package.module:factory

Everything above the adapter is identical for a live device, a replayed
recording and a simulator:

- features, the decoder boundary and consent;
- typed frames, the ESP session and the receiver.

The contract is versioned (:data:`CONTRACT_VERSION`). The Rust
implementation (``rust/esp-rs``, module ``neural``) mirrors it, and the
conformance runner cross-checks both. Out-of-process adapters in any language
speak the JSON-lines protocol in :mod:`esp.neural_sdk.jsonl`. A C ABI is
planned but not part of contract 1.0.0.

Contract rules (``check_adapter_contract`` rule names in brackets):

- declared, non-empty channels [channels];
- a positive rate [rate];
- normalized units [unit];
- neural modalities only [modality];
- channel names that never name an interpretation such as emotion or intent [neutral];
- blocks with exactly the declared channels [channels], device and clock domain
  [identity], at most ``max_samples`` samples [size];
- int64 nanosecond timestamps, strictly increasing across blocks [clock];
- at least one block [output], and only :class:`SampleBlock` objects [output];
- invasive (L4) sources only as declared recordings under ``L4-REPLAY``
  [level, replay:*];
- decoders answer only consented types, with finite vectors of the typed
  dimension [decode].
"""

from __future__ import annotations

from typing import Any, Final

from esp.adapters.neural.interface import (
    ContractReport,
    ContractViolation,
    NeuralAdapter,
    NeuralAdapterInfo,
    NeuralDecoder,
    NeuralFeatures,
    NeuralLevel,
    check_adapter_contract,
    check_decoder_contract,
    decode_boundary,
)
from esp.adapters.neural.model import (
    AUXILIARY,
    INVASIVE,
    NON_INVASIVE,
    OPEN_LICENSES,
    ElectrodeSpec,
    ElectrodeStatus,
    NeuralDeviceDescriptor,
    NeuralProfile,
    ProcessingStep,
    ReplayDeclaration,
    check_descriptor,
    check_profile,
)
from esp.adapters.physio.stream import ChannelSpec, SampleBlock, regular_timestamps
from esp.neural_sdk.base import AdapterStateError, BlockAdapter, TypedDecoderBase
from esp.observation.model import DeviceMetadata, Modality
from esp.observation.units import UNITS

CONTRACT_VERSION: Final = "1.0.0"

RULES: Final = (
    "channels",
    "rate",
    "unit",
    "modality",
    "neutral",
    "identity",
    "size",
    "clock",
    "output",
    "level",
    "replay:*",
    "descriptor:*",
    "decode",
)


def describe_contract() -> dict[str, Any]:
    """Machine-readable summary of contract 1.0.0 (published with conformance reports)."""
    return {
        "contract_version": CONTRACT_VERSION,
        "rules": list(RULES),
        "modalities": {
            "non_invasive": sorted(m.value for m in NON_INVASIVE),
            "invasive_replay_only": sorted(m.value for m in INVASIVE),
            "auxiliary": sorted(m.value for m in AUXILIARY),
        },
        "units": sorted(UNITS),
        "open_licenses_for_replay": sorted(OPEN_LICENSES),
        "profiles": [p.value for p in NeuralProfile],
    }


__all__ = [
    "CONTRACT_VERSION",
    "RULES",
    "AdapterStateError",
    "BlockAdapter",
    "ChannelSpec",
    "ContractReport",
    "ContractViolation",
    "DeviceMetadata",
    "ElectrodeSpec",
    "ElectrodeStatus",
    "Modality",
    "NeuralAdapter",
    "NeuralAdapterInfo",
    "NeuralDecoder",
    "NeuralDeviceDescriptor",
    "NeuralFeatures",
    "NeuralLevel",
    "NeuralProfile",
    "ProcessingStep",
    "ReplayDeclaration",
    "SampleBlock",
    "TypedDecoderBase",
    "check_adapter_contract",
    "check_decoder_contract",
    "check_descriptor",
    "check_profile",
    "decode_boundary",
    "describe_contract",
    "regular_timestamps",
]
