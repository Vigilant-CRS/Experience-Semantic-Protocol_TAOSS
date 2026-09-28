# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Future neural adapter interface (WP-045, class ``FUTURE``; V13 section L2-L3).

Interface and simulator contract only. No functional claim is made about any
neural device.
"""

from esp.adapters.neural.interface import (
    CLAIM_CLASS,
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
from esp.adapters.neural.simulator import SimulatedNeuralAdapter, SimulatorDecoder, band_features

__all__ = [
    "CLAIM_CLASS",
    "ContractReport",
    "ContractViolation",
    "NeuralAdapter",
    "NeuralAdapterInfo",
    "NeuralDecoder",
    "NeuralFeatures",
    "NeuralLevel",
    "SimulatedNeuralAdapter",
    "SimulatorDecoder",
    "band_features",
    "check_adapter_contract",
    "check_decoder_contract",
    "decode_boundary",
]
