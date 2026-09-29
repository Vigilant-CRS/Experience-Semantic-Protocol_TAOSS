# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Example vendor integration built on the SDK bases (WP-090).

``ExampleVendorAdapter`` stands in for a device driver. It "acquires"
deterministic synthetic ECoG-like voltages from an in-memory buffer. For a
real device you would read from the vendor API in :meth:`acquire` instead.
The adapter is declared as a *recording replay* (``L4-REPLAY``), which is the
only way invasive signals are admitted in v1.

``ExampleVendorDecoder`` is a fixed projection standing in for ``f_decode``.
It only ever outputs INT and TEM, the types a motor/communication decoder can
defend; see the neural mapping profile (M18) for what may map where.

``example_adapter`` and ``example_decoder`` are the factories that
``esp-conformance run --neural-adapter esp.neural_sdk.example:example_adapter``
loads.
"""

from __future__ import annotations

import hashlib

import numpy as np
from numpy.typing import NDArray

from esp.adapters.neural.interface import NeuralAdapterInfo, NeuralFeatures, NeuralLevel
from esp.adapters.neural.model import (
    ElectrodeSpec,
    NeuralDeviceDescriptor,
    ProcessingStep,
    ReplayDeclaration,
)
from esp.adapters.physio.stream import ChannelSpec, regular_timestamps
from esp.core.taoss_types import L1_DIMS, TaossType
from esp.neural_sdk.base import BlockAdapter, TypedDecoderBase
from esp.observation.model import DeviceMetadata, Modality

RATE_HZ = 1000.0
N_CHANNELS = 8


def _info() -> NeuralAdapterInfo:
    electrodes = tuple(ElectrodeSpec(f"g{i:02d}", group="grid-a") for i in range(N_CHANNELS))
    descriptor = NeuralDeviceDescriptor(
        manufacturer="Example Neurotech",
        model="ECoG grid 8",
        firmware="1.0.0",
        device_id="example-ecog-01",
        modalities=frozenset({Modality.ECOG}),
        electrodes=electrodes,
        unit="uV",
        clock_domain="example-ecog-01:mono",
        sampling_rate_hz=RATE_HZ,
        reference="common average",
        processing=(ProcessingStep("highpass", (("cutoff_hz", "0.5"),)),),
    )
    return NeuralAdapterInfo(
        adapter_id="example-vendor-ecog",
        device=DeviceMetadata(
            device_id="example-ecog-01", kind="ecog-grid", sampling_rate_hz=RATE_HZ, synthetic=True
        ),
        channels=tuple(ChannelSpec(e.name, Modality.ECOG, "uV") for e in electrodes),
        nominal_rate_hz=RATE_HZ,
        level=NeuralLevel.L4_INVASIVE,
        clock_domain="example-ecog-01:mono",
        descriptor=descriptor,
        replay=ReplayDeclaration(
            dataset_id="example:synthetic-ecog",
            version="1.0.0",
            license="CC0-1.0",
            consent_basis="synthetic data; no participant",
            url="https://example.org/datasets/synthetic-ecog",
        ),
    )


class ExampleVendorAdapter(BlockAdapter):
    def __init__(self, total_samples: int = 4000, seed: int = 0) -> None:
        super().__init__(_info())
        self._total = total_samples
        self._seed = seed
        self._pos = 0

    def on_start(self) -> None:
        self._pos = 0
        self._rng = np.random.default_rng(self._seed)

    def acquire(self, max_samples: int) -> tuple[NDArray[np.int64], NDArray[np.float64]] | None:
        n = min(max_samples, self._total - self._pos)
        if n <= 0:
            return None
        t = (self._pos + np.arange(n)) / RATE_HZ
        gamma = 20.0 * np.sin(2 * np.pi * 80.0 * t)[:, None]
        values = gamma + self._rng.standard_normal((n, N_CHANNELS)) * 5.0
        ts = regular_timestamps(round(self._pos * 1e9 / RATE_HZ), n, RATE_HZ)
        self._pos += n
        return ts, values


class ExampleVendorDecoder(TypedDecoderBase):
    decoder_id = "example-vendor-projection@1.0.0"

    def __init__(self, n_features: int) -> None:
        super().__init__(frozenset({TaossType.INT, TaossType.TEM}))
        self._w = {}
        for t in (TaossType.INT, TaossType.TEM):
            seed = int.from_bytes(hashlib.blake2b(t.name.encode(), digest_size=8).digest(), "big")
            self._w[t] = np.random.default_rng(seed).standard_normal(
                (L1_DIMS[t], n_features)
            ) / np.sqrt(n_features)

    def decode_one(self, t: TaossType, features: NeuralFeatures) -> NDArray[np.float64]:
        x = features.values - features.values.mean()
        out: NDArray[np.float64] = np.tanh(self._w[t] @ x)
        return out


def example_adapter() -> ExampleVendorAdapter:
    return ExampleVendorAdapter()


def example_decoder(n_features: int = N_CHANNELS * 4) -> ExampleVendorDecoder:
    return ExampleVendorDecoder(n_features)
