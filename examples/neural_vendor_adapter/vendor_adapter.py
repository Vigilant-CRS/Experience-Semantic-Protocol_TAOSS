# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Template for a device maker: a neural adapter and a decoder on the ESP neural SDK.

Run it:  uv run python examples/neural_vendor_adapter/vendor_adapter.py

It builds a small adapter for a (simulated) 4-channel EEG headset, checks it
against the vendor contract, extracts neutral features, decodes consented
types through the decoder boundary and prints the result. Replace
``MyHeadsetAdapter.acquire`` with calls into your device API.
"""

from __future__ import annotations

import sys

import numpy as np
from numpy.typing import NDArray

from esp.adapters.neural import band_features
from esp.core.taoss_types import L1_DIMS, TaossType
from esp.neural_sdk import (
    CONTRACT_VERSION,
    BlockAdapter,
    ChannelSpec,
    DeviceMetadata,
    Modality,
    NeuralAdapterInfo,
    NeuralFeatures,
    NeuralLevel,
    TypedDecoderBase,
    check_adapter_contract,
    check_decoder_contract,
    decode_boundary,
    regular_timestamps,
)

RATE = 250.0


class MyHeadsetAdapter(BlockAdapter):
    """Replace ``acquire`` with your driver; the base enforces the contract details."""

    def __init__(self) -> None:
        super().__init__(
            NeuralAdapterInfo(
                adapter_id="my-headset",
                device=DeviceMetadata(
                    device_id="headset-7f3a", kind="eeg-headset", sampling_rate_hz=RATE
                ),
                channels=tuple(
                    ChannelSpec(n, Modality.EEG, "uV") for n in ("f3", "f4", "c3", "c4")
                ),
                nominal_rate_hz=RATE,
                level=NeuralLevel.L3_NON_INVASIVE,
                clock_domain="headset-7f3a:mono",
            )
        )
        self._pos = 0

    def on_start(self) -> None:
        self._pos = 0
        self._rng = np.random.default_rng(0)

    def acquire(self, max_samples: int) -> tuple[NDArray[np.int64], NDArray[np.float64]] | None:
        n = min(max_samples, 2000 - self._pos)  # a finite demo stream
        if n <= 0:
            return None
        ts = regular_timestamps(round(self._pos * 1e9 / RATE), n, RATE)
        values = self._rng.standard_normal((n, 4)) * 10.0  # <- your device samples here
        self._pos += n
        return ts, values


class MyDecoder(TypedDecoderBase):
    """Your ``f_decode``. Declare only the types your decoder can defend."""

    decoder_id = "my-decoder@0.1.0"

    def __init__(self, n_features: int) -> None:
        super().__init__(frozenset({TaossType.TEM}))
        self._w = np.random.default_rng(1).standard_normal((L1_DIMS[TaossType.TEM], n_features))

    def decode_one(self, t: TaossType, features: NeuralFeatures) -> NDArray[np.float64]:
        out: NDArray[np.float64] = np.tanh(self._w @ (features.values - features.values.mean()))
        return out


def main() -> int:
    adapter = MyHeadsetAdapter()
    report = check_adapter_contract(adapter)
    print(
        f"contract {CONTRACT_VERSION}: adapter {'PASS' if report.ok else 'FAIL'}", report.violations
    )
    adapter.start()
    block = adapter.read(500)
    adapter.stop()
    if block is None:
        return 1
    features = band_features(block)
    decoder = MyDecoder(len(features.names))
    dec = check_decoder_contract(decoder, features)
    print(f"contract {CONTRACT_VERSION}: decoder {'PASS' if dec.ok else 'FAIL'}", dec.violations)
    typed = decode_boundary(decoder, features, frozenset({TaossType.TEM, TaossType.EMO}))
    print("decoded (consented ∩ declared):", {t.name: v.shape for t, v in typed.items()})
    return 0 if report.ok and dec.ok and set(typed) == {TaossType.TEM} else 1


if __name__ == "__main__":
    sys.exit(main())
