# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Base classes a device maker subclasses (WP-090).

A vendor implements two small methods; the bases take care of the contract
details that are easy to get wrong:

- :class:`BlockAdapter`: implement :meth:`BlockAdapter.acquire` and return
  ``(timestamps_ns, values)`` or ``None`` at the end of the stream. The base
  refuses reads before ``start``, builds the :class:`SampleBlock` with the
  *declared* channels, device and clock domain, and refuses a block that would
  break the clock (non-monotonic or non-integer timestamps). It never repairs data.
- :class:`TypedDecoderBase`: implement :meth:`TypedDecoderBase.decode_one`
  for each output type. The base answers only the requested types, as the
  decoder boundary requires.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Mapping

import numpy as np
from numpy.typing import NDArray

from esp.adapters.neural.interface import NeuralAdapterInfo, NeuralFeatures
from esp.adapters.physio.stream import SampleBlock
from esp.core.taoss_types import TaossType


class AdapterStateError(RuntimeError):
    pass


class BlockAdapter(ABC):
    """Skeleton for a neural source; subclasses implement :meth:`acquire`."""

    def __init__(self, info: NeuralAdapterInfo) -> None:
        self._info = info
        self._running = False
        self._last_ts: int | None = None

    @property
    def info(self) -> NeuralAdapterInfo:
        return self._info

    def start(self) -> None:
        self._running = True
        self._last_ts = None
        self.on_start()

    def stop(self) -> None:
        self._running = False
        self.on_stop()

    def on_start(self) -> None:  # noqa: B027 - optional hook
        """Open the device or file (optional)."""

    def on_stop(self) -> None:  # noqa: B027 - optional hook
        """Release the device or file (optional)."""

    @abstractmethod
    def acquire(self, max_samples: int) -> tuple[NDArray[np.int64], NDArray[np.float64]] | None:
        """Return up to ``max_samples`` samples as ``(timestamps_ns, values[n, channels])``."""

    def read(self, max_samples: int) -> SampleBlock | None:
        if not self._running:
            msg = "adapter not started"
            raise AdapterStateError(msg)
        got = self.acquire(max_samples)
        if got is None:
            return None
        ts, values = got
        ts = np.asarray(ts)
        if ts.dtype != np.int64:
            msg = "timestamps must be int64 nanoseconds"
            raise AdapterStateError(msg)
        if ts.size > max_samples:
            msg = "acquire returned more than max_samples"
            raise AdapterStateError(msg)
        if ts.size and (
            bool((np.diff(ts) <= 0).any())
            or (self._last_ts is not None and int(ts[0]) <= self._last_ts)
        ):
            msg = "timestamps must increase strictly across blocks"
            raise AdapterStateError(msg)
        if ts.size:
            self._last_ts = int(ts[-1])
        return SampleBlock(
            stream=self._info.adapter_id,
            channels=self._info.channels,
            timestamps_ns=ts,
            values=np.asarray(values, dtype=np.float64),
            device=self._info.device,
            clock_domain=self._info.clock_domain,
            nominal_rate_hz=self._info.nominal_rate_hz,
        )


class TypedDecoderBase(ABC):
    """Skeleton for a vendor ``f_decode``; subclasses implement :meth:`decode_one`."""

    decoder_id: str = "vendor-decoder@0.0.0"

    def __init__(self, output_types: frozenset[TaossType]) -> None:
        self._types = frozenset(output_types)

    @property
    def output_types(self) -> frozenset[TaossType]:
        return self._types

    @abstractmethod
    def decode_one(self, t: TaossType, features: NeuralFeatures) -> NDArray[np.float64]:
        """One typed latent (dimension ``L1_DIMS[t]``) for one consented type."""

    def decode(
        self, features: NeuralFeatures, types: frozenset[TaossType]
    ) -> Mapping[TaossType, NDArray[np.float64]]:
        return {t: self.decode_one(t, features) for t in types if t in self._types}
