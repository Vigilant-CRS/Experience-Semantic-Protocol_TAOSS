# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Replay sources that satisfy the same :class:`NeuralAdapter` contract as a device (WP-087).

Everything to the right of an adapter must not be able to tell whether a live
device or a file delivers the samples. Replay adapters therefore:

- emit :class:`~esp.adapters.physio.stream.SampleBlock` objects with int64
  nanosecond timestamps that depend only on the **absolute** sample index.
  Any chunking yields the same concatenated stream (same digest);
- declare device, clock domain, channels and, for invasive recordings, the
  :class:`~esp.adapters.neural.model.ReplayDeclaration` of the ``L4-REPLAY``
  profile;
- read lazily, so a multi-gigabyte NWB file or an HTTP-streamed asset is
  never loaded whole.

:class:`WindowReplay` is the shared base: a subclass supplies ``_values(lo, hi)``
and ``_timestamps(lo, hi)`` for absolute sample ranges.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable
from pathlib import Path
from typing import Final

import numpy as np
from numpy.typing import NDArray

from esp.adapters.neural.interface import NeuralAdapterInfo
from esp.adapters.neural.model import ReplayDeclaration
from esp.adapters.physio.stream import SampleBlock
from esp.observation.units import get_unit

F64 = NDArray[np.float64]
I64 = NDArray[np.int64]


class ReplayError(ValueError):
    """A recording cannot be replayed faithfully (format, unit, clock or declaration)."""


#: Consent statements as published in the DANDI metadata of each dataset (retrieved 2026-09-29).
CONSENT_BASIS: Final = {
    "000954": (
        "Collected under an FDA Investigational Device Exemption, approved by the Institutional "
        "Review Board of the University of Pittsburgh, ClinicalTrials.gov NCT01894802 "
        "(DANDI 000954 metadata)"
    ),
    "000950": (
        "Participant T5 gave informed consent in the BrainGate2 clinical trial, ClinicalTrials.gov "
        "NCT00912041, FDA IDE #G090003, Stanford University IRB protocol #20804 "
        "(DANDI 000950 metadata)"
    ),
    "000055": "Ethics approval STUDY00000623 as listed in the DANDI 000055 metadata",
}


def pseudonymous_id(*parts: str) -> str:
    """Stable, pseudonymous identifier from dataset-level ids (never a person's name)."""
    return hashlib.blake2b("\x1f".join(parts).encode(), digest_size=6).hexdigest()


def spdx_license(raw: object) -> str:
    """``["spdx:CC-BY-4.0"]`` / ``"CC0"`` -> SPDX identifier."""
    value = raw[0] if isinstance(raw, list) and raw else raw
    text = str(value or "").removeprefix("spdx:").strip()
    aliases = {"CC0": "CC0-1.0", "CC-BY": "CC-BY-4.0", "PD": "PDDL-1.0"}
    return aliases.get(text, text)


def declaration_from_manifest(manifest: Path) -> ReplayDeclaration:
    """Replay declaration for a dataset downloaded by ``scripts/fetch_dandi.py``."""
    raw = manifest.read_bytes()
    m = json.loads(raw)
    dandiset = str(m["dandiset"])
    consent = CONSENT_BASIS.get(dandiset) or f"see dataset documentation {m['url']}"
    return ReplayDeclaration(
        dataset_id=f"DANDI:{dandiset}",
        version=str(m["version"]),
        license=spdx_license(m.get("license")),
        consent_basis=consent,
        url=str(m["url"]),
        citation=str(m.get("citation") or ""),
        manifest_sha256=hashlib.sha256(raw).hexdigest(),
    )


def find_manifest(path: Path) -> Path | None:
    """Nearest ``MANIFEST.json`` in ``path``'s directory or its parents."""
    for d in (path if path.is_dir() else path.parent, *path.parents):
        candidate = d / "MANIFEST.json"
        if candidate.is_file():
            return candidate
    return None


def unit_scale(src: str, dst: str) -> float:
    """Multiplicative factor from ``src`` to ``dst`` (same dimension, no offset)."""
    a, b = get_unit(src), get_unit(dst)
    if a.dimension is not b.dimension or a.offset or b.offset:
        msg = f"cannot convert {src} to {dst}"
        raise ReplayError(msg)
    return a.scale / b.scale


def seconds_to_ns(t: F64) -> I64:
    out: I64 = np.rint(np.asarray(t, dtype=np.float64) * 1e9).astype(np.int64)
    return out


class WindowReplay:
    """Base for lazy replay adapters (NeuralAdapter protocol)."""

    def __init__(
        self,
        info: NeuralAdapterInfo,
        stream: str,
        n_samples: int,
        on_stop: Callable[[], None] | None = None,
    ) -> None:
        if n_samples < 0:
            msg = "negative sample count"
            raise ReplayError(msg)
        self._info = info
        self.stream = stream
        self.n_samples = n_samples
        self._on_stop = on_stop
        self._pos = 0
        self._open = False

    @property
    def info(self) -> NeuralAdapterInfo:
        return self._info

    def start(self) -> None:
        self._pos = 0
        self._open = True

    def stop(self) -> None:
        self._open = False
        if self._on_stop is not None:
            self._on_stop()

    def _values(self, lo: int, hi: int) -> F64:
        raise NotImplementedError

    def _timestamps(self, lo: int, hi: int) -> I64:
        raise NotImplementedError

    def read(self, max_samples: int) -> SampleBlock | None:
        if not self._open:
            msg = "start() the adapter before reading"
            raise ReplayError(msg)
        if max_samples < 1:
            msg = "max_samples must be positive"
            raise ReplayError(msg)
        if self._pos >= self.n_samples:
            return None
        lo, hi = self._pos, min(self._pos + max_samples, self.n_samples)
        self._pos = hi
        return SampleBlock(
            stream=self.stream,
            channels=self._info.channels,
            timestamps_ns=self._timestamps(lo, hi),
            values=self._values(lo, hi),
            device=self._info.device,
            clock_domain=self._info.clock_domain,
            nominal_rate_hz=self._info.nominal_rate_hz,
        )

    def read_all(self, chunk: int = 65536) -> list[SampleBlock]:
        """Convenience: replay everything from the start in ``chunk``-sized blocks."""
        self.start()
        out = []
        while (b := self.read(chunk)) is not None:
            out.append(b)
        return out


class ArrayReplay(WindowReplay):
    """Replay of arrays already in memory (e.g. an EDF file read whole)."""

    def __init__(self, info: NeuralAdapterInfo, stream: str, values: F64, timestamps: I64) -> None:
        super().__init__(info, stream, int(values.shape[0]) if values.ndim == 2 else -1)
        if values.ndim != 2 or values.shape[1] != len(info.channels):
            msg = "values must have shape (n_samples, n_channels)"
            raise ReplayError(msg)
        if timestamps.shape != (values.shape[0],):
            msg = "one timestamp per sample"
            raise ReplayError(msg)
        self._array = np.asarray(values, dtype=np.float64)
        self._ts = np.asarray(timestamps, dtype=np.int64)

    def _values(self, lo: int, hi: int) -> F64:
        out: F64 = np.array(self._array[lo:hi], dtype=np.float64)
        return out

    def _timestamps(self, lo: int, hi: int) -> I64:
        out: I64 = np.array(self._ts[lo:hi], dtype=np.int64)
        return out
