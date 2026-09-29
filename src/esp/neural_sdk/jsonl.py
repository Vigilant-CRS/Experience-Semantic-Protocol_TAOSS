# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""JSON-lines process protocol for out-of-process neural adapters (WP-090).

A source written in any language can take part in the neural conformance
check by printing JSON lines. The Rust implementation (``esp-rs neural-sim``)
uses exactly this format.

The first line is the declaration::

    {"type": "info", "contract_version": "1.0.0", "adapter_id": ..., "level": "L3"|"L4",
     "device": {...}, "channels": [{"name", "modality", "unit"}], "nominal_rate_hz": ...,
     "clock_domain": ..., "descriptor": {...}|null, "replay": {...}|null}

Every data block follows as its own line::

    {"type": "block", "stream": ..., "channels": [...], "device": {...}, "clock_domain": ...,
     "timestamps_ns": [...], "values": [[...], ...], "nominal_rate_hz": ...}

An optional last line carries the producer's own contract verdict::

    {"type": "verdict", "ok": ..., "blocks": ..., "samples": ..., "violations": [...]}

A line of any other ``type`` stands for a malformed read. The replaying
adapter returns it unchanged, so the contract check reports it as an
``output`` violation.
"""

from __future__ import annotations

import dataclasses
import json
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

import numpy as np

from esp.adapters.neural.interface import NeuralAdapter, NeuralAdapterInfo, NeuralLevel
from esp.adapters.neural.model import (
    ElectrodeSpec,
    ElectrodeStatus,
    NeuralDeviceDescriptor,
    ProcessingStep,
    ReplayDeclaration,
)
from esp.adapters.physio.stream import ChannelSpec, SampleBlock
from esp.observation.model import DeviceMetadata, Modality


def _channels(raw: list[dict[str, str]]) -> tuple[ChannelSpec, ...]:
    return tuple(ChannelSpec(c["name"], Modality(c["modality"]), c["unit"]) for c in raw)


def _channels_json(chs: Iterable[ChannelSpec]) -> list[dict[str, str]]:
    return [{"name": c.name, "modality": c.modality.value, "unit": c.unit} for c in chs]


def _device(raw: dict[str, Any]) -> DeviceMetadata:
    return DeviceMetadata(**raw)


def _device_json(d: DeviceMetadata) -> dict[str, Any]:
    return d.model_dump(mode="json", exclude_none=True)


def _descriptor(raw: dict[str, Any] | None) -> NeuralDeviceDescriptor | None:
    if raw is None:
        return None
    return NeuralDeviceDescriptor(
        manufacturer=raw["manufacturer"],
        model=raw["model"],
        firmware=raw["firmware"],
        device_id=raw["device_id"],
        modalities=frozenset(Modality(m) for m in raw["modalities"]),
        electrodes=tuple(
            ElectrodeSpec(
                e["name"],
                group=e.get("group", ""),
                location=e.get("location", ""),
                status=ElectrodeStatus(e.get("status", "unknown")),
            )
            for e in raw["electrodes"]
        ),
        unit=raw["unit"],
        clock_domain=raw["clock_domain"],
        sampling_rate_hz=raw.get("sampling_rate_hz"),
        bin_width_s=raw.get("bin_width_s"),
        reference=raw.get("reference", ""),
        processing=tuple(
            ProcessingStep(p["kind"], tuple(sorted(p.get("parameters", {}).items())))
            for p in raw.get("processing", [])
        ),
    )


def _descriptor_json(d: NeuralDeviceDescriptor | None) -> dict[str, Any] | None:
    if d is None:
        return None
    return {
        "manufacturer": d.manufacturer,
        "model": d.model,
        "firmware": d.firmware,
        "device_id": d.device_id,
        "modalities": sorted(m.value for m in d.modalities),
        "electrodes": [
            {"name": e.name, "group": e.group, "location": e.location, "status": e.status.value}
            for e in d.electrodes
        ],
        "unit": d.unit,
        "clock_domain": d.clock_domain,
        "sampling_rate_hz": d.sampling_rate_hz,
        "bin_width_s": d.bin_width_s,
        "reference": d.reference,
        "processing": [{"kind": p.kind, "parameters": dict(p.parameters)} for p in d.processing],
    }


def info_to_json(info: NeuralAdapterInfo, contract_version: str) -> dict[str, Any]:
    return {
        "type": "info",
        "contract_version": contract_version,
        "adapter_id": info.adapter_id,
        "level": info.level.value,
        "device": _device_json(info.device),
        "channels": _channels_json(info.channels),
        "nominal_rate_hz": info.nominal_rate_hz,
        "clock_domain": info.clock_domain,
        "descriptor": _descriptor_json(info.descriptor),
        "replay": None if info.replay is None else dataclasses.asdict(info.replay),
    }


def block_to_json(block: SampleBlock) -> dict[str, Any]:
    return {
        "type": "block",
        "stream": block.stream,
        "channels": _channels_json(block.channels),
        "device": _device_json(block.device),
        "clock_domain": block.clock_domain,
        "timestamps_ns": [int(t) for t in block.timestamps_ns],
        "values": block.values.tolist(),
        "nominal_rate_hz": block.nominal_rate_hz,
    }


def info_from_json(raw: dict[str, Any]) -> NeuralAdapterInfo:
    replay = raw.get("replay")
    return NeuralAdapterInfo(
        adapter_id=raw["adapter_id"],
        device=_device(raw["device"]),
        channels=_channels(raw["channels"]),
        nominal_rate_hz=float(raw["nominal_rate_hz"]),
        level=NeuralLevel(raw["level"]),
        clock_domain=raw["clock_domain"],
        descriptor=_descriptor(raw.get("descriptor")),
        replay=None if replay is None else ReplayDeclaration(**replay),
    )


def block_from_json(raw: dict[str, Any]) -> SampleBlock:
    values = np.asarray(raw["values"], dtype=np.float64)
    channels = _channels(raw["channels"])
    if values.size == 0:
        values = values.reshape(0, len(channels))
    return SampleBlock(
        stream=raw["stream"],
        channels=channels,
        timestamps_ns=np.asarray(raw["timestamps_ns"], dtype=np.int64),
        values=values,
        device=_device(raw["device"]),
        clock_domain=raw["clock_domain"],
        nominal_rate_hz=raw.get("nominal_rate_hz"),
    )


@dataclass
class JsonLinesAdapter:
    """Replays a JSON-lines transcript as a :class:`NeuralAdapter`."""

    info_raw: dict[str, Any]
    reads: list[dict[str, Any]]
    verdict: dict[str, Any] | None = None
    _pos: int = field(default=0, init=False)
    _info: NeuralAdapterInfo | None = field(default=None, init=False)

    @classmethod
    def parse(cls, lines: Iterable[str]) -> JsonLinesAdapter:
        docs = [json.loads(line) for line in lines if line.strip()]
        if not docs or docs[0].get("type") != "info":
            msg = "the first JSON line must be the adapter declaration"
            raise ValueError(msg)
        verdict = docs[-1] if docs[-1].get("type") == "verdict" else None
        body = docs[1:-1] if verdict is not None else docs[1:]
        return cls(docs[0], body, verdict)

    @property
    def contract_version(self) -> str:
        return str(self.info_raw.get("contract_version", ""))

    @property
    def info(self) -> NeuralAdapterInfo:
        if self._info is None:
            self._info = info_from_json(self.info_raw)
        return self._info

    def start(self) -> None:
        self._pos = 0

    def stop(self) -> None:
        pass

    def read(self, max_samples: int) -> SampleBlock | None:
        if self._pos >= len(self.reads):
            return None
        doc = self.reads[self._pos]
        self._pos += 1
        if doc.get("type") != "block":
            return doc  # type: ignore[return-value]  # malformed read: reported as "output"
        return block_from_json(doc)


def dump_adapter(
    adapter: NeuralAdapter, contract_version: str, *, reads: int, max_samples: int
) -> list[str]:
    """Record a Python adapter as JSON lines (the same format other languages print)."""
    lines = [json.dumps(info_to_json(adapter.info, contract_version))]
    adapter.start()
    try:
        for _ in range(reads):
            block = adapter.read(max_samples)
            if block is None:
                break
            lines.append(json.dumps(block_to_json(block)))
    finally:
        adapter.stop()
    return lines
