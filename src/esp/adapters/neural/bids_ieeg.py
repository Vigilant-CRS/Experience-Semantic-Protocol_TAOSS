# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""BIDS-iEEG replay adapter (M18, WP-087).

A BIDS-iEEG recording becomes the same
:class:`~esp.adapters.neural.interface.NeuralAdapter` contract as an NWB file
or a live device. The reader uses:

- ``*_ieeg.json``: ``SamplingFrequency`` (required) and ``iEEGReference``;
- ``*_channels.tsv``: ``name``, ``type``, ``units``, ``status`` (good/bad),
  ``group`` and the hardware filter (``low_cutoff``, ``high_cutoff``, ``notch``).
  Types map to ESP modalities: ECOG, SEEG, DBS→LFP, EEG, EMG, EOG→EYE, ECG.
  TRIG and MISC have no neutral ESP modality and are refused when requested;
  by default only ECOG, SEEG and DBS are replayed;
- ``*_electrodes.tsv`` (subject/session level): ``x``, ``y``, ``z``, ``group``
  and ``location``;
- sidecars follow the BIDS inheritance principle: a file whose entities are a
  subset of the recording's entities applies (e.g. ``task-rest_run-1_events.tsv``
  for ``task-rest_acq-clinical_run-1``); the most specific one wins;
- ``*_events.tsv``: ``onset`` and ``trial_type`` (or ``value``) become an
  :class:`~esp.adapters.physio.stream.EventBlock`;
- ``dataset_description.json``: ``License``, ``EthicsApprovals`` and
  ``DatasetDOI``, for the ``L4-REPLAY`` declaration.

Data comes from EDF/BDF or BrainVision (the existing physiology readers) or
from NWB (delegated to :mod:`esp.adapters.neural.nwb`). Timestamps are relative
to the start of the recording, as are BIDS event onsets, so events and samples
share one clock domain. Values are converted to the unit declared in
``channels.tsv``; a dimension mismatch between file and sidecar is refused.
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final

import numpy as np

from esp.adapters.neural.interface import NeuralAdapterInfo, NeuralLevel
from esp.adapters.neural.model import (
    INVASIVE,
    ElectrodeSpec,
    ElectrodeStatus,
    NeuralDeviceDescriptor,
    ProcessingStep,
    ReplayDeclaration,
)
from esp.adapters.neural.replay import (
    ArrayReplay,
    ReplayError,
    pseudonymous_id,
    seconds_to_ns,
    spdx_license,
    unit_scale,
)
from esp.adapters.physio.files import read_brainvision, read_edf
from esp.adapters.physio.stream import (
    ChannelSpec,
    EventBlock,
    normalize_channel,
    normalize_unit,
    regular_timestamps,
)
from esp.observation.model import DeviceMetadata, Modality

BIDS_TYPES: Final = {
    "ECOG": Modality.ECOG,
    "SEEG": Modality.SEEG,
    "DBS": Modality.LFP,
    "EEG": Modality.EEG,
    "EMG": Modality.EMG,
    "EOG": Modality.EYE,
    "ECG": Modality.ECG,
}
DEFAULT_TYPES: Final = ("ECOG", "SEEG", "DBS")
_SUFFIX: Final = re.compile(r"_ieeg\.(edf|bdf|vhdr|nwb)$", re.IGNORECASE)
_DOI_VERSION: Final = re.compile(r"\.v(\d+(?:\.\d+)*)$")


def _entities(stem: str) -> dict[str, str]:
    """BIDS ``key-value`` entities of a file stem (the trailing suffix is not an entity)."""
    return dict(p.split("-", 1) for p in stem.split("_") if "-" in p and not p.startswith("-"))


def _inherited(
    folder: Path, suffix: str, mine: dict[str, str], *, required: Sequence[str] = ("sub", "task")
) -> Path | None:
    """Most specific sidecar ``*_<suffix>`` whose entities are a subset of ``mine``."""
    best: tuple[int, str, Path] | None = None
    for p in folder.glob(f"*_{suffix}"):
        ent = _entities(p.name[: -len(suffix) - 1])
        if not ent.items() <= mine.items() or any(k not in ent for k in required if k in mine):
            continue
        if best is None or (len(ent), p.name) > best[:2]:
            best = (len(ent), p.name, p)
    return best[2] if best else None


def _tsv(path: Path) -> list[dict[str, str]]:
    with path.open(newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh, delimiter="\t"))


@dataclass(frozen=True, slots=True)
class BidsRecording:
    """Sidecar paths of one BIDS-iEEG recording."""

    data: Path
    prefix: str
    sidecar: Path
    channels: Path
    events: Path | None
    electrodes: Path | None
    root: Path | None

    @classmethod
    def locate(cls, data: Path) -> BidsRecording:
        m = _SUFFIX.search(data.name)
        if m is None:
            msg = f"not a BIDS-iEEG data file: {data.name}"
            raise ReplayError(msg)
        prefix = data.name[: m.start()]
        d = data.parent
        sidecar, channels = d / f"{prefix}_ieeg.json", d / f"{prefix}_channels.tsv"
        for p in (data, sidecar, channels):
            if not p.is_file():
                msg = f"missing BIDS file {p.name}"
                raise ReplayError(msg)
        mine = _entities(prefix)
        events = _inherited(d, "events.tsv", mine)
        electrodes = _inherited(d, "electrodes.tsv", mine, required=("sub",))
        root = next((p for p in data.parents if (p / "dataset_description.json").is_file()), None)
        return cls(
            data,
            prefix,
            sidecar,
            channels,
            events,
            electrodes,
            root,
        )


def bids_declaration(
    root: Path, *, url: str | None = None, version: str | None = None
) -> ReplayDeclaration | None:
    """``L4-REPLAY`` declaration from ``dataset_description.json``; ``None`` if unpinnable."""
    desc = json.loads((root / "dataset_description.json").read_text(encoding="utf-8"))
    doi = str(desc.get("DatasetDOI") or "").removeprefix("doi:").removeprefix("https://doi.org/")
    url = url or (f"https://doi.org/{doi}" if doi else None)
    if version is None and doi and (m := _DOI_VERSION.search(doi)):
        version = m.group(1)
    if not url or not version:
        return None
    ethics = [str(e) for e in desc.get("EthicsApprovals") or []]
    return ReplayDeclaration(
        dataset_id=f"DOI:{doi}" if doi else f"BIDS:{desc.get('Name', root.name)}",
        version=version,
        license=spdx_license(desc.get("License")),
        consent_basis="; ".join(ethics) if ethics else f"see dataset documentation {url}",
        url=url,
        citation=str(desc.get("HowToAcknowledge") or ""),
    )


def _read_data(rec: BidsRecording, rate: float) -> tuple[list[str], list[str], np.ndarray]:
    """(normalized channel names, units, values) of the block at the declared rate."""
    suffix = rec.data.suffix.lower()
    if suffix in {".edf", ".bdf"}:
        recording = read_edf(rec.data)
    elif suffix == ".vhdr":
        recording = read_brainvision(rec.data)
    else:  # pragma: no cover - NWB is routed before this call
        msg = f"unsupported data format {suffix}"
        raise ReplayError(msg)
    blocks = [
        b for b in recording.blocks if b.nominal_rate_hz and np.isclose(b.nominal_rate_hz, rate)
    ]
    if len(blocks) != 1:
        msg = f"no unique data block at the declared {rate} Hz"
        raise ReplayError(msg)
    b = blocks[0]
    return [c.name for c in b.channels], [c.unit for c in b.channels], np.asarray(b.values)


def _electrode(name: str, channel: dict[str, str], coords: dict[str, str]) -> ElectrodeSpec:
    """Merge a ``channels.tsv`` row (status) with its ``electrodes.tsv`` row (position)."""

    def num(key: str) -> float | None:
        v = coords.get(key, "n/a")
        return None if v in {"", "n/a"} else float(v)

    status = channel.get("status", "").lower()
    group = coords.get("group", "") or channel.get("group", "")
    return ElectrodeSpec(
        name=name,
        group="" if group == "n/a" else group,
        location=coords.get("location", "") or coords.get("anat", ""),
        x_mm=num("x"),
        y_mm=num("y"),
        z_mm=num("z"),
        status={"good": ElectrodeStatus.GOOD, "bad": ElectrodeStatus.BAD}.get(
            status, ElectrodeStatus.UNKNOWN
        ),
    )


def _hardware_filter(rows: Sequence[dict[str, str]]) -> tuple[ProcessingStep, ...]:
    """The channels' hardware filter as declared in ``channels.tsv`` (values as written, Hz)."""
    params = []
    for key in ("low_cutoff", "high_cutoff", "notch"):
        values = {r.get(key) or "n/a" for r in rows}
        if values != {"n/a"}:
            params.append((f"{key}_hz", values.pop() if len(values) == 1 else "mixed"))
    return (ProcessingStep("hardware_filter", tuple(params)),) if params else ()


def _select(rec: BidsRecording, types: Sequence[str], *, include_bad: bool) -> list[dict[str, str]]:
    unknown = set(types) - set(BIDS_TYPES)
    if unknown:
        msg = f"no neutral ESP modality for channel types {sorted(unknown)}"
        raise ReplayError(msg)
    rows = [r for r in _tsv(rec.channels) if r.get("type", "").upper() in set(types)]
    if not include_bad:
        rows = [r for r in rows if r.get("status", "").lower() != "bad"]
    if not rows:
        msg = "no channels of the requested types"
        raise ReplayError(msg)
    return rows


def bids_ieeg_adapter(
    data: Path,
    *,
    types: Sequence[str] = DEFAULT_TYPES,
    replay: ReplayDeclaration | None = None,
    include_bad: bool = True,
) -> ArrayReplay:
    """Replay the selected channel types of one BIDS-iEEG recording."""
    rec = BidsRecording.locate(data)
    meta = json.loads(rec.sidecar.read_text(encoding="utf-8"))
    rate = float(meta.get("SamplingFrequency") or 0.0)
    if not rate > 0:
        msg = "SamplingFrequency missing in the iEEG sidecar"
        raise ReplayError(msg)
    rows = _select(rec, types, include_bad=include_bad)
    if rec.data.suffix.lower() == ".nwb":
        msg = "NWB data in BIDS: use esp.adapters.neural.nwb.electrical_series_adapter"
        raise ReplayError(msg)
    names, units, values = _read_data(rec, rate)
    index = {n: i for i, n in enumerate(names)}
    coords = {}
    if rec.electrodes is not None:
        coords = {normalize_channel(r["name"]): r for r in _tsv(rec.electrodes)}
    cols, specs, electrodes, modalities = [], [], [], set()
    scales = []
    for r in rows:
        name = normalize_channel(r["name"])
        if name not in index:
            msg = f"channel {r['name']!r} from channels.tsv is not in the data file"
            raise ReplayError(msg)
        modality = BIDS_TYPES[r["type"].upper()]
        unit = normalize_unit(r.get("units") or units[index[name]])
        scales.append(unit_scale(units[index[name]], unit))
        cols.append(index[name])
        specs.append(ChannelSpec(name, modality, unit))
        modalities.add(modality)
        electrodes.append(_electrode(name, r, coords.get(name, {})))
    if len({s.unit for s in specs}) != 1:
        msg = "selected channels must share one unit"
        raise ReplayError(msg)
    vals = values[:, cols] * np.asarray(scales)
    invasive = bool(modalities & INVASIVE)
    if invasive and replay is None and rec.root is not None:
        replay = bids_declaration(rec.root)
    dataset = rec.root.name if rec.root is not None else "bids"
    key = pseudonymous_id(dataset, rec.prefix)
    clock = f"replay:bids:{key}"
    device_id = f"replay-bids-{key}"
    descriptor = NeuralDeviceDescriptor(
        manufacturer=str(meta.get("Manufacturer") or "unspecified (recording)"),
        model=str(meta.get("ManufacturersModelName") or "bids-ieeg-recording"),
        firmware=str(meta.get("SoftwareVersions") or "n/a (replay)"),
        device_id=device_id,
        modalities=frozenset(modalities),
        electrodes=tuple(electrodes),
        unit=specs[0].unit,
        clock_domain=clock,
        sampling_rate_hz=rate,
        reference=str(meta.get("iEEGReference") or ""),
        processing=(
            *_hardware_filter(rows),
            *(
                ProcessingStep(k.lower(), (("hz", str(meta[k])),))
                for k in ("PowerLineFrequency", "SoftwareFilters")
                if k in meta and not isinstance(meta[k], dict)
            ),
        ),
    )
    info = NeuralAdapterInfo(
        adapter_id=f"bids:{rec.prefix}",
        device=DeviceMetadata(device_id=device_id, kind="bids-ieeg", sampling_rate_hz=rate),
        channels=tuple(specs),
        nominal_rate_hz=rate,
        level=NeuralLevel.L4_INVASIVE if invasive else NeuralLevel.L3_NON_INVASIVE,
        clock_domain=clock,
        descriptor=descriptor,
        replay=replay if invasive else None,
    )
    ts = regular_timestamps(0, vals.shape[0], rate)
    return ArrayReplay(info, rec.prefix, np.ascontiguousarray(vals, dtype=np.float64), ts)


def read_bids_events(data: Path, *, label_column: str | None = None) -> EventBlock:
    """``*_events.tsv`` onsets (seconds from recording start) as events."""
    rec = BidsRecording.locate(data)
    if rec.events is None:
        msg = "no events.tsv for this recording"
        raise ReplayError(msg)
    rows = _tsv(rec.events)
    column = label_column or next(
        (c for c in ("trial_type", "value") if rows and c in rows[0]), None
    )
    onsets = np.asarray([float(r["onset"]) for r in rows], dtype=np.float64)
    labels = [r[column] if column else "event" for r in rows]
    order = np.argsort(onsets, kind="stable")
    dataset = rec.root.name if rec.root is not None else "bids"
    return EventBlock(
        stream="events",
        timestamps_ns=tuple(int(x) for x in seconds_to_ns(onsets[order])),
        labels=tuple(labels[i] for i in order),
        clock_domain=f"replay:bids:{pseudonymous_id(dataset, rec.prefix)}",
    )
