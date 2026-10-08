# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Neural modality model and the ``L4-REPLAY`` research profile (M18, WP-086).

The raw data a neural device delivers is **not** TAOSS. An implant or an
ECoG grid yields neutral signals:

- voltages (ECoG, sEEG, LFP);
- spike times or binned spike counts;
- vendor-derived features.

This module describes such sources precisely enough that everything above the
adapter works identically for a live device, a recording replayed from NWB or
BIDS-iEEG, and a simulator:

- :class:`NeuralDeviceDescriptor`: manufacturer, model, firmware, a
  pseudonymous device id, modalities, channels with electrode metadata,
  reference, sampling rate or bin width, unit, clock domain and processing
  chain;
- :class:`NeuralProfile`:
  - ``L3_LIVE``: non-invasive, live (EEG/EMG/eye);
  - ``L4_REPLAY``: invasive **recordings**, accepted only with a
    :class:`ReplayDeclaration` naming dataset, version, license and consent basis;
  - ``L4_LIVE``: live invasive. It has no v1 profile and is refused.

No ESP wire change: the descriptor stays inside the sender, and only decoder
outputs cross the boundary as typed parts.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from esp.observation.model import Modality
from esp.observation.units import UNITS

NON_INVASIVE: Final = frozenset({Modality.EEG, Modality.EMG, Modality.EYE})
INVASIVE: Final = frozenset(
    {
        Modality.ECOG,
        Modality.SEEG,
        Modality.LFP,
        Modality.MUA,
        Modality.BROADBAND,
        Modality.SPIKES,
        Modality.SPIKE_COUNTS,
        Modality.NEURAL_FEATURES,
    }
)
AUXILIARY: Final = frozenset(
    {Modality.MOTION, Modality.BEHAVIOR, Modality.EVENT, Modality.AUDIO, Modality.ECG}
)
"""Streams recorded alongside neural data (kinematics, pose, task events, audio, ECG)."""

OPEN_LICENSES: Final = frozenset({"CC-BY-4.0", "CC0-1.0", "CC-BY-SA-4.0", "PDDL-1.0", "ODC-BY-1.0"})
_DEVICE_ID: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:\-]{0,127}$")
_SERIAL_LIKE: Final = re.compile(r"(serial|s/n|sn[:=])", re.IGNORECASE)


class NeuralProfile(StrEnum):
    L3_LIVE = "L3-LIVE"
    L4_REPLAY = "L4-REPLAY"
    L4_LIVE = "L4-LIVE"


class ElectrodeStatus(StrEnum):
    GOOD = "good"
    BAD = "bad"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class ElectrodeSpec:
    """One recording site. ``location`` is an anatomical label (e.g. an atlas region)."""

    name: str
    group: str = ""
    location: str = ""
    x_mm: float | None = None
    y_mm: float | None = None
    z_mm: float | None = None
    status: ElectrodeStatus = ElectrodeStatus.UNKNOWN


@dataclass(frozen=True, slots=True)
class ProcessingStep:
    kind: str
    """e.g. ``highpass``, ``notch``, ``threshold_crossing``, ``binning``, ``car``."""
    parameters: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True, slots=True)
class NeuralDeviceDescriptor:
    manufacturer: str
    model: str
    firmware: str
    device_id: str
    """Pseudonymous, deployment-local. Never a hardware serial number."""
    modalities: frozenset[Modality]
    electrodes: tuple[ElectrodeSpec, ...]
    unit: str
    clock_domain: str
    sampling_rate_hz: float | None = None
    bin_width_s: float | None = None
    """Set for binned streams (e.g. 0.02 s spike-count bins); then rate = 1 / bin width."""
    reference: str = ""
    adc_bits: int | None = None
    processing: tuple[ProcessingStep, ...] = ()

    @property
    def invasive(self) -> bool:
        return bool(self.modalities & INVASIVE)

    @property
    def rate_hz(self) -> float:
        if self.bin_width_s:
            return 1.0 / self.bin_width_s
        return float(self.sampling_rate_hz or 0.0)


@dataclass(frozen=True, slots=True)
class ReplayDeclaration:
    """Why a recorded invasive dataset may be replayed (``L4-REPLAY``)."""

    dataset_id: str
    """e.g. ``DANDI:000954``."""
    version: str
    license: str
    """SPDX identifier; must be an open license."""
    consent_basis: str
    """How participants consented to sharing (from the dataset documentation)."""
    url: str
    citation: str = ""
    manifest_sha256: str = ""
    """Digest of the local ``MANIFEST.json`` pinning every file."""


@dataclass(frozen=True, slots=True)
class DescriptorIssue:
    rule: str
    detail: str


@dataclass(frozen=True, slots=True)
class ProfileCheck:
    profile: NeuralProfile
    issues: tuple[DescriptorIssue, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return not self.issues


def check_descriptor(d: NeuralDeviceDescriptor) -> list[DescriptorIssue]:
    """Structural checks that hold for every profile."""
    out: list[DescriptorIssue] = []
    if not _DEVICE_ID.match(d.device_id) or _SERIAL_LIKE.search(d.device_id):
        out.append(DescriptorIssue("device_id", "device id must be pseudonymous, not a serial"))
    if not d.modalities or d.modalities - NON_INVASIVE - INVASIVE - AUXILIARY:
        out.append(DescriptorIssue("modality", "unknown or empty modality set"))
    if d.unit not in UNITS:
        out.append(DescriptorIssue("unit", f"unit {d.unit!r} is not normalized"))
    if (d.sampling_rate_hz is None) == (d.bin_width_s is None):
        out.append(DescriptorIssue("rate", "declare exactly one of sampling rate or bin width"))
    elif not d.rate_hz > 0:
        out.append(DescriptorIssue("rate", "rate must be positive"))
    if not d.electrodes:
        out.append(DescriptorIssue("electrodes", "no electrodes declared"))
    names = [e.name for e in d.electrodes]
    if len(set(names)) != len(names):
        out.append(DescriptorIssue("electrodes", "electrode names must be unique"))
    if not d.clock_domain:
        out.append(DescriptorIssue("clock", "clock domain required"))
    return out


def check_profile(
    d: NeuralDeviceDescriptor, profile: NeuralProfile, replay: ReplayDeclaration | None = None
) -> ProfileCheck:
    """Admit a source under a profile; live invasive sources are always refused in v1."""
    issues = check_descriptor(d)
    if profile is NeuralProfile.L4_LIVE:
        issues.append(DescriptorIssue("profile", "live invasive sources have no v1 profile"))
    elif profile is NeuralProfile.L3_LIVE:
        if d.invasive:
            issues.append(DescriptorIssue("profile", "invasive modalities need L4-REPLAY"))
        if replay is not None:
            issues.append(DescriptorIssue("profile", "a replay declaration makes this L4-REPLAY"))
    elif profile is NeuralProfile.L4_REPLAY:
        if replay is None:
            issues.append(DescriptorIssue("replay", "L4-REPLAY needs a replay declaration"))
        else:
            if replay.license not in OPEN_LICENSES:
                issues.append(DescriptorIssue("replay", f"license {replay.license!r} not open"))
            if not replay.consent_basis.strip():
                issues.append(DescriptorIssue("replay", "consent basis must be documented"))
            if not replay.url.startswith("https://") or not replay.version:
                issues.append(DescriptorIssue("replay", "pinned https source and version needed"))
    return ProfileCheck(profile, tuple(issues))
