# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Alternate TAOSS type decompositions for the type-discovery frontier (WP-074). EXPERIMENTAL.

V13 ("Why Six, Not Three or Twelve"; eq. frontier) keeps the type count a
research question: alternate decompositions coexist on the wire through
``TLV_TYPE_PROFILE`` (0x11, :class:`esp.codec.structure.TypeProfile`), which
names a registry entry by UUID and BLAKE2b-256 digest and never reinterprets
the six TAOSS-6 latent codes.

Here a decomposition is a partition of twelve *semantic atoms* (two per
TAOSS-6 type) into ``K`` types: TAOSS-3, -6, -8 and -12. Each profile has a
canonical entry, a digest and a deterministic profile id, so a sender can
declare it in a TLV. These entries are research fixtures for the synthetic
frontier, not registry-adopted profiles.

A *consent scenario* (after V13 "What This Decomposition Enables") is a set
of atoms to share. It is **expressible** under a profile iff it is exactly a
union of that profile's types — otherwise sharing it either over-discloses
or loses content. This is the privacy-granularity side of the trade-off.
"""

from __future__ import annotations

import uuid
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from esp.codec.structure import TypeProfile
from esp.codec.tlv import Tlv
from esp.core.model import blake2b_256, canonical_json_bytes

ATOMS: Final = (
    "KNOF",  # knowledge: facts
    "KNOS",  # knowledge: skills
    "INTG",  # intention: goal
    "INTR",  # intention: action readiness
    "EMOC",  # emotion: category
    "EMOD",  # emotion: dimensions (valence/arousal)
    "CTXS",  # context: social
    "CTXP",  # context: place
    "SENV",  # sensory: visual
    "SENA",  # sensory: auditory
    "TEMR",  # temporal: rhythm
    "TEMP",  # temporal: phase
)
_NS: Final = uuid.UUID("6f1d3c2a-8e4b-4f7a-9c1d-2b3e4f5a6b7c")


@dataclass(frozen=True, slots=True)
class DecompositionProfile:
    name: str
    types: Mapping[str, tuple[str, ...]]
    """Type name -> atoms, in declared order."""

    def __post_init__(self) -> None:
        flat = [a for atoms in self.types.values() for a in atoms]
        if sorted(flat) != sorted(ATOMS) or len(flat) != len(set(flat)):
            msg = f"{self.name}: types must partition the twelve atoms"
            raise ValueError(msg)
        if any(not atoms for atoms in self.types.values()):
            msg = f"{self.name}: empty type"
            raise ValueError(msg)

    @property
    def k(self) -> int:
        return len(self.types)

    def entry(self) -> dict[str, object]:
        """Canonical registry entry (what the TLV digest binds)."""
        return {
            "profile": self.name,
            "status": "EXPERIMENTAL (WP-074 research fixture)",
            "type_count": self.k,
            "types": [{"name": t, "atoms": list(a)} for t, a in self.types.items()],
        }

    def digest(self) -> bytes:
        return blake2b_256(canonical_json_bytes(self.entry()))

    @property
    def profile_id(self) -> uuid.UUID:
        return uuid.UUID(bytes=uuid.uuid5(_NS, self.name).bytes, version=4)

    def tlv(self) -> Tlv:
        return TypeProfile(self.profile_id, self.k, self.digest()).encode()

    def expressible(self, share: frozenset[str]) -> bool:
        """True iff ``share`` is exactly a union of this profile's types."""
        covered = {a for atoms in self.types.values() if set(atoms) & share for a in atoms}
        return covered == share


PROFILES: Final = {
    p.name: p
    for p in (
        DecompositionProfile(
            "TAOSS-3",
            {
                "SEM": ("KNOF", "KNOS", "CTXS", "CTXP"),
                "AFF": ("INTG", "INTR", "EMOC", "EMOD"),
                "PER": ("SENV", "SENA", "TEMR", "TEMP"),
            },
        ),
        DecompositionProfile(
            "TAOSS-6",
            {
                "KNO": ("KNOF", "KNOS"),
                "INT": ("INTG", "INTR"),
                "EMO": ("EMOC", "EMOD"),
                "CTX": ("CTXS", "CTXP"),
                "SEN": ("SENV", "SENA"),
                "TEM": ("TEMR", "TEMP"),
            },
        ),
        DecompositionProfile(
            "TAOSS-8",
            {
                "KNOF": ("KNOF",),
                "KNOS": ("KNOS",),
                "INT": ("INTG", "INTR"),
                "EMOC": ("EMOC",),
                "EMOD": ("EMOD",),
                "CTX": ("CTXS", "CTXP"),
                "SEN": ("SENV", "SENA"),
                "TEM": ("TEMR", "TEMP"),
            },
        ),
        DecompositionProfile("TAOSS-12", {a: (a,) for a in ATOMS}),
    )
}

SCENARIOS: Final = {
    # V13 "What This Decomposition Enables", expressed in atoms
    "clinician: EMO+CTX, KNO masked": frozenset({"EMOC", "EMOD", "CTXS", "CTXP"}),
    "surgical skill: INT+SEN+TEM, EMO masked": frozenset(
        {"INTG", "INTR", "SENV", "SENA", "TEMR", "TEMP"}
    ),
    "film: EMO+TEM, KNO masked": frozenset({"EMOC", "EMOD", "TEMR", "TEMP"}),
    "collaboration: KNO+INT, EMO masked": frozenset({"KNOF", "KNOS", "INTG", "INTR"}),
    "finer: emotion category without dimensions": frozenset({"EMOC"}),
    "finer: skills without facts": frozenset({"KNOS"}),
}
