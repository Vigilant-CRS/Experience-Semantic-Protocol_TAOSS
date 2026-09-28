# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Registry governance and service (WP-077).

Registries: anchor sets (ontology), TAOSS type-set profiles, DP profiles,
addendum TLV codes, error codes, decoder policies, relation classes.

- **Snapshot**: canonical JSON (ESP canonical JSON v1) of the entries, a
  BLAKE2b-256 digest, and Ed25519 signatures of the governance roles over
  ``"esp/v1/registry-snapshot" ‖ name ‖ 0x00 ‖ version ‖ 0x00 ‖ digest``.
- **Change process**: PROPOSED → REVIEWED (a reviewer signs) → FROZEN (a
  maintainer signs; regulated registries additionally need a regulator).
  Frozen snapshots never change; a change is a new version that names its
  predecessor.
- **Export**: a static bundle (JSON + digests) that travels on the BULK
  channel; receivers verify signatures and that each digest equals what the
  session descriptor pinned.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Final

from esp.core.errors import ErrorCode
from esp.core.model import canonical_json_bytes
from esp.crypto.primitives import CryptoError, SigningKey, blake2b, ed25519_verify
from esp.ontology.profiles import basic8_registry
from esp.privacy.dp import REFERENCE_PROFILES
from esp.semantics.bindings import RelationClass
from esp.session.descriptor import DecoderPolicy
from esp.session.profiles import CUSTOM_PROFILES, SF_LEVELS

DOMAIN: Final = b"esp/v1/registry-snapshot"
ADDENDUM_TLV_CODES: Final = {
    0x80: "SESSION_DESCRIPTOR",
    0x81: "SESSION_CLOSE",
    0x82: "ERROR",
    0x83: "REGISTRY_DIGEST",
    0x84: "STATIC_KEY_BINDING",
    0x85: "SESSION_BINDING",
    0x86: "SOS",
    0x87: "DUMMY_TYPES",
    0x88: "FILLER",
    0x89: "REPLAY_WATERMARK",
    0x90: "SEMANTIC_BINDING",
    0x91: "EVIDENCE_CLAIM",
    0x92: "AFFECT_DESCRIPTOR",
    0x93: "EMOTION_EPISODE",
    0x94: "INTENTION_STATE",
    0x95: "FRAME_METADATA",
    0x98: "AGENT_OPAQUE_LATENT_DESCRIPTOR",
    0x99: "AGENT_EVENT",
}


class Role(StrEnum):
    MAINTAINER = "maintainer"
    REVIEWER = "reviewer"
    REGULATOR = "regulator"


class State(StrEnum):
    PROPOSED = "proposed"
    REVIEWED = "reviewed"
    FROZEN = "frozen"


#: Registries whose changes also need a regulator signature.
REGULATED: Final = frozenset({"esp-dp-profiles-v1", "esp-error-codes-v1"})


class GovernanceError(ValueError):
    pass


def builtin_entries() -> dict[str, Any]:
    """Entries of every v1 registry, derived from the code (single source of truth)."""
    ontology = basic8_registry()
    profiles = {
        **{
            f"SF{k}": {
                "required": sorted(t.name for t in p.required),
                "optional": sorted(t.name for t in p.optional),
            }
            for k, p in SF_LEVELS.items()
        },
        **{
            name: {
                "required": sorted(t.name for t in p.required),
                "optional": sorted(t.name for t in p.optional),
            }
            for name, p in CUSTOM_PROFILES.items()
        },
    }
    return {
        "esp-emo-v13-basic8-v1": json.loads(ontology.canonical_json()),
        "esp-taoss-profiles-v1": profiles,
        "esp-dp-profiles-v1": {
            lvl.name: {"epsilon": eps, "sigma": round(sigma, 6)}
            for lvl, (eps, sigma) in REFERENCE_PROFILES.items()
        },
        "esp-addendum-tlv-codes-v1": {
            f"0x{c:02x}": n for c, n in sorted(ADDENDUM_TLV_CODES.items())
        },
        "esp-error-codes-v1": {c.name: c.value for c in ErrorCode},
        "esp-decoder-policies-v1": {p.name: p.value for p in DecoderPolicy},
        "esp-relation-classes-v1": sorted(r.value for r in RelationClass),
    }


@dataclass
class Snapshot:
    name: str
    version: int
    entries: Any
    supersedes: str | None = None
    """Digest of the previous version (None for version 1)."""
    state: State = State.PROPOSED
    signatures: dict[str, tuple[bytes, bytes]] = field(default_factory=dict)
    """role -> (public key, signature)."""

    @property
    def canonical(self) -> bytes:
        return canonical_json_bytes(self.entries)

    @property
    def digest(self) -> bytes:
        return blake2b(self.canonical)

    def message(self) -> bytes:
        return (
            DOMAIN
            + self.name.encode()
            + b"\x00"
            + str(self.version).encode()
            + b"\x00"
            + self.digest
        )

    def sign(self, role: Role, key: SigningKey) -> None:
        if self.state is State.FROZEN:
            msg = "frozen snapshots cannot be changed or re-signed"
            raise GovernanceError(msg)
        self.signatures[role.value] = (key.public_bytes, key.sign(self.message()))

    def review(self, reviewer: SigningKey) -> None:
        if self.state is not State.PROPOSED:
            msg = "only proposals can be reviewed"
            raise GovernanceError(msg)
        self.sign(Role.REVIEWER, reviewer)
        self.state = State.REVIEWED

    def freeze(self, maintainer: SigningKey, regulator: SigningKey | None = None) -> None:
        if self.state is not State.REVIEWED:
            msg = "a snapshot must be reviewed before it is frozen"
            raise GovernanceError(msg)
        if self.name in REGULATED and regulator is None:
            msg = f"{self.name} is regulated: a regulator signature is required"
            raise GovernanceError(msg)
        self.sign(Role.MAINTAINER, maintainer)
        if regulator is not None:
            self.sign(Role.REGULATOR, regulator)
        self.state = State.FROZEN

    def successor(self, entries: object) -> Snapshot:
        if self.state is not State.FROZEN:
            msg = "only frozen snapshots can be superseded"
            raise GovernanceError(msg)
        return Snapshot(self.name, self.version + 1, entries, supersedes=self.digest.hex())

    def to_json(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "state": self.state.value,
            "supersedes": self.supersedes,
            "digest": self.digest.hex(),
            "entries": self.entries,
            "signatures": {
                r: {"pk": pk.hex(), "sig": sig.hex()}
                for r, (pk, sig) in sorted(self.signatures.items())
            },
        }


def verify_snapshot(doc: Mapping[str, Any], trusted: Mapping[Role, frozenset[bytes]]) -> Snapshot:
    """Recompute the digest and check every required role signature against trusted keys."""
    snap = Snapshot(doc["name"], int(doc["version"]), doc["entries"], doc.get("supersedes"))
    if snap.digest.hex() != doc["digest"]:
        msg = f"{snap.name}: digest does not match the entries"
        raise GovernanceError(msg)
    needed = {Role.REVIEWER, Role.MAINTAINER} | (
        {Role.REGULATOR} if snap.name in REGULATED else set()
    )
    for role in needed:
        entry = doc["signatures"].get(role.value)
        if entry is None:
            msg = f"{snap.name}: missing {role.value} signature"
            raise GovernanceError(msg)
        pk, sig = bytes.fromhex(entry["pk"]), bytes.fromhex(entry["sig"])
        if pk not in trusted.get(role, frozenset()):
            msg = f"{snap.name}: {role.value} key is not trusted"
            raise GovernanceError(msg)
        try:
            ed25519_verify(pk, snap.message(), sig)
        except CryptoError:
            msg = f"{snap.name}: bad {role.value} signature"
            raise GovernanceError(msg) from None
        snap.signatures[role.value] = (pk, sig)
    snap.state = State.FROZEN
    return snap


def export_bundle(snapshots: Sequence[Snapshot]) -> bytes:
    """Static registry export for the BULK channel (frozen snapshots only)."""
    if any(s.state is not State.FROZEN for s in snapshots):
        msg = "only frozen snapshots are exported"
        raise GovernanceError(msg)
    return canonical_json_bytes(
        {"format": "esp-registry-bundle-v1", "snapshots": [s.to_json() for s in snapshots]}
    )


def import_bundle(
    raw: bytes, trusted: Mapping[Role, frozenset[bytes]], pinned: Mapping[str, bytes]
) -> dict[str, Snapshot]:
    """Verify a received bundle; every snapshot must match the digest the session pinned."""
    doc = json.loads(raw)
    if doc.get("format") != "esp-registry-bundle-v1":
        msg = "unknown registry bundle format"
        raise GovernanceError(msg)
    out = {}
    for s in doc["snapshots"]:
        snap = verify_snapshot(s, trusted)
        want = pinned.get(snap.name)
        if want is not None and want != snap.digest:
            msg = f"{snap.name}: digest differs from the session pin"
            raise GovernanceError(msg)
        out[snap.name] = snap
    return out
