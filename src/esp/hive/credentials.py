# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Anonymous Hive membership with BBS credentials and per-episode pseudonyms (GAP-017).

The cryptography is never re-implemented here. ``esp-rs credential`` wraps the
`zkryptium` crate (Apache-2.0), which implements these IRTF CFRG drafts with
ciphersuite BLS12-381-SHA-256:

- BBS signatures (draft-12);
- blind BBS signatures (draft-02);
- BBS per-verifier linkability (draft-03).

**Issuance (blind).** The member commits to a random pseudonym secret. The issuer
verifies the commitment proof and signs it together with public attributes
(``class:<episode class>``), adding its own entropy. The issuer never learns the
member's final pseudonym secret.

**Joining an episode.**
- The member proves possession of an issuer credential and discloses only the class
  attribute.
- The pseudonym is bound to ``context_id = "esp/v1/hive-episode" ‖ episode_id`` and is
  deterministic per member and episode. A second join with the same credential produces
  the same pseudonym and is refused.
- Pseudonyms of different episodes cannot be linked.
- The presentation header is the object's authorization domain and signed fields, so
  a proof authorizes exactly one join, contribution or exit object.

**Wire.**
- ``member_ref = BLAKE2b-256("esp/v1/hive-bbs-nym" ‖ pseudonym)``;
- ``proof = pseudonym[48] ‖ bbs_proof``.

The suite plugs into :class:`~esp.hive.membership.CredentialSuite`. Its
``membership_root`` is :func:`issuer_root`, which binds the issuer key and the class.
"""

from __future__ import annotations

import hashlib
import json
import subprocess
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from esp.hive.membership import CONTRIBUTION_AUTH, EXIT_AUTH
from esp.hive.mls import default_binary
from esp.hive.tlv import HiveContribution, HiveError, HiveExit

SUITE_ID: Final = "esp-hive-bbs-nym-v1"
HEADER: Final = b"esp/v1/hive-credential"
PSEUDONYM_LEN: Final = 48
_CONTEXT: Final = b"esp/v1/hive-episode"
_REF: Final = b"esp/v1/hive-bbs-nym"
_ROOT: Final = b"esp/v1/hive-bbs-issuer"

HiveObject = HiveContribution | HiveExit


class CredentialError(HiveError):
    pass


def _b2(data: bytes) -> bytes:
    return hashlib.blake2b(data, digest_size=32).digest()


def context_id(episode_id: uuid.UUID) -> bytes:
    return _CONTEXT + episode_id.bytes


def member_ref(pseudonym: bytes) -> bytes:
    return _b2(_REF + pseudonym)


def class_attribute(episode_class: str) -> bytes:
    return b"class:" + episode_class.encode()


def issuer_root(issuer_pk: bytes, episode_class: str) -> bytes:
    """Membership root of a BBS episode: binds the trusted issuer key and the required class."""
    return _b2(
        _ROOT + len(issuer_pk).to_bytes(2, "big") + issuer_pk + class_attribute(episode_class)
    )


def _presentation_header(obj: HiveObject) -> bytes:
    domain = CONTRIBUTION_AUTH if isinstance(obj, HiveContribution) else EXIT_AUTH
    return domain + obj.signed_fields()


@dataclass(frozen=True, slots=True)
class CredentialTool:
    """Stateless driver for ``esp-rs credential`` (one JSON line per operation)."""

    binary: Path = field(default_factory=default_binary)

    def run(self, requests: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        if not self.binary.is_file():
            msg = f"esp-rs binary not found at {self.binary} (cargo build --release)"
            raise CredentialError(msg)
        payload = "".join(json.dumps(r) + "\n" for r in requests)
        proc = subprocess.run(  # noqa: S603 - fixed binary, JSON on stdin
            [str(self.binary), "credential"],
            input=payload,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode != 0:
            msg = f"esp-rs credential failed: {proc.stderr.strip()[:200]}"
            raise CredentialError(msg)
        out = [json.loads(line) for line in proc.stdout.splitlines() if line.strip()]
        if len(out) != len(requests):
            msg = "esp-rs credential returned a wrong number of responses"
            raise CredentialError(msg)
        return out

    def one(self, request: Mapping[str, Any]) -> dict[str, Any]:
        res = self.run([request])[0]
        if not res.get("ok"):
            raise CredentialError(str(res.get("error", "credential operation failed")))
        return res


@dataclass(frozen=True, slots=True)
class Issuer:
    """Issues blind BBS credentials for one episode class."""

    episode_class: str
    sk: bytes
    pk: bytes
    tool: CredentialTool = field(default_factory=CredentialTool)

    @classmethod
    def create(cls, episode_class: str, tool: CredentialTool | None = None) -> Issuer:
        t = tool or CredentialTool()
        k = t.one({"op": "keygen"})
        return cls(episode_class, bytes.fromhex(k["sk"]), bytes.fromhex(k["pk"]), t)

    @property
    def attributes(self) -> list[bytes]:
        return [class_attribute(self.episode_class)]

    @property
    def root(self) -> bytes:
        return issuer_root(self.pk, self.episode_class)

    def blind_sign(self, commitment: bytes) -> tuple[bytes, bytes]:
        """Verify the member's commitment proof and sign; returns (signature, entropy)."""
        r = self.tool.one(
            {
                "op": "blind_sign",
                "sk": self.sk.hex(),
                "pk": self.pk.hex(),
                "commitment": commitment.hex(),
                "header": HEADER.hex(),
                "messages": [m.hex() for m in self.attributes],
            }
        )
        return bytes.fromhex(r["signature"]), bytes.fromhex(r["signer_nym_entropy"])


@dataclass
class AnonymousCredential:
    """A member's credential. All secrets stay with the member."""

    issuer_pk: bytes
    attributes: list[bytes]
    signature: bytes
    nym_secret: bytes
    prover_blind: bytes
    tool: CredentialTool = field(default_factory=CredentialTool)
    _pseudonyms: dict[uuid.UUID, bytes] = field(default_factory=dict, repr=False)

    @classmethod
    def obtain(cls, issuer: Issuer, tool: CredentialTool | None = None) -> AnonymousCredential:
        """Blind issuance: commit, let the issuer sign, verify and finalize."""
        t = tool or issuer.tool
        c = t.one({"op": "commit", "committed": []})
        signature, entropy = issuer.blind_sign(bytes.fromhex(c["commitment"]))
        f = t.one(
            {
                "op": "finalize",
                "pk": issuer.pk.hex(),
                "header": HEADER.hex(),
                "messages": [m.hex() for m in issuer.attributes],
                "committed": [],
                "prover_nym": c["prover_nym"],
                "signer_nym_entropy": entropy.hex(),
                "prover_blind": c["prover_blind"],
                "signature": signature.hex(),
            }
        )
        return cls(
            issuer.pk,
            issuer.attributes,
            signature,
            bytes.fromhex(f["nym_secret"]),
            bytes.fromhex(c["prover_blind"]),
            t,
        )

    def _prove(self, episode_id: uuid.UUID, ph: bytes) -> tuple[bytes, bytes]:
        r = self.tool.one(
            {
                "op": "prove",
                "pk": self.issuer_pk.hex(),
                "signature": self.signature.hex(),
                "header": HEADER.hex(),
                "ph": ph.hex(),
                "nym_secret": self.nym_secret.hex(),
                "context": context_id(episode_id).hex(),
                "messages": [m.hex() for m in self.attributes],
                "committed": [],
                "disclosed": [0],  # only the class attribute
                "disclosed_committed": [],
                "prover_blind": self.prover_blind.hex(),
            }
        )
        return bytes.fromhex(r["proof"]), bytes.fromhex(r["pseudonym"])

    def pseudonym(self, episode_id: uuid.UUID) -> bytes:
        """Deterministic per episode; computed once with a throw-away presentation."""
        if episode_id not in self._pseudonyms:
            _, nym = self._prove(episode_id, b"esp/v1/hive-pseudonym-probe")
            self._pseudonyms[episode_id] = nym
        return self._pseudonyms[episode_id]

    def member_ref(self, episode_id: uuid.UUID) -> bytes:
        return member_ref(self.pseudonym(episode_id))

    def authorize(self, obj: HiveObject) -> bytes:
        """The proof field for ``obj`` (its member_ref must be this credential's)."""
        if obj.member_ref != self.member_ref(obj.episode_id):
            msg = "object member_ref does not belong to this credential"
            raise CredentialError(msg)
        proof, nym = self._prove(obj.episode_id, _presentation_header(obj))
        return nym + proof


@dataclass(frozen=True, slots=True)
class BbsCredentialSuite:
    """``esp-hive-bbs-nym-v1``: anonymous membership with per-episode pseudonyms."""

    issuer_pk: bytes
    episode_class: str
    tool: CredentialTool = field(default_factory=CredentialTool)
    suite_id: str = SUITE_ID
    provides_anonymity: bool = True

    def verify(self, obj: HiveObject, root: bytes) -> None:
        if root != issuer_root(self.issuer_pk, self.episode_class):
            msg = "membership root does not bind this issuer and class"
            raise CredentialError(msg)
        p = obj.proof
        if len(p) <= PSEUDONYM_LEN:
            msg = "credential proof truncated"
            raise CredentialError(msg)
        nym, proof = p[:PSEUDONYM_LEN], p[PSEUDONYM_LEN:]
        if member_ref(nym) != obj.member_ref:
            msg = "member_ref is not derived from the presented pseudonym"
            raise CredentialError(msg)
        res = self.tool.run(
            [
                {
                    "op": "verify",
                    "pk": self.issuer_pk.hex(),
                    "header": HEADER.hex(),
                    "ph": _presentation_header(obj).hex(),
                    "proof": proof.hex(),
                    "pseudonym": nym.hex(),
                    "context": context_id(obj.episode_id).hex(),
                    "total": 1,
                    "disclosed": {"0": class_attribute(self.episode_class).hex()},
                    "disclosed_committed": {},
                }
            ]
        )[0]
        if not res.get("ok") or res.get("valid") is not True:
            msg = f"anonymous credential proof rejected: {res.get('error', 'invalid')}"
            raise CredentialError(msg)
