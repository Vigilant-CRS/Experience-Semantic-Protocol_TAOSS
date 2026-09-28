# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Conformance runner (WP-039): ``esp-conformance run``.

Checks this implementation against the shared vector suite (``vectors/``,
CC BY 4.0) by category — wire, crypto, consent, revocation, identity,
session, replay, privacy, ontology, malformed inputs — and, with
``--peer``, runs live interoperability against another implementation that
speaks the ``esp-rs`` peer contract (``send`` / ``receive`` over the TCP
test transport, JSON lines on stdout).

Every check is a small function returning nothing or raising; the runner
records pass/fail per check and exits non-zero on any failure.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

from esp.codec.header import Header
from esp.codec.tlv import (
    LatentEncoding,
    Tlv,
    decode_typed_latent,
    encode_typed_latent,
    iter_tlvs,
)
from esp.consent.capability import SENDER_CAPABILITY_CODE, ReceiverCapability, SenderCapability
from esp.consent.revocation import DeletionAttestation, RevocationIntent
from esp.core.taoss_types import type_from_tlv_code
from esp.crypto.envelope import open_packet, seal_packet
from esp.crypto.identity import IdentityProof, verify_session_binding
from esp.crypto.keys import DirectionKeys
from esp.crypto.primitives import SigningKey
from esp.ontology.profiles import basic8_registry
from esp.privacy.dp import DpParams
from esp.session.descriptor import SessionDescriptor
from esp.session.replay import ReplayError, ReplayWindow

DEFAULT_VECTORS = Path(__file__).resolve().parents[3] / "vectors"


class ConformanceError(AssertionError):
    pass


def _require(ok: bool, msg: str) -> None:
    if not ok:
        raise ConformanceError(msg)


@dataclass
class Result:
    category: str
    name: str
    passed: bool
    detail: str = ""


@dataclass
class Report:
    results: list[Result] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        return bool(self.results) and all(r.passed for r in self.results)

    def summary(self) -> dict[str, dict[str, int]]:
        out: dict[str, dict[str, int]] = {}
        for r in self.results:
            c = out.setdefault(r.category, {"passed": 0, "failed": 0})
            c["passed" if r.passed else "failed"] += 1
        return out


class Suite:
    def __init__(self, vectors: Path) -> None:
        self.vectors = vectors
        self.report = Report()

    def load(self, rel: str) -> list[dict[str, Any]]:
        vs: list[dict[str, Any]] = json.loads((self.vectors / rel).read_text(encoding="utf-8"))[
            "vectors"
        ]
        return vs

    def check(self, category: str, name: str, fn: Callable[[], object]) -> None:
        try:
            fn()
        except Exception as exc:
            detail = f"{type(exc).__name__}: {exc}"
            if not isinstance(exc, ConformanceError):
                detail += "\n" + traceback.format_exc(limit=2)
            self.report.results.append(Result(category, name, passed=False, detail=detail))
        else:
            self.report.results.append(Result(category, name, passed=True))

    # --- categories ----------------------------------------------------------------------------

    def index(self) -> None:
        idx = json.loads((self.vectors / "INDEX.json").read_text(encoding="utf-8"))
        for rel, digest in idx["files"].items():
            self.check("index", rel, partial(_digest_matches, self.vectors / rel, digest))

    def wire(self) -> None:
        for v in self.load("wire/header_valid.json"):
            self.check(
                "wire", v["description"], partial(_header_roundtrip, bytes.fromhex(v["hex"]))
            )
        for v in self.load("wire/latent_valid.json"):
            self.check("wire", v["name"], partial(_latent_roundtrip, v))

    def malformed(self) -> None:
        for v in self.load("malformed/header_invalid.json"):
            self.check(
                "malformed",
                v["name"],
                partial(_rejects, partial(Header.decode, bytes.fromhex(v["hex"]))),
            )
        for v in self.load("malformed/latent_invalid.json"):
            self.check(
                "malformed",
                v["name"],
                partial(_rejects, partial(_parse_latent, bytes.fromhex(v["hex"]))),
            )

    def crypto(self) -> None:
        for v in self.load("crypto/packet_valid.json"):
            self.check("crypto", v["name"], partial(_packet, v))

    def consent(self) -> None:
        for v in self.load("consent/capabilities.json"):
            (tlv,) = iter_tlvs(bytes.fromhex(v["tlv_hex"]))
            if tlv.code == SENDER_CAPABILITY_CODE:
                self.check("consent", v["name"], partial(SenderCapability.verify, tlv))
            else:
                nh = bytes.fromhex(v["noise_h"])
                self.check(
                    "consent", v["name"], partial(ReceiverCapability.verify, tlv, noise_h=nh)
                )

    def revocation(self) -> None:
        by = {v["name"]: v for v in self.load("consent/revocation.json")}
        (rev,) = iter_tlvs(bytes.fromhex(by["consent_withdrawn"]["tlv_hex"]))
        self.check("revocation", "consent_withdrawn", partial(_capability_scope_revocation, rev))
        att = by["deletion_attestation"]
        (a,) = iter_tlvs(bytes.fromhex(att["tlv_hex"]))
        (req,) = iter_tlvs(bytes.fromhex(att["request_tlv_hex"]))
        self.check(
            "revocation",
            "deletion_attestation",
            partial(DeletionAttestation.verify, a, request=req),
        )

    def identity(self) -> None:
        by = {v["name"]: v for v in self.load("identity/bindings.json")}
        p = by["identity_proof"]
        (pt,) = iter_tlvs(bytes.fromhex(p["tlv_hex"]))
        proof = partial(
            IdentityProof.verify,
            pt,
            pk_session=bytes.fromhex(p["pk_session"]),
            noise_h=bytes.fromhex(p["noise_h"]),
        )
        self.check("identity", "identity_proof", proof)
        b = by["session_binding"]
        (bt,) = iter_tlvs(bytes.fromhex(b["tlv_hex"]))
        self.check(
            "identity",
            "session_binding",
            partial(verify_session_binding, bt, noise_h=bytes.fromhex(b["noise_h"])),
        )

    def session(self) -> None:
        for v in self.load("session/descriptor.json"):
            self.check("session", "descriptor", partial(_descriptor, v))

    def replay(self) -> None:
        for v in self.load("replay/windows.json"):
            self.check("replay", v["name"], partial(_window, v))

    def privacy(self) -> None:
        for v in self.load("privacy/dp_accounting.json"):
            if "tlv_hex" in v:
                (t,) = iter_tlvs(bytes.fromhex(v["tlv_hex"]))
                self.check("privacy", v.get("name", "dp_params"), partial(DpParams.decode, t))

    def ontology(self) -> None:
        path = self.vectors / "ontology" / "esp-emo-v13-basic8-v1.registry.blake2b256"
        self.check(
            "ontology",
            "basic8_registry_digest",
            partial(_registry_digest, path.read_text().strip()),
        )

    def run_all(self) -> Report:
        for category in (
            self.index,
            self.wire,
            self.malformed,
            self.crypto,
            self.consent,
            self.revocation,
            self.identity,
            self.session,
            self.replay,
            self.privacy,
            self.ontology,
        ):
            category()
        return self.report


def _digest_matches(path: Path, digest: str) -> None:
    _require(
        hashlib.blake2b(path.read_bytes(), digest_size=32).hexdigest() == digest, "digest mismatch"
    )


def _header_roundtrip(raw: bytes) -> None:
    _require(Header.decode(raw).encode() == raw, "re-encoding differs")


def _parse_latent(raw: bytes) -> None:
    (tlv,) = iter_tlvs(raw)
    decode_typed_latent(tlv)


def _latent_roundtrip(v: dict[str, Any]) -> None:
    raw = bytes.fromhex(v["hex"])
    (tlv,) = iter_tlvs(raw)
    decode_typed_latent(tlv)
    again = encode_typed_latent(
        type_from_tlv_code(tlv.code), v["input_values"], LatentEncoding[v["encoding"]]
    )
    _require(again == raw, "re-encoding differs")


def _packet(v: dict[str, Any]) -> None:
    keys = DirectionKeys.from_split_key(bytes.fromhex(v["k_split"]))
    _require(keys.aead.hex() == v["k_aead"], "aead key derivation")
    _require(keys.nonce.hex() == v["k_nonce"], "nonce key derivation")
    signer = SigningKey.from_seed(bytes.fromhex(v["ed25519_seed"]))
    raw = bytes.fromhex(v["packet_hex"])
    opened = open_packet(raw, keys, expected_sender=signer.public_bytes, max_payload_len=1 << 20)
    _require(seal_packet(opened.header, opened.plaintext, keys, signer) == raw, "reseal differs")
    tampered = bytearray(raw)
    tampered[-70] ^= 1
    _rejects(
        partial(
            open_packet,
            bytes(tampered),
            keys,
            expected_sender=signer.public_bytes,
            max_payload_len=1 << 20,
        )
    )


def _capability_scope_revocation(tlv: Tlv) -> None:
    _require(RevocationIntent.verify(tlv).capability_scope, "expected capability scope")


def _descriptor(v: dict[str, Any]) -> None:
    d = SessionDescriptor.decode(bytes.fromhex(v["hex"]))
    _require(d.encode().hex() == v["hex"], "re-encoding differs")
    _require(d.digest().hex() == v["digest"], "digest differs")


def _window(v: dict[str, Any]) -> None:
    w = ReplayWindow(w_back=v["w_back"], w_fwd=v["w_fwd"])
    got = []
    for s in v["sequence"]:
        try:
            w.accept(s)
            got.append(1)
        except ReplayError:
            got.append(0)
    _require(got == v["accept"], f"accept pattern {got}")


def _registry_digest(expected: str) -> None:
    _require(basic8_registry().digest_hex() == expected, "registry digest differs")


def _rejects(fn: Callable[[], object]) -> None:
    try:
        fn()
    except Exception:
        return
    raise ConformanceError("malformed input was accepted")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="esp-conformance", description="ESP V13 conformance runner"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run the conformance suite")
    run.add_argument("--vectors", type=Path, default=DEFAULT_VECTORS)
    run.add_argument(
        "--peer", type=Path, help="external implementation for live interop (esp-rs contract)"
    )
    run.add_argument("--json", type=Path, help="write the report as JSON")
    args = parser.parse_args(argv)
    suite = Suite(args.vectors)
    report = suite.run_all()
    if args.peer is not None:
        from esp.conformance.interop import run_interop  # noqa: PLC0415 - optional part

        run_interop(suite, args.peer)
    for cat, counts in report.summary().items():
        mark = "PASS" if counts["failed"] == 0 else "FAIL"
        print(f"{mark:4}  {cat:11} {counts['passed']:3} passed  {counts['failed']:3} failed")
    for r in report.results:
        if not r.passed:
            print(f"  FAILED {r.category}/{r.name}: {r.detail}")
    if args.json:
        args.json.write_text(
            json.dumps(
                {
                    "passed": report.passed,
                    "summary": report.summary(),
                    "results": [r.__dict__ for r in report.results],
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
    print("RESULT:", "PASS" if report.passed else "FAIL")
    return 0 if report.passed else 1


if __name__ == "__main__":
    sys.exit(main())
