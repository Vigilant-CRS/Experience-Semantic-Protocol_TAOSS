# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Conformance runner (WP-039): ``esp-conformance run``.

Checks this implementation against the shared vector suite (``vectors/``,
CC BY 4.0) by category — wire, crypto, consent, revocation, identity,
session, replay, privacy, ontology, malformed inputs, neural adapter
contract (WP-090) — and, with
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
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Any

from esp.codec.header import Header
from esp.codec.tlv import (
    ADDENDUM_V1_CODES,
    LatentEncoding,
    Tlv,
    decode_typed_latent,
    encode_typed_latent,
    iter_tlvs,
    parse_payload,
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
from esp.xcf.watermark import (
    ReplaySchedule,
    ReplayVerifier,
    ReplayWatermarkError,
    ReplayWatermarkPolicy,
)

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
    def __init__(
        self,
        vectors: Path,
        *,
        neural_adapter: str | None = None,
        neural_rust: Path | None = None,
    ) -> None:
        self.vectors = vectors
        self.report = Report()
        self.neural_adapter = neural_adapter
        self.neural_rust = neural_rust

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
        marks = self.load("replay/watermark.json")
        self.check("replay", "watermark_stream", partial(_watermark_stream, marks))
        for v in (m for m in marks if not m["valid"]):
            self.check("replay", f"watermark_{v['name']}", partial(_watermark_reject, marks, v))

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

    def xcf(self) -> None:
        path = self.vectors / "xcf" / "capsules.json"
        if path.exists():
            for v in self.load("xcf/capsules.json"):
                self.check("xcf", v["name"], partial(_capsule, v))

    def hive(self) -> None:
        path = self.vectors / "hive" / "tlvs.json"
        if path.exists():
            for v in self.load("hive/tlvs.json"):
                self.check("hive", v["name"], partial(_hive, v))

    def neural(self) -> None:
        """WP-090: neural adapter/decoder contract, broken sources, optional external and Rust."""
        from esp.conformance.neural import neural_checks  # noqa: PLC0415 - heavier imports

        for name, fn in neural_checks(self.neural_adapter, self.neural_rust):
            self.check("neural", name, fn)

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
            self.xcf,
            self.hive,
            self.neural,
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


def _watermark_verifier(v: dict[str, Any]) -> ReplayVerifier:
    schedule = ReplaySchedule(
        period_ns=v["period_ns"],
        jitter_ns=v["jitter_ns"],
        tolerance_ns=v["tolerance_ns"],
        start_grid_ns=v["start_grid_ns"],
    )
    vendors = {bytes.fromhex(v["vendor_id"]): bytes.fromhex(v["vendor_key"])}
    return ReplayVerifier(ReplayWatermarkPolicy(vendors, schedule))


def _watermark_segment(verifier: ReplayVerifier, v: dict[str, Any]) -> None:
    payload = bytes.fromhex(v["prefix_hex"]) + bytes.fromhex(v["tlv_hex"])
    header = Header(
        profile=1,
        sf_level=0,
        types_bitmap=0x0001,
        consent_flags=0,
        privacy_flags=0,
        capabilities=0,
        timestamp_ns=v["header_timestamp_ns"],
        timeline_id=uuid.UUID(v["timeline_id"]),
        segment_seq=v["index"],
        dt_ms=0,
        phase=0.0,
        sender_id=bytes(32),
        payload_len=0,
        nonce=bytes(12),
    )
    parsed = parse_payload(payload, extra_codes=ADDENDUM_V1_CODES)
    advance = verifier.check(header, payload, parsed, now_ns=v["header_timestamp_ns"])
    _require(advance is not None, "replay segment not recognized")
    if advance is not None:
        verifier.commit(advance)


def _watermark_stream(marks: list[dict[str, Any]]) -> None:
    valid = [m for m in marks if m["valid"]]
    verifier = _watermark_verifier(valid[0])
    for v in valid:
        _watermark_segment(verifier, v)


def _watermark_reject(marks: list[dict[str, Any]], v: dict[str, Any]) -> None:
    valid = [m for m in marks if m["valid"]]
    verifier = _watermark_verifier(valid[0])
    _watermark_segment(verifier, valid[0])
    try:
        _watermark_segment(verifier, v)
    except ReplayWatermarkError as exc:
        _require(v["expect_error"] in str(exc), f"wrong refusal: {exc}")
        return
    msg = f"{v['name']} was accepted"
    raise ConformanceError(msg)


def _registry_digest(expected: str) -> None:
    _require(basic8_registry().digest_hex() == expected, "registry digest differs")


def _capsule(v: dict[str, Any]) -> None:
    import uuid  # noqa: PLC0415

    from esp.xcf.capsule import Capsule, Header, PrivateBody  # noqa: PLC0415

    raw = bytes.fromhex(v["capsule_hex"])
    c = Capsule(raw)
    _require(len(bytes.fromhex(v["header_hex"])) == 148, "header is not 148 bytes")
    _require(Header.decode(raw[:148]).encode() == raw[:148], "header re-encoding differs")
    _require(c.header.parent_cid.hex() == v["parent_cid"], "parent_cid")
    c.verify_signature()
    _require(c.cid.hex() == v["cid"], "CID differs")
    body = c.open_with_cek(bytes.fromhex(v["cek"]))
    _require(
        body
        == PrivateBody(
            uuid.UUID(v["policy_id"]), uuid.UUID(v["timeline_id"]), bytes.fromhex(v["payload_hex"])
        ),
        "private body",
    )
    tampered = bytearray(raw)
    tampered[200] ^= 1
    _rejects(Capsule(bytes(tampered)).verify_signature)


def _hive(v: dict[str, Any]) -> None:
    """Typed-Hive TLVs (ADR-0021): valid objects verify; invalid ones are refused."""
    from esp.hive.tlv import (  # noqa: PLC0415
        CollectiveIntent,
        HiveContribution,
        HiveExit,
        HiveGrant,
        verify_collective_intent,
        verify_grant,
    )

    (tlv,) = iter_tlvs(bytes.fromhex(v["tlv_hex"]))
    if "expect_error" in v:
        base = v.get("base_capability_tlv_hex")

        def attempt() -> None:
            if tlv.code == 0x70 and base is not None:
                (b,) = iter_tlvs(bytes.fromhex(base))
                verify_grant(tlv, SenderCapability.verify(b), now_ns=0)
            elif tlv.code == 0x70:
                HiveGrant.parse(tlv)
            elif tlv.code == 0x71:
                HiveContribution.decode(tlv)
            else:
                CollectiveIntent.decode(tlv)

        try:
            attempt()
        except Exception as exc:  # any rejection counts; the reason is checked below
            _require(v["expect_error"] in str(exc), f"rejected for another reason: {exc}")
            return
        raise ConformanceError("accepted an invalid hive object")
    if tlv.code == 0x70:
        (b,) = iter_tlvs(bytes.fromhex(v["base_capability_tlv_hex"]))
        g = verify_grant(tlv, SenderCapability.verify(b), now_ns=0)
        _require(
            g.sign(SigningKey.from_seed(bytes.fromhex(v["master_seed"]))) == tlv, "re-sign differs"
        )
    elif tlv.code == 0x71:
        from esp.hive.membership import verify_identified  # noqa: PLC0415

        c = HiveContribution.decode(tlv)
        _require(c.encode() == tlv, "re-encoding differs")
        verify_identified(c, SigningKey.from_seed(bytes.fromhex(v["member_seed"])).public_bytes)
    elif tlv.code == 0x72:
        from esp.hive.membership import verify_identified  # noqa: PLC0415

        x = HiveExit.decode(tlv)
        _require(x.encode() == tlv, "re-encoding differs")
        verify_identified(x, SigningKey.from_seed(bytes.fromhex(v["member_seed"])).public_bytes)
    else:
        cic = verify_collective_intent(tlv, bytes.fromhex(v["group_public_key"]))
        _require(cic.signing_message().hex() == v["signing_message"], "signing message differs")


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
    run.add_argument(
        "--neural-adapter",
        metavar="MODULE:FACTORY",
        help="check an external neural adapter against the vendor contract (WP-090)",
    )
    run.add_argument(
        "--neural-rust",
        type=Path,
        metavar="ESP_RS",
        help="cross-check the Rust neural contract via `esp-rs neural-sim`",
    )
    args = parser.parse_args(argv)
    suite = Suite(args.vectors, neural_adapter=args.neural_adapter, neural_rust=args.neural_rust)
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
