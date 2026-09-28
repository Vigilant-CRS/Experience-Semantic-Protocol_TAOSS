# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-075 / GAP-024: PQ declaration, hybrid outer channel, no false claims."""

import re
from pathlib import Path

import pytest

from esp.codec.errors import WireError
from esp.session.descriptor import PqMode, SessionDescriptor
from esp.session.pq import (
    CLASSICAL_CLAIM,
    HYBRID_GROUP,
    OuterChannel,
    OuterChannelReport,
    PqPolicyError,
    PqSupport,
    QuicOuterChannel,
    assess,
    probe,
    require_outer_hybrid,
)

pytestmark = pytest.mark.security
ROOT = Path(__file__).resolve().parents[3]


@pytest.mark.parametrize("mode", [PqMode.HYBRID_OUTER, PqMode.HYBRID_NOISE])
def test_descriptor_refuses_non_classical_modes_on_the_wire(mode: PqMode) -> None:
    raw = bytearray(SessionDescriptor().encode())
    assert raw[4] == PqMode.CLASSICAL_ONLY  # version, profile, sf_level, nonce_mode, pq_mode
    raw[4] = mode
    with pytest.raises(WireError, match="CLASSICAL_ONLY"):
        SessionDescriptor.decode(bytes(raw))
    raw[4] = 3  # unassigned
    with pytest.raises(WireError):
        SessionDescriptor.decode(bytes(raw))


def test_probe_reports_what_the_libraries_really_offer() -> None:
    from aioquic.tls import Group  # noqa: PLC0415

    s = probe()
    assert s.quic_hybrid_group == (HYBRID_GROUP in Group.__members__)
    assert isinstance(s.mlkem768_primitive, bool)
    assert s.openssl


def test_default_statement_is_classical() -> None:
    a = assess(SessionDescriptor())
    assert a.descriptor_mode is PqMode.CLASSICAL_ONLY
    assert not a.outer_hybrid_verified
    assert a.statement == CLASSICAL_CLAIM
    assert "no post-quantum" in a.statement


@pytest.mark.parametrize("group", [None, "x25519", "secp256r1", "X25519Kyber768Draft00"])
def test_hybrid_is_never_claimed_without_verified_negotiation(group: str | None) -> None:
    report = OuterChannelReport("TLS1.3", requested_hybrid=True, negotiated_group=group)
    assert not assess(SessionDescriptor(), report).outer_hybrid_verified
    with pytest.raises(PqPolicyError):
        require_outer_hybrid(report)


def test_verified_hybrid_keeps_inner_session_classical() -> None:
    report = OuterChannelReport("TLS1.3", requested_hybrid=True, negotiated_group=HYBRID_GROUP)
    require_outer_hybrid(report)
    a = assess(SessionDescriptor(), report)
    assert a.outer_hybrid_verified
    assert a.descriptor_mode is PqMode.CLASSICAL_ONLY
    assert "remains classical-only" in a.statement


def test_quic_outer_channel_never_guesses() -> None:
    ch = QuicOuterChannel()
    assert isinstance(ch, OuterChannel)
    assert ch.negotiated_group() is None
    assert not assess(SessionDescriptor(), ch.report()).outer_hybrid_verified
    no = PqSupport(
        mlkem768_primitive=True, quic_hybrid_group=False, tls_group_introspection=False, openssl="x"
    )
    with pytest.raises(PqPolicyError, match="refusing"):
        QuicOuterChannel(request_hybrid=True, support=no)
    yes = PqSupport(
        mlkem768_primitive=True, quic_hybrid_group=True, tls_group_introspection=False, openssl="x"
    )
    # Even if a future aioquic offered the group, an unverifiable negotiation is not a claim.
    with pytest.raises(PqPolicyError, match="unknown"):
        require_outer_hybrid(QuicOuterChannel(request_hybrid=True, support=yes).report())


# --- claim lint: no quantum-resistance claim anywhere while CLASSICAL_ONLY ------------------------

CLAIM = re.compile(
    r"post[\s\-]?quantum|quantum[\s\-](?:safe|resistant|secure|proof)|pq[\s\-](?:safe|secure)",
    re.IGNORECASE,
)
NEGATION = re.compile(
    r"\b(?:no|not|never|without|kein|keine|nie|must\s*not|mustnot)\b", re.IGNORECASE
)
DECLARATION_AFTER = re.compile(
    r"^[\s\-„“\"']*(?:deklaration|declaration|questions|migration)", re.IGNORECASE
)


def claim_violations(text: str) -> list[str]:
    """Matches not negated shortly before, and not a declaration/migration heading."""
    out = []
    for m in CLAIM.finditer(text):
        before = text[max(0, m.start() - 80) : m.start()]
        after = text[m.end() : m.end() + 40]
        if NEGATION.search(before) or DECLARATION_AFTER.search(after):
            continue
        line = text.count("\n", 0, m.start()) + 1
        out.append(f"line {line}: …{text[max(0, m.start() - 40) : m.end() + 20]!r}")
    return out


def scanned_files() -> list[Path]:
    files = [ROOT / "README.md", *(ROOT / "docs").rglob("*.md"), *(ROOT / "docs").rglob("*.svg")]
    files += [*(ROOT / "src").rglob("*.py"), *(ROOT / "examples").rglob("*")]
    files += [p for p in (ROOT / "rust").rglob("*.rs") if "target" not in p.parts]
    files += [p for p in (ROOT / "rust").rglob("*.md") if "target" not in p.parts]
    return [p for p in files if p.is_file()]


def test_no_post_quantum_claim_in_docs_ui_or_code() -> None:
    found = {}
    for p in scanned_files():
        v = claim_violations(p.read_text("utf-8", errors="replace"))
        if v:
            found[str(p.relative_to(ROOT))] = v
    assert not found, found


@pytest.mark.parametrize(
    "text",
    [
        "ESP is post-quantum secure.",
        "Sessions are quantum-safe by default.",
        "A PQ-secure transport for experiences",
        "Now with Post Quantum encryption!",
    ],
)
def test_claim_lint_catches_claims(text: str) -> None:
    assert claim_violations(text)


@pytest.mark.parametrize(
    "text",
    [
        "`pq_mode` is `CLASSICAL_ONLY` in v1: no post-quantum claim.",
        "v1 never claims\n  post-quantum protection.",
        "## WP-075 — Post-Quantum-Deklaration und Hybrid-Pfad",
        "kein „post-quantum“ in Doku/UI",
    ],
)
def test_claim_lint_allows_negations_and_declarations(text: str) -> None:
    assert not claim_violations(text)
