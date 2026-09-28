# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""PQ declaration and the optional hybrid outer channel (WP-075, GAP-024).

V13 (Cryptographic Primitives) requires deployments to **declare** whether
session establishment is classical-only or hybrid PQ/T. They MUST NOT describe
X25519-only Noise IK as resistant to quantum attackers. In v1:

- the session descriptor carries ``pq_mode``, and the only admissible value is
  ``CLASSICAL_ONLY`` (:mod:`esp.session.descriptor` refuses anything else,
  both when constructing and when decoding);
- an **outer** standards-track hybrid channel (TLS 1.3 with
  ``X25519MLKEM768``, RFC 10024) may wrap the transport. That property belongs
  to the outer channel, not to ESP. It is reported only when the channel
  *verifiably negotiated* the hybrid group. A request alone is never enough.

This module declares, probes and assesses. It does not implement a KEM
combiner (V13: "this document does not invent a bespoke KEM combiner").
"""

from __future__ import annotations

import ssl
from dataclasses import dataclass
from typing import Final, Protocol, runtime_checkable

from esp.core.errors import ErrorCode, EspError
from esp.session.descriptor import PqMode, SessionDescriptor

HYBRID_GROUP: Final = "X25519MLKEM768"
HYBRID_GROUP_CODEPOINT: Final = 0x11EC
"""TLS NamedGroup codepoint for X25519MLKEM768 (RFC 10024)."""

CLASSICAL_CLAIM: Final = (
    "classical-only session establishment (X25519 Noise IK); no post-quantum confidentiality claim"
)


class PqPolicyError(EspError):
    code = ErrorCode.SESSION_STATE


@dataclass(frozen=True, slots=True)
class PqSupport:
    """What this installation can actually do. Every flag is probed, not assumed."""

    mlkem768_primitive: bool
    """``cryptography`` exposes ML-KEM-768 (FIPS 203) key encapsulation."""
    quic_hybrid_group: bool
    """aioquic offers the X25519MLKEM768 TLS group for QUIC."""
    tls_group_introspection: bool
    """The stdlib ``ssl`` module can report the negotiated key-exchange group."""
    openssl: str


def probe() -> PqSupport:
    try:
        from cryptography.hazmat.primitives.asymmetric import mlkem  # noqa: PLC0415

        key = mlkem.MLKEM768PrivateKey.generate()
        secret, ct = key.public_key().encapsulate()
        mlkem_ok = key.decapsulate(ct) == secret
    except Exception:  # absence of the primitive in any form
        mlkem_ok = False
    try:
        from aioquic.tls import Group  # noqa: PLC0415

        quic_ok = HYBRID_GROUP in Group.__members__
    except ImportError:  # pragma: no cover - aioquic is a core dependency
        quic_ok = False
    introspect = hasattr(ssl.SSLSocket, "group") or hasattr(ssl.SSLObject, "group")
    return PqSupport(mlkem_ok, quic_ok, introspect, ssl.OPENSSL_VERSION)


@runtime_checkable
class OuterChannel(Protocol):
    """An outer secure channel under ESP (e.g. TLS 1.3 around TCP, or QUIC)."""

    @property
    def protocol(self) -> str: ...

    def negotiated_group(self) -> str | None:
        """The key-exchange group the handshake actually used, or ``None`` if unknown."""
        ...


@dataclass(frozen=True, slots=True)
class OuterChannelReport:
    protocol: str
    requested_hybrid: bool
    negotiated_group: str | None


@dataclass(frozen=True, slots=True)
class PqAssessment:
    descriptor_mode: PqMode
    outer_hybrid_verified: bool
    statement: str


def assess(descriptor: SessionDescriptor, outer: OuterChannelReport | None = None) -> PqAssessment:
    """The only statement a UI or report may make about quantum resistance.

    The ESP session itself is always classical in v1. A hybrid outer channel is
    mentioned only when it is verified, and even then the statement keeps the
    inner session classical.
    """
    if descriptor.pq_mode is not PqMode.CLASSICAL_ONLY:  # pragma: no cover - descriptor refuses
        msg = "v1 descriptors are CLASSICAL_ONLY"
        raise PqPolicyError(msg)
    if outer is None or outer.negotiated_group != HYBRID_GROUP:
        return PqAssessment(PqMode.CLASSICAL_ONLY, False, CLASSICAL_CLAIM)
    return PqAssessment(
        PqMode.CLASSICAL_ONLY,
        True,
        f"outer channel {outer.protocol} negotiated hybrid {HYBRID_GROUP} (PQ/T, RFC 10024); "
        "the ESP session inside it remains classical-only",
    )


def require_outer_hybrid(outer: OuterChannelReport) -> None:
    """For deployments that MUST have hybrid confidentiality (XCF, L3+, high-assurance I2I).

    Refuses unless the outer channel verifiably negotiated the hybrid group.
    """
    if outer.negotiated_group is None:
        msg = f"{outer.protocol}: negotiated group unknown; hybrid cannot be verified"
        raise PqPolicyError(msg)
    if outer.negotiated_group != HYBRID_GROUP:
        msg = f"{outer.protocol}: negotiated {outer.negotiated_group}, not {HYBRID_GROUP}"
        raise PqPolicyError(msg)


class QuicOuterChannel:
    """The reference QUIC transport as an outer channel.

    aioquic selects the TLS group itself. Unless its group enumeration contains
    ``X25519MLKEM768``, a hybrid request is refused outright instead of being
    silently downgraded.
    """

    protocol = "QUIC/TLS1.3 (aioquic)"

    def __init__(self, *, request_hybrid: bool = False, support: PqSupport | None = None) -> None:
        support = support or probe()
        if request_hybrid and not support.quic_hybrid_group:
            msg = f"aioquic offers no {HYBRID_GROUP} group; refusing a hybrid request"
            raise PqPolicyError(msg)
        self.requested_hybrid = request_hybrid

    def negotiated_group(self) -> str | None:
        return None  # aioquic exposes no negotiated-group API; never guess

    def report(self) -> OuterChannelReport:
        return OuterChannelReport(self.protocol, self.requested_hybrid, self.negotiated_group())
