# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Semantic fidelity levels and type-set profiles (V13 section 8.6; WP-063; ADR-0025).

Strict interpretation: a data packet at SF level ``s`` carries every required
type of ``s`` (unless intentionally masked where the level allows it) and no
type outside ``required | optional``.

=====  =====================================  ===========================
SF     required                               optional
=====  =====================================  ===========================
SF0    KNO                                    -
SF1    KNO, CTX                               -
SF2    KNO, CTX, INT                          -
SF3    KNO, CTX, INT, TEM                     -
SF4    KNO, CTX, INT, TEM                     SEN
SF5    KNO, CTX, INT, TEM, SEN                -
SF6    KNO, CTX, INT, TEM, SEN                EMO (explicit opt-in)
SF7    all six                                -
=====  =====================================  ===========================

Custom type-set profiles (e.g. ``MEB-HANDOVER`` = INT, CTX, TEM, SEN) are
registry entries pinned in the session descriptor; their packets carry
``sf_level = 0`` and are validated against the custom set (GAP-027).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from esp.codec.errors import WireError
from esp.core.taoss_types import TaossType

K, I, E, C, S, T = (  # noqa: E741 - TAOSS abbreviations
    TaossType.KNO,
    TaossType.INT,
    TaossType.EMO,
    TaossType.CTX,
    TaossType.SEN,
    TaossType.TEM,
)


@dataclass(frozen=True, slots=True)
class TypeSetProfile:
    name: str
    required: frozenset[TaossType]
    optional: frozenset[TaossType] = frozenset()
    #: Types whose absence must be an explicit mask (e.g. EMO in SF6).
    maskable: frozenset[TaossType] = frozenset()

    def check(self, present: frozenset[TaossType], masked: frozenset[TaossType]) -> None:
        missing = self.required - present
        if missing:
            msg = f"{self.name}: required types missing: {sorted(t.name for t in missing)}"
            raise WireError(msg)
        extra = present - self.required - self.optional
        if extra:
            msg = f"{self.name}: types not allowed: {sorted(t.name for t in extra)}"
            raise WireError(msg)
        bad_mask = masked - self.maskable - self.optional
        if bad_mask & present:  # pragma: no cover - frame invariant forbids present+masked
            msg = "type both present and masked"
            raise WireError(msg)

    @property
    def allowed(self) -> frozenset[TaossType]:
        return self.required | self.optional


SF_LEVELS: Final = MappingProxyType(
    {
        0: TypeSetProfile("SF0", frozenset({K})),
        1: TypeSetProfile("SF1", frozenset({K, C})),
        2: TypeSetProfile("SF2", frozenset({K, C, I})),
        3: TypeSetProfile("SF3", frozenset({K, C, I, T})),
        4: TypeSetProfile("SF4", frozenset({K, C, I, T}), frozenset({S})),
        5: TypeSetProfile("SF5", frozenset({K, C, I, T, S})),
        6: TypeSetProfile("SF6", frozenset({K, C, I, T, S}), frozenset({E}), frozenset({E})),
        7: TypeSetProfile("SF7", frozenset({K, C, I, E, T, S})),
    }
)

#: Registered custom type-set profiles (V13 section 17 domain profiles).
CUSTOM_PROFILES: Final = MappingProxyType(
    {
        "esp-typeset-meb-handover-v1": TypeSetProfile(
            "MEB-HANDOVER", frozenset({I, C, T, S}), maskable=frozenset({E})
        ),
        #: BCI-free demo (WP-025): KNO+INT+CTX, EMO only under explicit consent.
        "esp-typeset-demo-v1": TypeSetProfile(
            "DEMO", frozenset({K, I, C}), frozenset({E}), frozenset({E})
        ),
    }
)


def custom_profile_digest(name: str) -> bytes:
    """Registry digest pinning a custom type-set profile's definition."""
    p = CUSTOM_PROFILES[name]
    definition = "|".join(
        [name, *(",".join(sorted(t.name for t in s)) for s in (p.required, p.optional, p.maskable))]
    )
    return hashlib.blake2b(definition.encode(), digest_size=32).digest()


def profile_for(sf_level: int, registries: frozenset[str] = frozenset()) -> TypeSetProfile:
    """The type-set profile governing a session (custom profile wins when pinned)."""
    custom = [CUSTOM_PROFILES[n] for n in sorted(registries) if n in CUSTOM_PROFILES]
    if len(custom) > 1:
        msg = "at most one custom type-set profile per session"
        raise WireError(msg)
    if custom:
        if sf_level != 0:
            msg = "custom type-set profiles use sf_level 0 (ADR-0025)"
            raise WireError(msg)
        return custom[0]
    try:
        return SF_LEVELS[sf_level]
    except KeyError:
        msg = f"unknown SF level {sf_level}"
        raise WireError(msg) from None


# --- I2I privacy envelopes (V13 section 16) -------------------------------------------


@dataclass(frozen=True, slots=True)
class I2IEnvelope:
    name: str
    dp_mandatory: bool
    #: Header flags that must be set (EMO_MASKED initially, NO_STORE, NO_REPLAY, TIMING_OBF).
    required_consent_flags: int
    required_privacy_flags: int
    aggregation_n: int = 1


I2I_TRUSTED: Final = I2IEnvelope(
    "I2I-TRUSTED", dp_mandatory=False, required_consent_flags=0b111, required_privacy_flags=0x20
)
I2I_PRIVATE: Final = I2IEnvelope(
    "I2I-PRIVATE",
    dp_mandatory=True,
    required_consent_flags=0b110,
    required_privacy_flags=0x20,
    aggregation_n=10,
)


def check_i2i_packet(
    envelope: I2IEnvelope, *, consent_flags: int, privacy_flags: int, initial: bool
) -> None:
    """Validate one packet's header flags against an I2I envelope."""
    need_consent = envelope.required_consent_flags
    if not initial:
        need_consent &= ~0b001  # EMO_MASKED is only mandatory initially (explicit opt-in later)
    if consent_flags & need_consent != need_consent:
        msg = f"{envelope.name}: required consent flags missing"
        raise WireError(msg)
    if privacy_flags & envelope.required_privacy_flags != envelope.required_privacy_flags:
        msg = f"{envelope.name}: TIMING_OBF required"
        raise WireError(msg)
    if envelope.dp_mandatory and privacy_flags & 0x0F == 0:
        msg = f"{envelope.name}: runtime DP is mandatory"
        raise WireError(msg)


# --- wire-rate arithmetic (V13 section 16) ------------------------------------------------

PACKET_OVERHEAD_BYTES: Final = 180
LATENT_TLV_OVERHEAD_BYTES: Final = 13  # 5-byte TLV header + 8-byte typed-latent sub-header


def release_bytes(
    types: frozenset[TaossType], *, bytes_per_coordinate: int, dp_params_bytes: int = 0
) -> int:
    """Bytes of one packet carrying ``types`` (latents only)."""
    from esp.core.taoss_types import L1_DIMS  # noqa: PLC0415 - avoid widening module imports

    coords = sum(L1_DIMS[t] for t in types)
    return (
        coords * bytes_per_coordinate
        + len(types) * LATENT_TLV_OVERHEAD_BYTES
        + PACKET_OVERHEAD_BYTES
        + dp_params_bytes
    )


def bitrate_kbit_s(bytes_per_release: int, releases_per_s: float) -> float:
    return bytes_per_release * 8 * releases_per_s / 1000.0
