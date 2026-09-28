# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Error hierarchy and stable error-code register (plan GAP-014, ADR-0020).

Codes are stable once released: a code is never reused for a different
meaning. Ranges:

- ``0x01xx`` logical model validation
- ``0x02xx`` wire codec
- ``0x03xx`` cryptography
- ``0x04xx`` consent / capability / policy
- ``0x05xx`` session
- ``0x06xx`` decoder
- ``0x07xx`` registry / ontology
- ``0x08xx`` regulatory guard (WP-078)
"""

from __future__ import annotations

from enum import IntEnum, unique


@unique
class ErrorCode(IntEnum):
    """Stable numeric error codes."""

    VALIDATION = 0x0100
    RANGE = 0x0101
    PROVENANCE_REQUIRED = 0x0102
    AFFECT_SCOPE_VIOLATION = 0x0103
    CLOCK = 0x0104

    WIRE_MALFORMED = 0x0200

    CRYPTO_AUTH_FAILED = 0x0300

    CONSENT_DENIED = 0x0400

    SESSION_STATE = 0x0500

    DECODER_POLICY_FAILED = 0x0601  # V13 section 7.2: ESP_DECODER_POLICY_FAILED

    REGISTRY_CONFLICT = 0x0700
    REGISTRY_UNKNOWN_ID = 0x0701

    REGULATORY_DECLARATION_MISSING = 0x0800
    REGULATORY_PROHIBITED_PRACTICE = 0x0801
    REGULATORY_MISDECLARED = 0x0802


class EspError(Exception):
    """Base class for all ESP errors. Carries a stable :class:`ErrorCode`."""

    code: ErrorCode = ErrorCode.VALIDATION

    def __init__(self, message: str, *, code: ErrorCode | None = None) -> None:
        super().__init__(message)
        if code is not None:
            self.code = code

    def __str__(self) -> str:
        return f"[{self.code.name} 0x{self.code.value:04x}] {super().__str__()}"


class EspValidationError(EspError):
    """A logical object violates the ESP data model."""

    code = ErrorCode.VALIDATION


class RegistryError(EspError):
    """Registry / ontology rule violation (duplicate IDs, silent mutation, ...)."""

    code = ErrorCode.REGISTRY_CONFLICT
