# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Wire codec errors. Parsers raise only :class:`WireError` on malformed input."""

from __future__ import annotations

from esp.core.errors import ErrorCode, EspError


class WireError(EspError):
    """Malformed or non-canonical wire data."""

    code = ErrorCode.WIRE_MALFORMED
