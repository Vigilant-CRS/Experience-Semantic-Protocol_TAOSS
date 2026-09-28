# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Version types."""

from __future__ import annotations

from typing import Annotated, Final

from pydantic import StringConstraints

SEMVER_PATTERN: Final = (
    r"^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)"
    r"(?:-[0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*)?(?:\+[0-9A-Za-z\-]+(?:\.[0-9A-Za-z\-]+)*)?$"
)

#: Semantic version string (semver.org 2.0.0).
SemVer = Annotated[str, StringConstraints(pattern=SEMVER_PATTERN)]

#: Logical schema version "MAJOR.MINOR".
SchemaVersion = Annotated[str, StringConstraints(pattern=r"^(0|[1-9]\d*)\.(0|[1-9]\d*)$")]

#: Current logical schema version of ESP data-model objects.
CURRENT_SCHEMA_VERSION: Final = "1.0"
