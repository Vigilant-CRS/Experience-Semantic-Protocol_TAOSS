# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Identifier types.

UUIDs are immutable by construction. ESP identifiers that V13 specifies as
UUIDv4 (for example ``timeline_id``) are validated as version 4, RFC 4122
variant. Anchor IDs follow ``esp:<type>:<label>:v<major>`` (plan section 23).
"""

from __future__ import annotations

import re
import uuid
from typing import Annotated, Final

from pydantic import AfterValidator, StringConstraints


def _require_uuid4(value: uuid.UUID) -> uuid.UUID:
    if value.version != 4 or value.variant != uuid.RFC_4122:
        msg = "identifier must be an RFC 4122 UUID version 4"
        raise ValueError(msg)
    return value


#: RFC 4122 UUID version 4.
UUID4 = Annotated[uuid.UUID, AfterValidator(_require_uuid4)]


def new_uuid4() -> uuid.UUID:
    """Return a fresh random UUIDv4 (CSPRNG-backed via :func:`os.urandom`)."""
    return uuid.uuid4()


ANCHOR_ID_PATTERN: Final = r"^esp:(kno|int|emo|ctx|sen|tem):[a-z0-9][a-z0-9_\-]*:v[1-9][0-9]*$"

#: Registry anchor identifier, e.g. ``esp:emo:fear:v1``.
AnchorId = Annotated[str, StringConstraints(pattern=ANCHOR_ID_PATTERN)]

#: Registry / vocabulary / profile identifier, e.g. ``esp-emo-v13-basic8-v1``.
RegistryName = Annotated[
    str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9.\-]*[a-z0-9]$", max_length=128)
]

#: Free-form local reference to another object (``obs_voice_193``).
LocalRef = Annotated[
    str, StringConstraints(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:\-]*$", max_length=256)
]

#: Lower-case hex digest (e.g. BLAKE2b-256 = 64 hex chars).
HexDigest = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{16,128}$")]

_ANCHOR_RE: Final = re.compile(ANCHOR_ID_PATTERN)


def anchor_major_version(anchor_id: str) -> int:
    """Return the major version encoded in an anchor ID."""
    if _ANCHOR_RE.fullmatch(anchor_id) is None:
        msg = f"not an anchor id: {anchor_id!r}"
        raise ValueError(msg)
    return int(anchor_id.rsplit(":v", 1)[1])
