# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Base class for logical ESP objects and their canonical JSON form.

Logical objects (plan section 25) are serialized as *ESP canonical JSON v1*:
UTF-8, object keys sorted, no insignificant whitespace, no NaN/Infinity,
floats in Python's shortest round-trip representation, negative zero
normalized by the scalar validators. This is the canonical form for logical
objects and registry digests. It is **not** the V13 signed-object encoding,
which is binary (V13 section 9.2) and lives in the codec package.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Self

from pydantic import BaseModel, ConfigDict


def canonical_json_bytes(data: Any) -> bytes:  # noqa: ANN401 - accepts any JSON value
    """Serialize a JSON-compatible value in ESP canonical JSON v1."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def blake2b_256(data: bytes) -> bytes:
    """BLAKE2b with a 32-byte digest (RFC 7693)."""
    return hashlib.blake2b(data, digest_size=32).digest()


class EspModel(BaseModel):
    """Immutable, strictly validated logical object.

    - ``frozen``: attribute assignment is rejected; collections are tuples.
    - ``extra="forbid"``: unknown fields are errors, never silently dropped.
    - ``strict``: no lossy coercion (``"0.5"`` is not a float).
    """

    model_config = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        allow_inf_nan=False,
        validate_default=True,
        revalidate_instances="always",
        use_enum_values=False,
    )

    def canonical_json(self) -> bytes:
        """ESP canonical JSON v1 bytes of this object."""
        return canonical_json_bytes(self.model_dump(mode="json"))

    def canonical_digest(self) -> bytes:
        """BLAKE2b-256 over the canonical JSON."""
        return blake2b_256(self.canonical_json())

    @classmethod
    def from_json(cls, data: str | bytes) -> Self:
        """Strictly parse an object from JSON."""
        return cls.model_validate_json(data)

    @classmethod
    def from_data(cls, data: Any) -> Self:  # noqa: ANN401 - any JSON-compatible value
        """Strictly parse external, JSON-compatible data (e.g. loaded YAML).

        Goes through JSON so that external data gets JSON strictness:
        enum values as strings and lists for tuples are accepted, but no
        lossy coercion (``"0.5"`` is still not a float). Python callers
        constructing objects directly should pass typed values instead.
        """
        return cls.model_validate_json(canonical_json_bytes(data))
