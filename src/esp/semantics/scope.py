# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Affect-scope rules (plan section 4.5, ADR-0008, V13 sections 6.4, 17, 23)."""

from __future__ import annotations

from esp.core.errors import ErrorCode
from esp.core.provenance import (
    INFERENTIAL_SOURCES,
    MIN_PROFILE_FOR_SCOPE,
    AffectScope,
    Provenance,
    SourceKind,
)


class AffectScopeError(ValueError):
    """An affect statement violates the content/subject boundary."""

    code = ErrorCode.AFFECT_SCOPE_VIOLATION


def check_scope_source(scope: AffectScope, provenance: Provenance) -> None:
    """Validate that ``scope`` is consistent with where the statement came from.

    - ``SELF_DECLARED`` must come from the person's own self report and nothing else.
    - ``INFERRED_SUBJECT`` must be an inference (model or derived) with provenance.
    - ``MACHINE_RELAY`` must reference the relayed human-origin statement(s).
    - A self report can never be labelled as content-side or inferred affect.
    """
    kind = provenance.source_kind
    if scope is AffectScope.SELF_DECLARED and kind is not SourceKind.SELF_REPORT:
        msg = f"self_declared affect requires source_kind=self_report, got {kind.value}"
        raise AffectScopeError(msg)
    if kind is SourceKind.SELF_REPORT and scope is not AffectScope.SELF_DECLARED:
        msg = f"a self report is self_declared affect, not {scope.value}"
        raise AffectScopeError(msg)
    if scope is AffectScope.INFERRED_SUBJECT and kind not in INFERENTIAL_SOURCES:
        msg = f"inferred_subject affect requires an inferential source, got {kind.value}"
        raise AffectScopeError(msg)
    if scope is AffectScope.MACHINE_RELAY and not provenance.source_refs:
        msg = "machine_relay affect must reference the relayed human-origin statement"
        raise AffectScopeError(msg)


def check_scope_profile(scope: AffectScope, profile: int) -> None:
    """Reject subject-side affect on an L1 channel (V13 section 6.4)."""
    minimum = MIN_PROFILE_FOR_SCOPE[scope]
    if profile < minimum:
        msg = f"{scope.value} affect requires profile >= 0x{minimum:02x}, got 0x{profile:02x}"
        raise AffectScopeError(msg)
