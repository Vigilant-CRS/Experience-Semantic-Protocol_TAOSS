# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Experience Legacy profile: policy objects and validation (WP-071, class ``FUTURE``)."""

from esp.legacy_profile.policy import (
    CLAIM_CLASS,
    Activation,
    ActivationCondition,
    ActivationRule,
    LegacyOrigin,
    LegacyPolicy,
    LegacyRefused,
    Quorum,
    RecipientClass,
    RendererRight,
    UseRequest,
    activate,
    attest_activation,
    authorize_use,
)

__all__ = [
    "CLAIM_CLASS",
    "Activation",
    "ActivationCondition",
    "ActivationRule",
    "LegacyOrigin",
    "LegacyPolicy",
    "LegacyRefused",
    "Quorum",
    "RecipientClass",
    "RendererRight",
    "UseRequest",
    "activate",
    "attest_activation",
    "authorize_use",
]
