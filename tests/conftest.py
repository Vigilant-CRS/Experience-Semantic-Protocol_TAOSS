# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Shared test configuration: deterministic seeds and Hypothesis profiles."""

import os
import random

import numpy as np
import pytest
from hypothesis import HealthCheck, settings

#: Global deterministic seed (master plan WP-000: deterministic seeds).
SEED = int(os.environ.get("ESP_TEST_SEED", "20260925"))

settings.register_profile("default", max_examples=200, deadline=None)
settings.register_profile(
    "ci",
    max_examples=1000,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile("thorough", max_examples=10_000, deadline=None, derandomize=True)
settings.load_profile(os.environ.get("HYPOTHESIS_PROFILE", "default"))


@pytest.fixture(autouse=True)
def _deterministic_seed() -> None:
    random.seed(SEED)
    np.random.seed(SEED % (2**32))


@pytest.fixture
def rng() -> np.random.Generator:
    """Explicit, seeded generator; prefer this over global state."""
    return np.random.default_rng(SEED)
