# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
import esp


def test_version_is_exposed() -> None:
    assert isinstance(esp.__version__, str)
    assert esp.__version__.count(".") == 2


def test_targets_v13_wire_1_0() -> None:
    assert esp.SPEC_VERSION == "V13"
    assert esp.WIRE_VERSION == (1, 0)
