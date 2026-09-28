# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-063: SF levels (strict), custom type-set profiles, I2I envelopes, wire rates."""

import math

import pytest

from esp.codec.errors import WireError
from esp.core.taoss_types import TaossType
from esp.session.profiles import (
    I2I_PRIVATE,
    I2I_TRUSTED,
    SF_LEVELS,
    bitrate_kbit_s,
    check_i2i_packet,
    profile_for,
    release_bytes,
)

K, I, E, C, S, T = (
    TaossType.KNO,
    TaossType.INT,
    TaossType.EMO,
    TaossType.CTX,
    TaossType.SEN,
    TaossType.TEM,
)


def test_sf_table_matches_v13() -> None:
    expected = {
        0: ({K}, set()),
        1: ({K, C}, set()),
        2: ({K, C, I}, set()),
        3: ({K, C, I, T}, set()),
        4: ({K, C, I, T}, {S}),
        5: ({K, C, I, T, S}, set()),
        6: ({K, C, I, T, S}, {E}),
        7: ({K, C, I, E, T, S}, set()),
    }
    for level, (required, optional) in expected.items():
        p = SF_LEVELS[level]
        assert set(p.required) == required
        assert set(p.optional) == optional


def test_strict_checks() -> None:
    SF_LEVELS[2].check(frozenset({K, C, I}), frozenset({E}))
    with pytest.raises(WireError, match="required types missing"):
        SF_LEVELS[2].check(frozenset({K, C}), frozenset())
    with pytest.raises(WireError, match="not allowed"):
        SF_LEVELS[2].check(frozenset({K, C, I, T}), frozenset())
    SF_LEVELS[6].check(frozenset({K, C, I, T, S}), frozenset({E}))  # EMO masked in SF6
    SF_LEVELS[6].check(frozenset({K, C, I, T, S, E}), frozenset())  # EMO opted in
    SF_LEVELS[4].check(frozenset({K, C, I, T}), frozenset())
    SF_LEVELS[4].check(frozenset({K, C, I, T, S}), frozenset())


def test_custom_type_set_profile_meb_handover() -> None:
    p = profile_for(0, frozenset({"esp-typeset-meb-handover-v1"}))
    p.check(frozenset({I, C, T, S}), frozenset({E}))
    with pytest.raises(WireError, match="not allowed"):
        p.check(frozenset({I, C, T, S, K}), frozenset())  # no KNO in MEB-HANDOVER
    with pytest.raises(WireError, match="sf_level 0"):
        profile_for(4, frozenset({"esp-typeset-meb-handover-v1"}))
    with pytest.raises(WireError, match="unknown SF"):
        profile_for(8)


def test_i2i_envelopes() -> None:
    check_i2i_packet(I2I_TRUSTED, consent_flags=0b111, privacy_flags=0x20, initial=True)
    check_i2i_packet(I2I_TRUSTED, consent_flags=0b110, privacy_flags=0x20, initial=False)
    with pytest.raises(WireError, match="consent flags"):
        check_i2i_packet(I2I_TRUSTED, consent_flags=0b110, privacy_flags=0x20, initial=True)
    with pytest.raises(WireError, match="TIMING_OBF"):
        check_i2i_packet(I2I_TRUSTED, consent_flags=0b111, privacy_flags=0x00, initial=True)
    with pytest.raises(WireError, match="DP is mandatory"):
        check_i2i_packet(I2I_PRIVATE, consent_flags=0b110, privacy_flags=0x20, initial=False)
    check_i2i_packet(I2I_PRIVATE, consent_flags=0b110, privacy_flags=0x22, initial=False)
    assert I2I_PRIVATE.aggregation_n == 10


def test_v13_wire_rate_arithmetic() -> None:
    sf5 = frozenset({K, C, I, T, S})
    trusted = release_bytes(sf5, bytes_per_coordinate=1)
    assert trusted == 448 + 65 + 180 == 693
    assert math.isclose(bitrate_kbit_s(trusted, 25), 138.6)
    assert math.isclose(bitrate_kbit_s(trusted, 50), 277.2)
    private = release_bytes(sf5, bytes_per_coordinate=1, dp_params_bytes=87)
    assert private == 780
    assert math.isclose(bitrate_kbit_s(private, 2.5), 15.6)
    assert math.isclose(bitrate_kbit_s(private, 5.0), 31.2)
