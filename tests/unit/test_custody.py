# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-072 acceptance tests: custody and recovery policies, Shamir k-of-n."""

import itertools
import secrets

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from esp.crypto.primitives import SigningKey, ed25519_verify
from esp.keys.custody import (
    NO_RECOVERY_MAX_LIFETIME_NS,
    CustodyError,
    CustodyKind,
    CustodyPolicy,
    RecoveryKind,
    RecoveryPolicy,
    Share,
    SoftwareMasterKey,
    combine_shares,
    split_secret,
)

SOCIAL = RecoveryPolicy(RecoveryKind.SOCIAL_K_OF_N, threshold=3, shares=5)


def test_software_custody_requires_disclosure_and_l1() -> None:
    with pytest.raises(CustodyError, match="disclosed"):
        CustodyPolicy(CustodyKind.SOFTWARE, SOCIAL, disclosed_to_user=False)
    with pytest.raises(CustodyError, match="L1"):
        CustodyPolicy(CustodyKind.SOFTWARE, SOCIAL, disclosed_to_user=True, profile=0x03)
    ok = CustodyPolicy(CustodyKind.SOFTWARE, SOCIAL, disclosed_to_user=True)
    key = SoftwareMasterKey(SigningKey.from_seed(b"\x01" * 32), ok)
    ed25519_verify(key.public_bytes, b"m", key.sign(b"m"))
    hw = CustodyPolicy(CustodyKind.TPM2, SOCIAL, disclosed_to_user=False, profile=0x03)
    with pytest.raises(CustodyError, match="SOFTWARE custody"):
        SoftwareMasterKey(SigningKey.from_seed(b"\x01" * 32), hw)


def test_recovery_policy_rules() -> None:
    with pytest.raises(CustodyError, match="k <= n"):
        RecoveryPolicy(RecoveryKind.SOCIAL_K_OF_N, threshold=1, shares=3)
    with pytest.raises(CustodyError, match="institution"):
        RecoveryPolicy(RecoveryKind.CUSTODIAL)
    with pytest.raises(CustodyError, match="short capability expiry"):
        RecoveryPolicy(RecoveryKind.NONE)
    none = RecoveryPolicy(RecoveryKind.NONE, max_capability_lifetime_ns=NO_RECOVERY_MAX_LIFETIME_NS)
    policy = CustodyPolicy(CustodyKind.FIDO2, none, disclosed_to_user=True)
    policy.check_capability_lifetime(valid_until_ns=NO_RECOVERY_MAX_LIFETIME_NS, now_ns=0)
    with pytest.raises(CustodyError, match="outlives"):
        policy.check_capability_lifetime(valid_until_ns=NO_RECOVERY_MAX_LIFETIME_NS + 1, now_ns=0)


def test_any_k_of_n_shares_recover_the_seed() -> None:
    seed = secrets.token_bytes(32)
    shares = split_secret(seed, 3, 5)
    for subset in itertools.combinations(shares, 3):
        assert combine_shares(list(subset)) == seed
    assert combine_shares(shares) == seed  # more than k is fine


def test_fewer_than_k_shares_fail() -> None:
    shares = split_secret(b"\x00" * 31 + b"\x01", 3, 5)
    with pytest.raises(CustodyError, match="at least 3"):
        combine_shares(shares[:2])


def test_tampered_duplicate_or_mixed_shares_are_detected() -> None:
    a = split_secret(secrets.token_bytes(32), 2, 3)
    b = split_secret(secrets.token_bytes(32), 2, 3)
    bad = Share(a[0].index, 2, (a[0].value + 1), a[0].tag)
    with pytest.raises(CustodyError, match="wrong or tampered"):
        combine_shares([bad, a[1]])
    with pytest.raises(CustodyError, match="duplicate"):
        combine_shares([a[0], a[0]])
    with pytest.raises(CustodyError, match="different secrets"):
        combine_shares([a[0], b[1]])


def test_leading_zero_bytes_survive_and_repr_hides_values() -> None:
    seed = b"\x00\x00\x07" + secrets.token_bytes(29)
    shares = split_secret(seed, 2, 2)
    assert combine_shares(shares) == seed
    assert "redacted" in repr(shares[0])
    assert str(shares[0].value) not in repr(shares[0])


@settings(max_examples=50)
@given(st.binary(min_size=1, max_size=64), st.integers(2, 6), st.data())
def test_split_combine_property(secret: bytes, k: int, data: st.DataObject) -> None:
    n = data.draw(st.integers(k, 8))
    shares = split_secret(secret, k, n)
    chosen = data.draw(st.permutations(shares)).__getitem__(slice(0, k))
    assert combine_shares(list(chosen)) == secret
