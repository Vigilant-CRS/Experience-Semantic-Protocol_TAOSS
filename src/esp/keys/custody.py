# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Master-key custody and recovery (V13 section 9.6; WP-072).

- Custody: ``sk_M`` SHOULD be hardware-backed and non-exportable. Software
  custody is acceptable only for low-stakes L1 profiles and MUST be disclosed
  to the user. Hardware backends (TPM 2.0, PKCS#11, FIDO2) plug in through the
  :class:`~esp.crypto.identity.MasterSigner` protocol.
- Recovery: every profile declares one of pre-registered successor keys,
  social k-of-n recovery (Shamir secret sharing of a recovery seed),
  custodial recovery, or "none" — the latter only with short capability
  expiry so orphaned grants age out.

Shamir's scheme is implemented over the prime field GF(2^521 - 1) with
coefficients from the OS CSPRNG. Each share carries a 16-byte tag of the
secret so that a wrong or tampered share set is detected on recovery.
"""

from __future__ import annotations

import hmac
import secrets
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum, unique
from typing import Final

from esp.core.errors import ErrorCode, EspError
from esp.crypto.primitives import SigningKey, blake2b

PRIME: Final = 2**521 - 1
MAX_SECRET_BYTES: Final = 64
#: Upper bound on capability lifetime when a profile has no recovery (V13).
NO_RECOVERY_MAX_LIFETIME_NS: Final = 30 * 24 * 3600 * 10**9


class CustodyError(EspError):
    code = ErrorCode.VALIDATION


@unique
class CustodyKind(StrEnum):
    SOFTWARE = "software"
    TPM2 = "tpm2"
    PKCS11 = "pkcs11"
    FIDO2 = "fido2"


@unique
class RecoveryKind(StrEnum):
    PRE_REGISTERED_SUCCESSOR = "pre_registered_successor"
    SOCIAL_K_OF_N = "social_k_of_n"
    CUSTODIAL = "custodial"
    NONE = "none"


@dataclass(frozen=True, slots=True)
class RecoveryPolicy:
    kind: RecoveryKind
    threshold: int = 0
    shares: int = 0
    custodian: str | None = None
    max_capability_lifetime_ns: int | None = None

    def __post_init__(self) -> None:
        if (
            self.kind is RecoveryKind.SOCIAL_K_OF_N
            and not 2 <= self.threshold <= self.shares <= 255
        ):
            msg = "social recovery needs 2 <= k <= n <= 255"
            raise CustodyError(msg)
        if self.kind is RecoveryKind.CUSTODIAL and not self.custodian:
            msg = "custodial recovery must name (and disclose) the institution"
            raise CustodyError(msg)
        if self.kind is RecoveryKind.NONE and (
            self.max_capability_lifetime_ns is None
            or self.max_capability_lifetime_ns > NO_RECOVERY_MAX_LIFETIME_NS
        ):
            msg = "'no recovery' requires short capability expiry defaults"
            raise CustodyError(msg)


@dataclass(frozen=True, slots=True)
class CustodyPolicy:
    kind: CustodyKind
    recovery: RecoveryPolicy
    disclosed_to_user: bool
    profile: int = 0x01

    def __post_init__(self) -> None:
        if self.kind is CustodyKind.SOFTWARE:
            if self.profile != 0x01:
                msg = "software custody is only acceptable for low-stakes L1 profiles"
                raise CustodyError(msg)
            if not self.disclosed_to_user:
                msg = "software custody must be disclosed to the user"
                raise CustodyError(msg)

    def check_capability_lifetime(self, valid_until_ns: int, now_ns: int) -> None:
        limit = self.recovery.max_capability_lifetime_ns
        if limit is not None and valid_until_ns - now_ns > limit:
            msg = "capability outlives the no-recovery lifetime bound"
            raise CustodyError(msg)


class SoftwareMasterKey:
    """Software-held master key; only valid together with a disclosed policy."""

    __slots__ = ("_key", "policy")

    def __init__(self, key: SigningKey, policy: CustodyPolicy) -> None:
        if policy.kind is not CustodyKind.SOFTWARE:
            msg = "SoftwareMasterKey requires a SOFTWARE custody policy"
            raise CustodyError(msg)
        self._key = key
        self.policy = policy

    @property
    def public_bytes(self) -> bytes:
        return self._key.public_bytes

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


# --- Shamir secret sharing over GF(2^521 - 1) ---------------------------------------


@dataclass(frozen=True, slots=True)
class Share:
    index: int
    threshold: int
    value: int
    tag: bytes

    def __repr__(self) -> str:
        return f"Share(index={self.index}, threshold={self.threshold}, value=<redacted>)"


def _tag(secret: bytes) -> bytes:
    return blake2b(b"esp/v1/recovery-tag" + secret, digest_size=16)


def split_secret(secret: bytes, threshold: int, shares: int) -> list[Share]:
    """Split ``secret`` into ``shares`` shares; any ``threshold`` of them recover it."""
    if not 1 <= len(secret) <= MAX_SECRET_BYTES:
        msg = f"secret must be 1..{MAX_SECRET_BYTES} bytes"
        raise CustodyError(msg)
    if not 2 <= threshold <= shares <= 255:
        msg = "need 2 <= threshold <= shares <= 255"
        raise CustodyError(msg)
    s = int.from_bytes(b"\x01" + secret, "big")  # leading 0x01 keeps leading zero bytes
    coefficients = [s] + [secrets.randbelow(PRIME) for _ in range(threshold - 1)]
    tag = _tag(secret)

    def poly(x: int) -> int:
        acc = 0
        for c in reversed(coefficients):
            acc = (acc * x + c) % PRIME
        return acc

    return [Share(i, threshold, poly(i), tag) for i in range(1, shares + 1)]


def combine_shares(shares: Sequence[Share]) -> bytes:
    """Lagrange interpolation at 0; verifies the tag of the recovered secret."""
    if not shares:
        msg = "no shares"
        raise CustodyError(msg)
    threshold, tag = shares[0].threshold, shares[0].tag
    if any(sh.threshold != threshold or sh.tag != tag for sh in shares):
        msg = "shares belong to different secrets"
        raise CustodyError(msg)
    indices = [sh.index for sh in shares]
    if len(set(indices)) != len(indices):
        msg = "duplicate share index"
        raise CustodyError(msg)
    if len(shares) < threshold:
        msg = f"need at least {threshold} shares"
        raise CustodyError(msg)
    points = shares[:threshold]
    secret = 0
    for j, sj in enumerate(points):
        num, den = 1, 1
        for m, sm in enumerate(points):
            if m != j:
                num = (num * -sm.index) % PRIME
                den = (den * (sj.index - sm.index)) % PRIME
        secret = (secret + sj.value * num * pow(den, -1, PRIME)) % PRIME
    raw = secret.to_bytes((secret.bit_length() + 7) // 8, "big")
    if not raw or raw[0] != 0x01:
        msg = "recovered value is not a valid secret (wrong or tampered shares)"
        raise CustodyError(msg)
    recovered = raw[1:]
    if not hmac.compare_digest(_tag(recovered), tag):
        msg = "recovery tag mismatch (wrong or tampered shares)"
        raise CustodyError(msg)
    return recovered
