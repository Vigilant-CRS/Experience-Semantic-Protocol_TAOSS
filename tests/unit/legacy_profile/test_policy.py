# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-071: Experience Legacy policy objects and validation."""

import dataclasses
import uuid

import pytest

from esp.core.taoss_types import TaossType
from esp.crypto.primitives import SigningKey
from esp.legacy_profile import (
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

pytestmark = pytest.mark.security
T = TaossType
A = ActivationCondition
ORIGINATOR = SigningKey.from_seed(b"\x31" * 32)
WITNESSES = [SigningKey.from_seed(bytes([0x40 + i]) * 32) for i in range(3)]
CREATED = 1_000
DEATH_AT = 5_000
UNTIL = 10**12


def policy(**kw: object) -> LegacyPolicy:
    fields: dict[str, object] = {
        "policy_id": uuid.UUID("71717171-7171-4171-8171-717171717171"),
        "originator_pk": ORIGINATOR.public_bytes,
        "created_ns": CREATED,
        "types": frozenset({T.KNO, T.SEN, T.TEM, T.EMO}),
        "recipients": frozenset({RecipientClass.FAMILY}),
        "activation": (ActivationRule(A.DEATH_CERTIFIED),),
        "retention_until_ns": UNTIL,
        "renderer_rights": RendererRight.TEXT | RendererRight.VISUALIZATION,
        "machine_continuation": False,
        "posthumous_emo_synthesis": False,
        "quorum": Quorum(tuple(w.public_bytes for w in WITNESSES), 2),
    }
    return LegacyPolicy(**(fields | kw)).signed(ORIGINATOR)  # type: ignore[arg-type]


def activated(p: LegacyPolicy, n: int = 2):  # type: ignore[no-untyped-def]
    return activate(
        p,
        A.DEATH_CERTIFIED,
        DEATH_AT,
        [attest_activation(p, A.DEATH_CERTIFIED, DEATH_AT, w) for w in WITNESSES[:n]],
    )


def use(**kw: object) -> UseRequest:
    fields: dict[str, object] = {
        "recipient": RecipientClass.FAMILY,
        "types": frozenset({T.KNO}),
        "renderer": RendererRight.TEXT,
        "origin": LegacyOrigin.RECORDED_HUMAN_STATE,
        "now_ns": DEATH_AT + 1,
    }
    return UseRequest(**(fields | kw))  # type: ignore[arg-type]


def test_recorded_state_use_within_policy() -> None:
    p = policy()
    act = activated(p)
    assert authorize_use(p, act, use()) is LegacyOrigin.RECORDED_HUMAN_STATE
    # Recorded EMO (a stored self-declared state) is not synthesis.
    assert authorize_use(p, act, use(types=frozenset({T.EMO}))) is LegacyOrigin.RECORDED_HUMAN_STATE


def test_posthumous_emo_synthesis_needs_its_own_consent() -> None:
    p = policy(machine_continuation=True)
    act = activated(p)
    # Other types surviving never authorizes EMO synthesis.
    with pytest.raises(LegacyRefused, match="EMO synthesis"):
        authorize_use(
            p, act, use(types=frozenset({T.EMO}), origin=LegacyOrigin.LATER_SYNTHETIC_INFERENCE)
        )
    with pytest.raises(LegacyRefused, match="EMO synthesis"):
        authorize_use(p, act, use(emo_synthesis=True))
    # Non-EMO machine continuation is allowed by this policy.
    assert authorize_use(p, act, use(origin=LegacyOrigin.LATER_SYNTHETIC_INFERENCE)) is (
        LegacyOrigin.LATER_SYNTHETIC_INFERENCE
    )
    q = policy(machine_continuation=True, posthumous_emo_synthesis=True)
    assert (
        authorize_use(
            q,
            activated(q),
            use(types=frozenset({T.EMO}), origin=LegacyOrigin.LATER_SYNTHETIC_INFERENCE),
        )
        is LegacyOrigin.LATER_SYNTHETIC_INFERENCE
    )


def test_machine_continuation_needs_permission() -> None:
    p = policy()
    with pytest.raises(LegacyRefused, match="continuation"):
        authorize_use(p, activated(p), use(origin=LegacyOrigin.LATER_SYNTHETIC_INFERENCE))


def test_emo_synthesis_flag_requires_continuation() -> None:
    with pytest.raises(LegacyRefused, match="machine continuation"):
        policy(posthumous_emo_synthesis=True)


@pytest.mark.parametrize(
    ("request_kw", "match"),
    [
        ({"recipient": RecipientClass.PUBLIC}, "recipient"),
        ({"types": frozenset({T.INT})}, "types"),
        ({"types": frozenset()}, "types"),
        ({"renderer": RendererRight.IMMERSIVE}, "renderer"),
        ({"now_ns": UNTIL}, "retention"),
        ({"now_ns": DEATH_AT - 1}, "retention"),
    ],
)
def test_use_outside_policy_refused(request_kw: dict[str, object], match: str) -> None:
    p = policy()
    with pytest.raises(LegacyRefused, match=match):
        authorize_use(p, activated(p), use(**request_kw))


def test_activation_needs_quorum_of_members() -> None:
    p = policy()
    with pytest.raises(LegacyRefused, match="quorum"):
        activated(p, n=1)
    outsider = SigningKey.from_seed(b"\x99" * 32)
    atts = [
        attest_activation(p, A.DEATH_CERTIFIED, DEATH_AT, WITNESSES[0]),
        attest_activation(p, A.DEATH_CERTIFIED, DEATH_AT, outsider),
        attest_activation(p, A.DEATH_CERTIFIED, DEATH_AT, WITNESSES[0]),  # duplicate counts once
    ]
    with pytest.raises(LegacyRefused, match="quorum"):
        activate(p, A.DEATH_CERTIFIED, DEATH_AT, atts)
    # A signature over another time or condition does not count.
    wrong = [attest_activation(p, A.DEATH_CERTIFIED, DEATH_AT + 1, w) for w in WITNESSES]
    with pytest.raises(LegacyRefused, match="quorum"):
        activate(p, A.DEATH_CERTIFIED, DEATH_AT, wrong)
    assert activated(p, n=3).attesters == frozenset(w.public_bytes for w in WITNESSES)


def test_activation_condition_and_time() -> None:
    p = policy()
    atts = [attest_activation(p, A.INCAPACITY_CERTIFIED, DEATH_AT, w) for w in WITNESSES]
    with pytest.raises(LegacyRefused, match="not an activation condition"):
        activate(p, A.INCAPACITY_CERTIFIED, DEATH_AT, atts)
    dated = policy(activation=(ActivationRule(A.DATE_REACHED, not_before_ns=DEATH_AT),))
    early = [attest_activation(dated, A.DATE_REACHED, DEATH_AT - 1, w) for w in WITNESSES]
    with pytest.raises(LegacyRefused, match="permitted time"):
        activate(dated, A.DATE_REACHED, DEATH_AT - 1, early)
    late = [attest_activation(dated, A.DATE_REACHED, UNTIL, w) for w in WITNESSES]
    with pytest.raises(LegacyRefused, match="retention"):
        activate(dated, A.DATE_REACHED, UNTIL, late)


def test_policy_must_be_signed_by_originator_ex_ante() -> None:
    p = policy()
    p.verify()
    forged = dataclasses.replace(p, posthumous_emo_synthesis=True, machine_continuation=True)
    with pytest.raises(LegacyRefused, match="not signed"):
        forged.verify()
    with pytest.raises(LegacyRefused, match="not signed"):
        activated(forged)
    with pytest.raises(LegacyRefused, match="only the originator"):
        dataclasses.replace(p, signature=b"").signed(WITNESSES[0])


def test_activation_bound_to_policy() -> None:
    p, q = policy(), policy(recipients=frozenset({RecipientClass.FAMILY, RecipientClass.PUBLIC}))
    with pytest.raises(LegacyRefused, match="another policy"):
        authorize_use(q, activated(p), use())


@pytest.mark.parametrize(
    ("kw", "match"),
    [
        ({"types": frozenset()}, "types"),
        ({"recipients": frozenset()}, "recipient"),
        ({"activation": ()}, "activation"),
        ({"retention_until_ns": CREATED}, "retention"),
        ({"renderer_rights": RendererRight(0)}, "renderer"),
        (
            {
                "activation": (
                    ActivationRule(A.DEATH_CERTIFIED),
                    ActivationRule(A.DEATH_CERTIFIED, 7),
                )
            },
            "one rule",
        ),
        ({"originator_pk": WITNESSES[0].public_bytes}, "own activation quorum"),
    ],
)
def test_policy_declares_everything(kw: dict[str, object], match: str) -> None:
    with pytest.raises(LegacyRefused, match=match):
        policy(**kw)


def test_quorum_is_never_unilateral() -> None:
    keys = tuple(w.public_bytes for w in WITNESSES)
    with pytest.raises(LegacyRefused, match="at least 2"):
        Quorum(keys, 1)
    with pytest.raises(LegacyRefused, match="at least 2"):
        Quorum(keys, 4)
    with pytest.raises(LegacyRefused, match="distinct"):
        Quorum((keys[0], keys[0]), 2)
    with pytest.raises(LegacyRefused, match="public keys"):
        Quorum((b"x", keys[0]), 2)
    with pytest.raises(LegacyRefused, match="date"):
        ActivationRule(A.DATE_REACHED)


def test_policy_digest_is_canonical() -> None:
    a = policy(recipients=frozenset({RecipientClass.FAMILY, RecipientClass.EXECUTOR}))
    b = policy(recipients=frozenset({RecipientClass.EXECUTOR, RecipientClass.FAMILY}))
    assert a.digest() == b.digest()
    assert policy().digest() != policy(machine_continuation=True).digest()
