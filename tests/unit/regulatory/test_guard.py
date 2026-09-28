# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-078: regulatory declaration, Art. 5(1)(f) guard, runtime scope enforcement."""

import itertools
import uuid
from pathlib import Path

import pytest

from esp.core.provenance import AffectScope
from esp.core.taoss_types import TaossType
from esp.frame.model import DisclosurePolicy, ExperienceFrame, TypeBlock
from esp.regulatory.guard import (
    HIGH_RISK_OBLIGATIONS,
    DeploymentContext,
    Exemption,
    MisdeclarationError,
    ProhibitedPracticeError,
    Regime,
    RegulatoryDeclaration,
    RegulatoryError,
    assess,
    check_frame,
    require_permitted,
)
from esp.semantics.episode import EmotionEpisode
from tests.integration.test_endpoint import DECLARATION, NOW, establish, pair
from tests.unit.frame.factory import full_frame
from tests.unit.frame.test_frame_wire import full_anchor_frame

pytestmark = pytest.mark.security

S = AffectScope
C = DeploymentContext


def decl(**kw: object) -> RegulatoryDeclaration:
    base: dict[str, object] = {
        "regimes": (Regime.EU_AI_ACT,),
        "intended_use": "test",
        "deployment_context": C.OTHER,
        "biometric_inputs": False,
        "affect_scopes": (S.SELF_DECLARED,),
    }
    return RegulatoryDeclaration(**(base | kw))  # type: ignore[arg-type]


def _subsets[T](items: list[T]) -> list[tuple[T, ...]]:
    return [
        tuple(sorted(c)) for r in range(len(items) + 1) for c in itertools.combinations(items, r)
    ]


def test_guard_over_all_combinations() -> None:
    """Exhaustive: prohibited iff EU AI Act ∧ biometric ∧ inferred-subject ∧ W/E ∧ no exemption."""
    checked = 0
    for regimes, context, biometric, scopes, intention, exemption in itertools.product(
        [r for r in _subsets(list(Regime)) if r],
        list(C),
        [False, True],
        _subsets(list(S)),
        [False, True],
        list(Exemption),
    ):
        d = decl(
            regimes=regimes,
            deployment_context=context,
            biometric_inputs=biometric,
            affect_scopes=scopes,
            infers_subject_intention=intention,
            exemption=exemption,
            exemption_justification="" if exemption is Exemption.NONE else "clinical protocol",
        )
        eu = Regime.EU_AI_ACT in regimes
        expected = (
            eu
            and biometric
            and S.INFERRED_SUBJECT in scopes
            and context in {C.WORKPLACE, C.EDUCATION}
            and exemption is Exemption.NONE
        )
        a = assess(d)
        assert a.prohibited == expected, d
        recognition = eu and biometric and (S.INFERRED_SUBJECT in scopes or intention)
        assert a.high_risk == (recognition and not expected)
        if expected:
            with pytest.raises(ProhibitedPracticeError, match=r"5\(1\)\(f\)"):
                require_permitted(d)
        elif a.high_risk:
            with pytest.raises(MisdeclarationError, match="high-risk"):
                require_permitted(d)
            ok = require_permitted(d.model_copy(update={"high_risk_declared": True}))
            assert ok.obligations == HIGH_RISK_OBLIGATIONS
        else:
            assert require_permitted(d).obligations == ()
        checked += 1
    assert checked == 7 * 5 * 2 * 16 * 2 * 3


def test_missing_declaration_refuses_start() -> None:
    with pytest.raises(RegulatoryError, match="does not start"):
        require_permitted(None)


def test_exemption_needs_justification_and_declarations_are_canonical() -> None:
    with pytest.raises(ValueError, match="justification"):
        decl(exemption=Exemption.MEDICAL)
    with pytest.raises(ValueError, match="justification"):
        decl(exemption_justification="because")
    with pytest.raises(ValueError, match="sorted"):
        decl(affect_scopes=(S.SELF_DECLARED, S.CONTENT))


def test_audit_record_is_deterministic_and_complete() -> None:
    d = decl(biometric_inputs=True, affect_scopes=(S.INFERRED_SUBJECT,), high_risk_declared=True)
    r1, r2 = d.audit_record(), d.audit_record()
    assert r1 == r2
    assert r1["high_risk"] is True
    assert r1["declaration_digest"] == d.digest()
    assert len(str(r1["declaration_digest"])) == 64


def test_runtime_check_refuses_undeclared_scopes() -> None:
    frame = full_frame()  # carries a SELF_DECLARED affect descriptor
    check_frame(decl(), frame)
    with pytest.raises(MisdeclarationError, match="self_declared"):
        check_frame(decl(affect_scopes=(S.CONTENT,)), frame)


def test_episode_scope_is_enforced_like_descriptor_scope() -> None:
    """GAP-030 resolved: episodes carry their own affect_scope, checked like descriptors."""
    frame = full_frame()
    emo = frame.block(TaossType.EMO)
    assert emo is not None

    def with_episode(scope: S) -> ExperienceFrame:
        bare = TypeBlock(
            type=TaossType.EMO,
            latent=emo.latent,
            episodes=(
                EmotionEpisode(
                    id=uuid.UUID("c0ffee00-0000-4000-8000-000000000001"),
                    affect_scope=scope,
                    onset_ns=1,
                    peak_ns=2,
                ),
            ),
        )
        blocks = tuple(bare if b.type is TaossType.EMO else b for b in frame.types)
        return ExperienceFrame.model_validate(
            frame.model_dump() | {"types": blocks, "bindings": ()}
        )

    check_frame(decl(), with_episode(S.SELF_DECLARED))  # declared: fine
    with pytest.raises(MisdeclarationError, match="inferred_subject"):
        check_frame(decl(), with_episode(S.INFERRED_SUBJECT))


# --- endpoint integration ---------------------------------------------------------------


def test_prohibited_or_missing_declaration_stops_endpoints(tmp_path: Path) -> None:
    import tests.integration.test_endpoint as te  # noqa: PLC0415

    prohibited = decl(
        deployment_context=C.WORKPLACE, biometric_inputs=True, affect_scopes=(S.INFERRED_SUBJECT,)
    )
    for bad, err in ((prohibited, ProhibitedPracticeError), (None, RegulatoryError)):
        original = te.DECLARATION
        te.DECLARATION = bad  # type: ignore[assignment]
        try:
            with pytest.raises(err):
                pair(tmp_path)
        finally:
            te.DECLARATION = original


def test_sender_refuses_and_receiver_does_not_deliver_undeclared_scopes(tmp_path: Path) -> None:
    s, r = pair(tmp_path, sf=6)
    establish(s, r)
    policy = DisclosurePolicy(allowed_types=tuple(TaossType))
    s._declaration = decl(affect_scopes=(S.CONTENT,))
    with pytest.raises(MisdeclarationError):
        s.send_frame(full_anchor_frame(), policy, now_ns=NOW)
    s._declaration = DECLARATION
    r._declaration = decl(affect_scopes=(S.CONTENT,))
    result = r.receive(s.send_frame(full_anchor_frame(), policy, now_ns=NOW), now_ns=NOW)
    assert not result.accepted
    assert result.frame is None
    assert any(v.startswith("regulatory:") for v in result.violations)
