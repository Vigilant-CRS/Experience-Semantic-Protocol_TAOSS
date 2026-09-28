# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-059: absence symbols, policies, outputs, compatibility, renderers, panel."""

import json
import uuid

import numpy as np
import pytest

from esp.core.taoss_types import L1_DIMS, TaossType
from esp.decoder.compat import compatibility, mediated_compatibility
from esp.decoder.core import (
    Absent,
    DecodeRefused,
    DecoderPolicyError,
    DecoderProfile,
    audit_absence_handling,
    run_decoder,
    slots_of,
)
from esp.decoder.outputs import (
    ActionOutput,
    MediaOutput,
    OutputTag,
    TextOutput,
    VectorOutput,
    cosine_dissimilarity,
    default_distance,
    edit_distance,
)
from esp.decoder.reference import LinearDecoder, NearestAnchorDecoder, ZeroFillDecoder
from esp.decoder.render import RENDERERS, render_text, sparkline, transparency_panel
from esp.demo.compose import DemoState, compose_frame
from esp.frame.model import DisclosurePolicy, ExperienceFrame, TypeBlock
from esp.session.descriptor import DecoderPolicy as P

T = TaossType
TL = uuid.UUID("22222222-2222-4222-8222-222222222222")
EMOTIONS = ("anger", "fear", "joy", "sadness")


def frame(state: DemoState | None = None, seq: int = 1) -> ExperienceFrame:
    s = state or DemoState(emotions={"fear": 4}, context=("work",), knowledge=("k",))
    return compose_frame(s, timeline_id=TL, sequence=seq, now_ns=1)


def without_emo(f: ExperienceFrame) -> ExperienceFrame:
    return f.disclose(DisclosurePolicy(allowed_types=(T.KNO, T.INT, T.CTX)))


def with_zero_emo(f: ExperienceFrame) -> ExperienceFrame:
    blocks = tuple(
        TypeBlock(type=T.EMO, latent=(0.0,) * L1_DIMS[T.EMO]) if b.type is T.EMO else b
        for b in f.types
    )
    return ExperienceFrame.model_validate(f.model_dump() | {"types": blocks, "bindings": ()})


# --- absence ------------------------------------------------------------------------------


def test_masked_unsent_and_zero_are_three_different_things() -> None:
    masked = slots_of(without_emo(frame()))
    assert masked[T.EMO] == Absent(T.EMO, intentional=True)
    assert masked[T.SEN] == Absent(T.SEN, intentional=False)  # never part of the frame
    zero = slots_of(with_zero_emo(frame()))
    assert not isinstance(zero[T.EMO], Absent)
    assert not np.any(zero[T.EMO])


def test_profiles_must_declare_every_policy() -> None:
    with pytest.raises(DecoderPolicyError, match="no absence policy"):
        DecoderProfile("d", "1", OutputTag.VECTOR, frozenset({T.KNO, T.EMO}), {T.KNO: P.GRACEFUL})
    with pytest.raises(DecoderPolicyError, match="pinned 64-dim prior"):
        DecoderProfile("d", "1", OutputTag.VECTOR, frozenset({T.EMO}), {T.EMO: P.PRIOR_IMPUTE})
    with pytest.raises(DecoderPolicyError, match="pinned 64-dim prior"):
        DecoderProfile(
            "d", "1", OutputTag.VECTOR, frozenset({T.EMO}), {T.EMO: P.PRIOR_IMPUTE}, {T.EMO: (0.0,)}
        )
    with pytest.raises(DecoderPolicyError, match="only allowed under PRIOR_IMPUTE"):
        DecoderProfile(
            "d",
            "1",
            OutputTag.VECTOR,
            frozenset({T.EMO}),
            {T.EMO: P.GRACEFUL},
            {T.EMO: (0.0,) * 64},
        )


def test_strict_refuses_graceful_reports_prior_imputes() -> None:
    f = without_emo(frame())
    strict = LinearDecoder("strict", {T.KNO: P.STRICT_REFUSE, T.EMO: P.STRICT_REFUSE})
    with pytest.raises(DecodeRefused, match="EMO is masked"):
        run_decoder(strict, f)
    graceful = LinearDecoder("graceful", {T.KNO: P.STRICT_REFUSE, T.EMO: P.GRACEFUL})
    r = run_decoder(graceful, f)
    assert r.absent == (Absent(T.EMO, intentional=True),)
    assert r.used == (T.KNO,)
    assert set(r.unused) == {T.INT, T.CTX}  # sent, outside T_phi
    prior = tuple(np.linspace(-1, 1, 64))
    imputing = LinearDecoder(
        "impute", {T.KNO: P.STRICT_REFUSE, T.EMO: P.PRIOR_IMPUTE}, priors={T.EMO: prior}
    )
    r2 = run_decoder(imputing, f)
    assert r2.imputed == (T.EMO,)
    assert r2.absent == ()


def test_bottom_and_zero_take_different_decoder_paths() -> None:
    d = LinearDecoder("g", {T.KNO: P.STRICT_REFUSE, T.EMO: P.GRACEFUL})
    out_bottom = run_decoder(d, without_emo(frame())).output
    out_zero = run_decoder(d, with_zero_emo(frame())).output
    assert out_bottom != out_zero
    audit_absence_handling(d)
    bad = ZeroFillDecoder("zero-fill", {T.KNO: P.STRICT_REFUSE, T.EMO: P.GRACEFUL})
    with pytest.raises(DecoderPolicyError, match="absent EMO as a zero vector"):
        audit_absence_handling(bad)
    assert (
        run_decoder(bad, without_emo(frame())).output
        == run_decoder(bad, with_zero_emo(frame())).output
    )


def test_output_tag_must_match_profile() -> None:
    class Liar(LinearDecoder):
        def decode(self, inputs):  # type: ignore[no-untyped-def,override]
            return TextOutput("surprise")

    with pytest.raises(DecoderPolicyError, match="produced"):
        run_decoder(Liar("liar", {T.KNO: P.STRICT_REFUSE}), frame())


# --- outputs -------------------------------------------------------------------------------


def test_comparison_functionals() -> None:
    assert edit_distance("fear", "fear") == 0.0
    assert edit_distance("fear", "bear") == 0.25
    a, b, c = (1.0, 0.0), (1.0, 1.0), (0.0, 1.0)
    # cosine dissimilarity is not a metric: the triangle inequality fails
    assert cosine_dissimilarity(a, c) > cosine_dissimilarity(a, b) + cosine_dissimilarity(b, c)
    m = MediaOutput((2, 2, 1), (0.1, 0.5, 0.9, 0.3))
    assert default_distance(m, m) == pytest.approx(0.0)
    assert default_distance(ActionOutput((1, 2, 3)), ActionOutput((1, 0, 3))) == 1.0
    with pytest.raises(TypeError, match="mediated"):
        default_distance(TextOutput("x"), VectorOutput((1.0,)))
    with pytest.raises(ValueError, match="shape"):
        MediaOutput((2, 2), (0.0,))


# --- compatibility ---------------------------------------------------------------------------


def references(n: int = 40, seed: int = 11) -> list[DemoState]:
    rng = np.random.default_rng(seed)
    return [
        DemoState(
            emotions={str(rng.choice(EMOTIONS)): int(rng.integers(3, 6))},
            valence=int(rng.integers(1, 6)),
            arousal=int(rng.integers(1, 6)),
            context=(str(rng.choice(["work", "home", "school"])),),
            knowledge=(f"topic_{int(rng.integers(0, 5))}",),
        )
        for _ in range(n)
    ]


def encode(state: DemoState) -> ExperienceFrame:
    return frame(state)


def test_compatibility_metrics_are_reproducible_and_ordered() -> None:
    policies = {T.KNO: P.STRICT_REFUSE, T.EMO: P.STRICT_REFUSE, T.CTX: P.GRACEFUL}
    a = LinearDecoder("vendor-a", policies, seed=3)
    b = LinearDecoder("vendor-b", policies, seed=3, noise=0.05)
    refs = references()
    r1 = compatibility(refs, encode, a, b, q=0.9)
    r2 = compatibility(refs, encode, a, b, q=0.9)
    assert r1 == r2  # reproducible on the synthetic reference set
    assert 0.0 < r1.mean <= r1.quantile <= r1.worst
    same = compatibility(refs, encode, a, LinearDecoder("a2", policies, seed=3))
    assert same.worst == 0.0
    assert same.compatible(0.0, epsilon_q=0.0, epsilon_max=0.0)
    assert not r1.compatible(r1.mean / 2)
    with pytest.raises(ValueError, match="empty"):
        compatibility([], encode, a, b)


def test_anchor_mediated_compatibility_across_output_spaces() -> None:
    def realization(label: str) -> tuple[float, ...]:
        emo = frame(DemoState(emotions={label: 5})).block(T.EMO)
        assert emo is not None
        assert emo.latent is not None
        return emo.latent

    base = {label: realization(label) for label in EMOTIONS}
    rng = np.random.default_rng(5)
    shifted = {k: tuple(np.asarray(v) + 0.02 * rng.normal(size=64)) for k, v in base.items()}
    text_a = NearestAnchorDecoder("text-a", T.EMO, base)
    text_b = NearestAnchorDecoder("text-b", T.EMO, shifted)
    refs = references()

    def psi(state: DemoState) -> str:
        return max(state.emotions, key=lambda k: state.emotions[k])

    def classify(out: object) -> str:
        assert isinstance(out, TextOutput)
        return out.text

    agreement, ok = mediated_compatibility(
        refs, psi, (encode, text_a, classify), (encode, text_b, classify), epsilon=0.2
    )
    assert agreement >= 0.8
    assert ok
    again, _ = mediated_compatibility(
        refs, psi, (encode, text_a, classify), (encode, text_b, classify), epsilon=0.2
    )
    assert again == agreement


# --- renderers and transparency panel -------------------------------------------------------------


def test_renderers_and_transparency_panel() -> None:
    f = without_emo(frame())
    text = render_text(f)
    assert "masked:  EMO" in text
    assert "intention readiness: none" in text
    full = render_text(frame(DemoState(emotions={"fear": 4}, readiness={"avoid": 5})))
    assert "affect [self_declared]" in full
    assert "avoid 1.00" in full
    assert json.loads(RENDERERS["machine"](f))["masked_types"] == ["EMO"]
    assert "KNO" in RENDERERS["vector"](f)
    assert sparkline([0.0, 1.0]) == "▁█"
    d = LinearDecoder("g", {T.KNO: P.STRICT_REFUSE, T.EMO: P.GRACEFUL})
    panel = transparency_panel(f, [run_decoder(d, f)], "text")
    assert panel["masked_by_sender"] == ["EMO"]
    assert panel["not_sent"] == ["SEN", "TEM"]
    assert panel["decoders"][0]["absent_graceful"] == [{"type": "EMO", "intentional": True}]
    assert set(panel["cannot_reconstruct"]) == {"EMO", "SEN", "TEM", "INT", "CTX"}


def test_decoder_policies_must_match_the_session_profile() -> None:
    from esp.decoder.core import check_against_session  # noqa: PLC0415

    d = LinearDecoder("g", {T.KNO: P.STRICT_REFUSE, T.EMO: P.GRACEFUL})
    check_against_session(d.profile, {T.KNO: P.STRICT_REFUSE, T.EMO: P.GRACEFUL, T.CTX: P.GRACEFUL})
    with pytest.raises(DecoderPolicyError, match="declares STRICT_REFUSE"):
        check_against_session(d.profile, dict.fromkeys(T, P.STRICT_REFUSE))
    with pytest.raises(DecoderPolicyError, match="no decoder policy"):
        check_against_session(d.profile, {T.KNO: P.STRICT_REFUSE})
