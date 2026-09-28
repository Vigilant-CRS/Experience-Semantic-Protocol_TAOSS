# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-080: one regression per V13 failure mode (docs/FAILURE_MODES.md)."""

from pathlib import Path

import numpy as np
import pytest

from esp.audit.suite import covert_channel_audit, v_information_ladder
from esp.bench.smoke import TYPES, encode, make_corpus
from esp.bench.tasks import encoder_drift, ood_anchor_shift
from esp.training.leakage import leakage_matrix

pytestmark = pytest.mark.security
ROOT = Path(__file__).resolve().parents[2]


def test_type_collapse_is_detected() -> None:
    rng = np.random.default_rng(0)
    shared = rng.normal(size=(800, 4))
    collapsed = {
        t: shared @ rng.normal(size=(4, 6)) + 0.05 * rng.normal(size=(800, 6)) for t in TYPES
    }
    healthy = {t: rng.normal(size=(800, 6)) for t in TYPES}
    assert len(leakage_matrix(collapsed, n_boot=30).significant()) == 30  # every ordered pair
    assert leakage_matrix(healthy, n_boot=30).significant() == []


def test_encoder_drift_is_detected() -> None:
    c = make_corpus()
    same = encoder_drift(c, encode(c, "taoss"))  # another seed, same semantics
    assert min(same.metrics.values()) > 0.95
    drifted = encode(c, "taoss")
    drifted["EMO"], drifted["CTX"] = drifted["CTX"], drifted["EMO"][:, : drifted["CTX"].shape[1]]
    moved = encoder_drift(c, drifted)
    assert moved.metrics["compat_EMO"] < 0.5  # semantic change survives alignment -> flagged


def test_anchor_shift_beyond_ten_percent_is_flagged() -> None:
    small = ood_anchor_shift(
        make_corpus(ood_shift=0.1), encode(make_corpus(ood_shift=0.1), "taoss")
    )
    large_c = make_corpus(ood_shift=2.5)
    large = ood_anchor_shift(large_c, encode(large_c, "taoss"))
    assert small.metrics["relative_degradation"] <= 0.10
    assert large.metrics["relative_degradation"] > 0.10


def test_weak_auditor_miss_is_closed_by_the_ladder() -> None:
    rng = np.random.default_rng(4)
    emo = rng.normal(size=(1500, 2))
    tem = emo + 0.3 * rng.normal(size=emo.shape)
    intensity = np.sum(emo**2, axis=1, keepdims=True)
    linear, *_, strongest = v_information_ladder(tem, intensity)
    assert linear < 0.05  # a linear-only audit would pass this channel
    assert strongest > 1.0  # the ladder (reported maximum) does not


def test_emo_stego_sender_fails_the_audit() -> None:
    rng = np.random.default_rng(1)
    emo = rng.normal(size=(1500, 2))
    honest = rng.normal(size=(1500, 4))
    stego = honest + 0.7 * np.concatenate([np.sin(1.2 * emo), np.cos(1.2 * emo)], axis=1)
    assert covert_channel_audit(honest, emo).passed
    assert not covert_channel_audit(stego, emo).passed


def test_crafted_vectors_never_reach_the_decoder(tmp_path: Path) -> None:
    from esp.core.taoss_types import TaossType  # noqa: PLC0415
    from tests.integration.test_endpoint import NOW, establish, pair  # noqa: PLC0415
    from tests.integration.test_receiver_threats import adversarial, raw_latent  # noqa: PLC0415

    s, r = pair(tmp_path)
    establish(s, r)
    for poison in (np.full(240, np.nan), np.full(240, 1e30), np.full(240, np.inf)):
        with np.errstate(over="ignore", invalid="ignore"):
            result = r.receive(
                adversarial(s, {TaossType.KNO}, raw_latent(TaossType.KNO, poison)), now_ns=NOW
            )
        assert not result.accepted
    assert r.decoder_invocations == 0


def test_non_technical_failure_modes_are_documented() -> None:
    doc = (ROOT / "docs" / "FAILURE_MODES.md").read_text(encoding="utf-8")
    for mode in ("Linguistic atrophy at scale", "Coercion at scale"):
        row = next(line for line in doc.splitlines() if line.startswith(f"| {mode}"))
        assert "not technically mitigable" in row
