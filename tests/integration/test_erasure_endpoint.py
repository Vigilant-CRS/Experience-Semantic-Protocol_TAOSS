# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Masked-type erasure in a real session: declared, applied, enforceable by the receiver."""

from pathlib import Path

import numpy as np
import pytest

from esp.core.taoss_types import TaossType as T
from esp.frame.model import DisclosurePolicy
from esp.privacy.erasure import ErasureProfile, LeaceEraser, declared_erasures
from esp.session.endpoint import ReceiverHardening
from tests.integration.test_endpoint import NOW, establish, pair
from tests.unit.frame.test_frame_wire import full_anchor_frame

pytestmark = [pytest.mark.integration, pytest.mark.security]
RELEASED = tuple(t for t in T if t is not T.EMO)
POLICY = DisclosurePolicy(allowed_types=RELEASED)


def _profile() -> tuple[ErasureProfile, tuple[T, ...]]:
    disclosed = full_anchor_frame().disclose(POLICY)
    present = tuple(
        sorted((b.type for b in disclosed.types if b.latent is not None), key=lambda t: t.value)
    )
    dims = [len(disclosed.block(t).latent) for t in present]  # type: ignore[union-attr, arg-type]
    rng = np.random.default_rng(3)
    blocks = [rng.normal(size=(800, d)) for d in dims]
    concept = blocks[0][:, :4] @ rng.normal(size=(4, 3))
    eraser = LeaceEraser.fit(
        blocks, concept, concept=T.EMO, released_types=present, training_data_id="test:v1"
    )
    return ErasureProfile((eraser,)), present


def test_erased_latents_arrive_with_their_declaration(tmp_path: Path) -> None:
    profile, present = _profile()
    s, r = pair(tmp_path, sf=6)
    s._erasure = profile
    r._hardening = ReceiverHardening(require_erasure=frozenset({T.EMO}))
    establish(s, r)
    res = r.receive(s.send_frame(full_anchor_frame(), POLICY, now_ns=NOW), now_ns=NOW)
    assert res.accepted, res.violations
    assert res.frame is not None
    assert T.EMO in res.frame.masked_types
    assert declared_erasures(res.frame.provenance.evidence_refs) == {T.EMO}
    assert profile.erasers[0].ref in res.frame.provenance.evidence_refs
    original = full_anchor_frame().disclose(POLICY)
    before = np.concatenate([original.block(t).latent for t in present])  # type: ignore[union-attr]
    got = np.concatenate([res.frame.block(t).latent for t in present])  # type: ignore[union-attr]
    np.testing.assert_allclose(got, profile.erasers[0].apply(before), atol=1e-4)  # float32 wire


def test_receiver_requiring_erasure_refuses_undeclared_frames(tmp_path: Path) -> None:
    s, r = pair(tmp_path, sf=6)  # sender without an erasure profile
    r._hardening = ReceiverHardening(require_erasure=frozenset({T.EMO}))
    establish(s, r)
    res = r.receive(s.send_frame(full_anchor_frame(), POLICY, now_ns=NOW), now_ns=NOW)
    assert not res.accepted
    assert res.violations[0].startswith("erasure:")


def test_no_requirement_when_the_concept_is_disclosed(tmp_path: Path) -> None:
    s, r = pair(tmp_path, sf=6)
    r._hardening = ReceiverHardening(require_erasure=frozenset({T.EMO}))
    establish(s, r)
    everything = DisclosurePolicy(allowed_types=tuple(T))
    assert r.receive(s.send_frame(full_anchor_frame(), everything, now_ns=NOW), now_ns=NOW).accepted
