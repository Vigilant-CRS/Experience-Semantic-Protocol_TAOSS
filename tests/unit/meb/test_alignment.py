# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-066: block-preserving alignment, cycle loss, eta compatibility, cross-type adapters."""

import numpy as np
import pytest

from esp.core.taoss_types import TaossType
from esp.meb.alignment import (
    BridgeMaps,
    CrossTypeAuditFailed,
    CrossTypeDeclaration,
    UndeclaredCrossTypeError,
    bridge_loss,
    cross_type_adapt,
    eta_compatibility,
    is_eta_compatible,
    train_bridge,
)
from esp.meb.profiles import MebError

T = TaossType


@pytest.fixture(scope="module")
def paired() -> tuple[dict[TaossType, np.ndarray], dict[TaossType, np.ndarray]]:
    """Synthetic pairs: human = rotated machine latent + noise (sigma 0.05)."""
    rng = np.random.default_rng(0)
    zm = {T.INT: rng.normal(size=(400, 64)), T.TEM: rng.normal(size=(400, 16))}
    zh = {}
    for t, z in zm.items():
        rot = np.linalg.qr(rng.normal(size=(z.shape[1], z.shape[1])))[0]
        zh[t] = z @ rot + 0.05 * rng.normal(size=z.shape)
    return zm, zh


def test_training_recovers_the_map_and_never_increases_the_objective(paired) -> None:  # type: ignore[no-untyped-def]
    zm, zh = paired
    maps, traces = train_bridge(zm, zh, iterations=5)
    for t, trace in traces.items():
        obj = np.array(trace.objective)
        assert np.all(np.diff(obj) <= 1e-9 * obj[:-1]), t  # exact block-coordinate descent
    eta = eta_compatibility(maps, zm, zh)
    for t, z in zm.items():
        noise = 0.05**2 * z.shape[1]
        assert eta[t] < 1.5 * noise, t  # at the noise floor
    # the cycle m→h→m approximately recovers the machine latent
    back = maps.to_machine(maps.to_human(zm))
    for t in zm:
        assert np.mean(np.sum((back[t] - zm[t]) ** 2, axis=1)) < 0.05 * zm[t].shape[1]
    loss = bridge_loss(maps, zm, zh, lambda_cycle=1.0)
    identity = BridgeMaps(
        {t: np.eye(z.shape[1]) for t, z in zm.items()},
        {t: np.eye(z.shape[1]) for t, z in zm.items()},
    )
    assert loss < 0.1 * bridge_loss(identity, zm, zh, lambda_cycle=1.0)
    assert bridge_loss(maps, zm, zh, lambda_cycle=1.0, human_cycle=True) >= loss


def test_bridge_is_block_preserving(paired) -> None:  # type: ignore[no-untyped-def]
    zm, zh = paired
    maps, _ = train_bridge(zm, zh, iterations=1)
    only_int = maps.to_human({T.INT: zm[T.INT]})
    assert set(only_int) == {T.INT}
    # changing TEM does not change the INT image: no block mixing
    a = maps.to_human({T.INT: zm[T.INT], T.TEM: zm[T.TEM]})
    b = maps.to_human({T.INT: zm[T.INT], T.TEM: -zm[T.TEM]})
    np.testing.assert_array_equal(a[T.INT], b[T.INT])
    with pytest.raises(MebError, match="no alignment"):
        maps.to_human({T.CTX: np.zeros((1, 64))})


def test_eta_compatibility_is_per_type(paired) -> None:  # type: ignore[no-untyped-def]
    zm, zh = paired
    maps, _ = train_bridge(zm, zh, iterations=2)
    assert is_eta_compatible(maps, zm, zh, {T.INT: 1.0, T.TEM: 1.0})
    assert not is_eta_compatible(maps, zm, zh, {T.INT: 1.0, T.TEM: 1e-6})
    assert not is_eta_compatible(maps, zm, zh, {T.INT: 1.0})  # a missing eta_t fails


def test_training_input_validation(paired) -> None:  # type: ignore[no-untyped-def]
    zm, zh = paired
    with pytest.raises(MebError, match="same type set"):
        train_bridge(zm, {T.INT: zh[T.INT]})
    with pytest.raises(MebError, match="never author EMO"):
        train_bridge({T.EMO: zm[T.INT]}, {T.EMO: zh[T.INT]})
    with pytest.raises(MebError, match="equal shape"):
        train_bridge({T.INT: zm[T.INT]}, {T.INT: zh[T.INT][:10]})
    with pytest.raises(ValueError, match="positive"):
        train_bridge(zm, zh, lambda_cycle=0.0)


DECL = frozenset({CrossTypeDeclaration(T.SEN, T.CTX, "urgency cue rendered as situation")})


def test_undeclared_cross_type_adapter_is_rejected() -> None:
    rng = np.random.default_rng(1)
    with pytest.raises(UndeclaredCrossTypeError, match="undeclared"):
        cross_type_adapt(
            rng.normal(size=(50, 64)),
            np.eye(64),
            source=T.INT,
            target=T.CTX,
            declarations=DECL,
            representation={T.TEM: rng.normal(size=(50, 16))},
        )


def test_declared_cross_type_adapter_enforces_the_leakage_audit() -> None:
    rng = np.random.default_rng(2)
    sen = rng.normal(size=(300, 64))
    w = rng.normal(size=(64, 64)) / 8
    independent = {T.INT: rng.normal(size=(300, 64)), T.TEM: rng.normal(size=(300, 16))}
    released = cross_type_adapt(
        sen, w, source=T.SEN, target=T.CTX, declarations=DECL, representation=independent
    )
    assert released.report.passed
    assert {p.target for p in released.report.pairs} == {"INT", "TEM"}
    assert all(p.probe_r2 is not None for p in released.report.pairs)
    # the adapted block leaks the source block released alongside it: refused
    leaky = {T.SEN: sen, T.TEM: independent[T.TEM]}
    with pytest.raises(CrossTypeAuditFailed, match="release refused") as exc:
        cross_type_adapt(
            sen, w, source=T.SEN, target=T.CTX, declarations=DECL, representation=leaky
        )
    assert not exc.value.report.passed
    with pytest.raises(MebError, match="needs the representation"):
        cross_type_adapt(sen, w, source=T.SEN, target=T.CTX, declarations=DECL, representation={})
    with pytest.raises(MebError, match="overwrite"):
        cross_type_adapt(
            sen, w, source=T.SEN, target=T.CTX, declarations=DECL, representation={T.CTX: sen}
        )


def test_cross_type_declarations_are_validated() -> None:
    with pytest.raises(MebError, match="never author EMO"):
        CrossTypeDeclaration(T.SEN, T.EMO, "no")
    with pytest.raises(MebError, match="same-type"):
        CrossTypeDeclaration(T.SEN, T.SEN, "x")
    with pytest.raises(MebError, match="justification"):
        CrossTypeDeclaration(T.SEN, T.CTX, "  ")
