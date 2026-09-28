# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-055 end to end: runtime DP through sender and receiver endpoints."""

import math
import uuid
from pathlib import Path

import numpy as np
import pytest

from esp.codec.header import DpLevel
from esp.core.provenance import Provenance, SourceKind
from esp.core.taoss_types import TaossType
from esp.crypto.noise_ik import StaticKeyPair
from esp.frame.model import DisclosurePolicy, ExperienceFrame, TypeBlock
from esp.privacy.dp import REFERENCE_PROFILES, DpConfig, PrivacyBudgetError, PrivacyLedger
from esp.semantics.bindings import BindingPolicy, RelationClass, SemanticBinding, TypedEndpoint
from esp.session.endpoint import ReceiverEndpoint, SenderEndpoint
from tests.integration.test_endpoint import (
    MASTER,
    NOW,
    RECEIVER_ID,
    WIRE,
    descriptor,
    establish,
    receiver_capability,
    sender_capability,
)
from tests.unit.frame.test_frame_wire import full_anchor_frame

pytestmark = pytest.mark.integration
T = TaossType
SIGMA = REFERENCE_PROFILES[DpLevel.L1_BALANCED_REF][1]
KNO_CTX = DisclosurePolicy(allowed_types=(T.KNO, T.CTX))


def latent_only() -> ExperienceFrame:
    f = full_anchor_frame()
    return ExperienceFrame.model_validate(
        f.model_dump()
        | {"types": tuple(TypeBlock(type=b.type, latent=b.latent) for b in f.types), "bindings": ()}
    )


def dp_pair(tmp_path: Path, *, ceiling: float = 8.0, dp: bool = True):  # type: ignore[no-untyped-def]
    cap = sender_capability(dp_epsilon_ceiling=ceiling)
    r_static = StaticKeyPair.generate()
    ledger = PrivacyLedger(tmp_path / "ledger.json", cap.capability_id, ceiling=ceiling)
    config = (
        DpConfig(DpLevel.L1_BALANCED_REF, clip_norm=1.0, sigma=SIGMA, ledger=ledger) if dp else None
    )
    sender = SenderEndpoint(
        master=MASTER,
        static=StaticKeyPair.generate(),
        responder_static=r_static.public_bytes,
        receiver_identity=RECEIVER_ID.public_bytes,
        descriptor=descriptor(dp_level=1, sf_level=1),
        capability=cap,
        state_dir=tmp_path,
        wire=WIRE,
        dp=config,
    )
    receiver = ReceiverEndpoint(
        identity=RECEIVER_ID,
        static=r_static,
        descriptor=descriptor(dp_level=1, sf_level=1),
        capability=receiver_capability,
        trusted_issuers=frozenset({MASTER.public_bytes}),
        wire=WIRE,
    )
    establish(sender, receiver)
    return sender, receiver, ledger


def test_dp_release_is_noised_accounted_and_audited(tmp_path: Path) -> None:
    s, r, ledger = dp_pair(tmp_path)
    frame = latent_only()
    packet = s.send_frame(frame, KNO_CTX, now_ns=NOW)
    assert packet[13] & 0x0F == 1  # DP_LEVEL = L1_BALANCED_REF in the header
    res = r.receive(packet, now_ns=NOW)
    assert res.accepted, res.violations
    assert res.frame is not None
    sent = np.asarray(frame.block(T.KNO).latent)  # type: ignore[union-attr]
    got = np.asarray(res.frame.block(T.KNO).latent)  # type: ignore[union-attr]
    assert not np.allclose(sent, got)  # noise was applied before transmission
    assert math.isclose(float(np.std(got)), SIGMA, rel_tol=0.15)
    assert ledger.k == 1
    assert r.accept_state.epsilon_spent[s._capability.capability_id.bytes] > 0


def test_retransmission_does_not_consume_budget(tmp_path: Path) -> None:
    s, _, ledger = dp_pair(tmp_path)
    packet = s.send_frame(latent_only(), KNO_CTX, now_ns=NOW)
    assert s.retransmit(0) == packet
    assert ledger.k == 1


def test_non_latent_content_refused_under_dp(tmp_path: Path) -> None:
    s, _, ledger = dp_pair(tmp_path)
    base = latent_only()
    binding = SemanticBinding(
        binding_id=uuid.uuid4(),
        relation=RelationClass.CONTEXTUALIZED_BY,
        source=TypedEndpoint(type=T.KNO, ref="k"),
        target=TypedEndpoint(type=T.CTX, ref="c"),
        confidence=0.9,
        provenance=Provenance(source_kind=SourceKind.SELF_REPORT),
    )
    frame = ExperienceFrame.model_validate(base.model_dump() | {"bindings": (binding,)})
    policy = DisclosurePolicy(
        allowed_types=(T.KNO, T.CTX),
        bindings=BindingPolicy(allowed_binding_ids=(binding.binding_id,)),
    )
    with pytest.raises(PrivacyBudgetError, match="only privatized latents"):
        s.send_frame(frame, policy, now_ns=NOW)
    assert ledger.k == 0


def test_sender_stops_at_the_ceiling(tmp_path: Path) -> None:
    s, r, ledger = dp_pair(tmp_path, ceiling=2.0)
    sent = 0
    refused = None
    while refused is None and sent < 1000:
        try:
            packet = s.send_frame(latent_only(), KNO_CTX, now_ns=NOW + sent)
        except PrivacyBudgetError as exc:
            refused = exc
            break
        assert r.receive(packet, now_ns=NOW + sent).accepted
        sent += 1
    assert refused is not None
    assert "exceed the DP ceiling" in str(refused)
    assert sent == ledger.k > 0
    assert ledger.epsilon_spent <= 2.0


def test_receiver_rejects_missing_dp_params(tmp_path: Path) -> None:
    s, r, _ = dp_pair(tmp_path, dp=False)  # header says L1_BALANCED_REF, no TLV_DP_PARAMS
    res = r.receive(s.send_frame(latent_only(), KNO_CTX, now_ns=NOW), now_ns=NOW)
    assert not res.accepted
    assert "TLV_DP_PARAMS missing" in res.violations[0]
    assert r.decoder_invocations == 0


def test_dp_config_must_match_descriptor(tmp_path: Path) -> None:
    cap = sender_capability()
    ledger = PrivacyLedger(tmp_path / "l.json", cap.capability_id, ceiling=8.0)
    with pytest.raises(PrivacyBudgetError, match="must match the session descriptor"):
        SenderEndpoint(
            master=MASTER,
            static=StaticKeyPair.generate(),
            responder_static=bytes(32),
            receiver_identity=RECEIVER_ID.public_bytes,
            descriptor=descriptor(),
            capability=cap,
            state_dir=tmp_path,
            wire=WIRE,
            dp=DpConfig(DpLevel.L1_BALANCED_REF, clip_norm=1.0, sigma=SIGMA, ledger=ledger),
        )
    with pytest.raises(ValueError, match="below the L1_PRIVATE_REF reference"):
        DpConfig(DpLevel.L1_PRIVATE_REF, clip_norm=1.0, sigma=SIGMA, ledger=ledger)
