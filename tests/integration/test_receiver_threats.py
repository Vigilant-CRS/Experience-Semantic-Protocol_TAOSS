# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-060: receiver-side threats T13-T19 (V13 receiver threats).

T13 malicious vectors, T15 decoder drift, T16 decoder budget, T18 mandatory
vendor provenance, T19 anchor-only minimization. T14 (bidirectional consent,
local decoding) is the default-deny receiver of WP-051
(``test_endpoint.py``); T17 is not technically mitigable (V13).
"""

import json
import struct
from pathlib import Path

import numpy as np
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from esp.codec.frame_wire import frame_to_payload
from esp.codec.header import ConsentFlags
from esp.codec.tlv import encode_tlv, parse_payload
from esp.core.taoss_types import TaossType, types_to_bitmap
from esp.crypto.primitives import SigningKey
from esp.crypto.provenance import ProvenanceRole, VendorProvenance, payload_hash
from esp.decoder.budget import DecodeBudget
from esp.decoder.core import DecoderPolicyError
from esp.decoder.drift import archive, check_drift
from esp.decoder.reference import LinearDecoder
from esp.frame.minimize import anchor_only
from esp.frame.model import DisclosurePolicy
from esp.session.descriptor import DecoderPolicy as P
from esp.session.endpoint import ReceiverHardening, SenderEndpoint
from tests.integration.test_endpoint import NOW, WIRE, establish, pair
from tests.unit.frame.test_frame_wire import full_anchor_frame

pytestmark = pytest.mark.integration
T = TaossType
KNO = DisclosurePolicy(allowed_types=(T.KNO,))
SF6 = DisclosurePolicy(allowed_types=tuple(T))


def adversarial(
    s: SenderEndpoint, types: set[TaossType], payload: bytes, *, emo_masked: bool = False
) -> bytes:
    """An authenticated but malicious sender: bypasses all sender-side checks."""
    flags = s._rights_flags() | (int(ConsentFlags.EMO_MASKED) if emo_masked else 0)
    return s._seal(types_to_bitmap(types), flags, payload, NOW)


def raw_latent(t: TaossType, values: np.ndarray) -> bytes:
    """F32 typed latent built byte by byte (so NaN/Inf/huge values survive encoding)."""
    body = struct.pack(">BBHf", t.value, 0, values.size, 1.0) + values.astype(">f4").tobytes()
    return encode_tlv(t.tlv_code, body)


# --- T13: malicious vector injection -----------------------------------------------------------

special = st.sampled_from([np.nan, np.inf, -np.inf, 3.0e38, -3.0e38, 1e20])


@settings(
    max_examples=60, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(
    base=st.lists(st.floats(-5, 5), min_size=240, max_size=240),
    poison=st.lists(st.tuples(st.integers(0, 239), special), min_size=1, max_size=5),
)
def test_t13_poisoned_vectors_are_rejected_before_decoding(
    tmp_path: Path, base: list[float], poison: list[tuple[int, float]]
) -> None:
    s, r = pair(tmp_path)
    establish(s, r)
    values = np.array(base, dtype=np.float64)
    for i, v in poison:
        values[i] = v
    with np.errstate(over="ignore", invalid="ignore"):
        result = r.receive(adversarial(s, {T.KNO}, raw_latent(T.KNO, values)), now_ns=NOW)
    assert not result.accepted
    reason = " ".join(result.violations)
    assert "NaN or infinity" in reason or "norm exceeds cap" in reason, reason
    assert result.frame is None
    assert r.decoder_invocations == 0


def test_raw_latent_helper_matches_the_codec(tmp_path: Path) -> None:
    s, r = pair(tmp_path)
    establish(s, r)
    ok = r.receive(adversarial(s, {T.KNO}, raw_latent(T.KNO, np.full(240, 0.01))), now_ns=NOW)
    assert ok.accepted, ok.violations  # the hand-built encoding is valid when values are sane


@pytest.mark.parametrize("valence", [1e300, -7.0, 1.5])
def test_t13_extreme_declared_valence_is_screened_even_without_bounds(
    tmp_path: Path, valence: float
) -> None:
    s, r = pair(tmp_path, sf=6)  # receiver_types=0x3F: valence bounds (-1, 1) = unconstrained
    establish(s, r)
    encoded = frame_to_payload(full_anchor_frame().disclose(SF6), WIRE)
    parsed = parse_payload(encoded.payload, extra_codes=frozenset(range(0x80, 0xA0)))
    out = b""
    for tlv in parsed.known:
        if tlv.code == 0x92:
            body = json.loads(tlv.value[1:])
            body["valence"] = valence
            out += encode_tlv(0x92, b"\x01" + json.dumps(body).encode())
        else:
            out += tlv.encode()
    result = r.receive(adversarial(s, set(T), out), now_ns=NOW)
    assert not result.accepted
    assert any("valence outside" in v for v in result.violations)
    assert r.decoder_invocations == 0  # screened in quarantine, not by the decoder


# --- T16: decoder capacity exhaustion ----------------------------------------------------------


def test_t16_budget_throttles_instead_of_crashing_and_retransmission_recovers(
    tmp_path: Path,
) -> None:
    s, r = pair(tmp_path)
    establish(s, r)
    budget = DecodeBudget(rate_per_s=2.0, burst=3)
    r._hardening = ReceiverHardening(decode_budget=budget)
    packets = [s.send_frame(full_anchor_frame(), KNO, now_ns=NOW) for _ in range(10)]
    results = [r.receive(p, now_ns=NOW) for p in packets]
    assert sum(x.accepted for x in results) == 3
    throttled = [i for i, x in enumerate(results) if not x.accepted]
    assert all("T16" in results[i].violations[0] for i in throttled)
    assert r.decoder_invocations == 3
    assert budget.throttled == 7
    # after refill, an identical retransmission of a throttled packet is accepted
    later = r.receive(s.retransmit(throttled[0]), now_ns=NOW + 2 * 10**9)
    assert later.accepted, later.violations


def test_t16_session_cost_ceiling() -> None:
    b = DecodeBudget(rate_per_s=1000.0, burst=1000, session_cost_limit=5.0)
    assert [b.try_spend(i, 2.0) for i in range(4)] == [True, True, False, False]
    with pytest.raises(ValueError, match="positive"):
        DecodeBudget(rate_per_s=0.0, burst=1)


# --- T18: forced experience embedding -----------------------------------------------------------


def provenance_payload(s: SenderEndpoint, vendor: SigningKey) -> bytes:
    encoded = frame_to_payload(full_anchor_frame().disclose(KNO), WIRE)
    parsed = parse_payload(encoded.payload, extra_codes=frozenset(range(0x80, 0xA0)))
    tlv = VendorProvenance(
        ProvenanceRole.ENCODER_VENDOR, "vendor.example", "enc-1.0", vendor.public_bytes, NOW
    ).sign(vendor, payload_hash(parsed))
    del s
    return encoded.payload + tlv.encode()


def test_t18_receiver_requires_trusted_vendor_provenance(tmp_path: Path) -> None:
    trusted, rogue = SigningKey.from_seed(b"\x31" * 32), SigningKey.from_seed(b"\x32" * 32)
    s, r = pair(tmp_path)
    establish(s, r)
    r._hardening = ReceiverHardening(trusted_vendors=frozenset({trusted.public_bytes}))
    missing = r.receive(s.send_frame(full_anchor_frame(), KNO, now_ns=NOW), now_ns=NOW)
    assert missing.violations == ("T18:vendor provenance required but missing",)
    bad = r.receive(
        adversarial(s, {T.KNO}, provenance_payload(s, rogue), emo_masked=True), now_ns=NOW
    )
    assert not bad.accepted
    assert "untrusted vendor" in bad.violations[0]
    good = r.receive(
        adversarial(s, {T.KNO}, provenance_payload(s, trusted), emo_masked=True), now_ns=NOW
    )
    assert good.accepted, good.violations
    assert r.decoder_invocations == 1


# --- T19: latent inversion / over-recovery -------------------------------------------------------


def test_t19_anchor_only_release_and_receiver() -> None:
    frame = anchor_only(full_anchor_frame())
    assert frame.present_types == (T.EMO,)
    emo = frame.block(T.EMO)
    assert emo is not None
    assert emo.latent is None
    assert emo.affect == ()
    assert set(frame.masked_types) == {T.KNO, T.INT, T.CTX, T.SEN, T.TEM}
    assert frame.bindings == ()  # bindings to withheld types cannot survive


def test_t19_anchor_only_receiver_refuses_raw_latents(tmp_path: Path) -> None:
    s, r = pair(tmp_path)
    establish(s, r)
    r._hardening = ReceiverHardening(anchor_only=True)
    result = r.receive(s.send_frame(full_anchor_frame(), KNO, now_ns=NOW), now_ns=NOW)
    assert result.violations == ("T19:anchor-only receiver refuses raw typed latents",)
    assert r.decoder_invocations == 0


# --- T15: decoder version drift -------------------------------------------------------------------


def test_t15_drift_is_detected_against_archived_references() -> None:
    policies = {T.KNO: P.STRICT_REFUSE, T.EMO: P.GRACEFUL}
    refs = [full_anchor_frame(), full_anchor_frame().disclose(KNO)]
    pinned = archive(LinearDecoder("dec", policies, seed=1), refs)
    assert check_drift(LinearDecoder("dec", policies, seed=1), pinned).ok
    drifted = check_drift(LinearDecoder("dec", policies, seed=1, noise=0.1), pinned, epsilon=1e-9)
    assert drifted.drifted == (0, 1)
    assert drifted.worst > 0
    renamed = LinearDecoder("other", policies, seed=1)
    with pytest.raises(DecoderPolicyError, match="re-baseline"):
        check_drift(renamed, pinned)
