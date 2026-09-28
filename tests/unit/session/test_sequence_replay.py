# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-017 (nonce/replay state) and WP-065 (adaptive window formulas)."""

import itertools
import uuid
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from esp.codec.header import Header
from esp.crypto.envelope import seal_packet
from esp.crypto.keys import DirectionKeys, deterministic_nonce
from esp.crypto.primitives import SigningKey
from esp.session.replay import NonceReplayCache, ReplayError, ReplayWindow, replay_windows
from esp.session.sequence import (
    MAX_SEQUENCE,
    NonceReuseError,
    RandomNonceSource,
    SenderSequencer,
    SequenceStore,
    SessionTerminatedError,
    session_fingerprint,
)

KEYS = DirectionKeys.from_split_key(bytes(range(32)))
SIGNER = SigningKey.from_seed(bytes(32))
TIMELINE = uuid.UUID("5f0c6a8e-3b7d-4c4e-9a53-2f6a1d9e8b10")
FP = session_fingerprint(KEYS.aead)


def new_sequencer(tmp_path: Path) -> SenderSequencer:
    store = SequenceStore(tmp_path / "seq.json", FP)
    store.initialize()
    return SenderSequencer(store)


def seal(seq: int, plaintext: bytes) -> bytes:
    header = Header(
        profile=1,
        sf_level=0,
        types_bitmap=1,
        consent_flags=0,
        privacy_flags=0,
        capabilities=0,
        timestamp_ns=0,
        timeline_id=TIMELINE,
        segment_seq=seq,
        dt_ms=0,
        phase=0.0,
        sender_id=SIGNER.public_bytes,
        payload_len=0,
        nonce=deterministic_nonce(KEYS, TIMELINE, seq),
    )
    return seal_packet(header, plaintext, KEYS, SIGNER)


# --- sender -----------------------------------------------------------------


def test_sequences_are_unique_and_persisted_before_use(tmp_path: Path) -> None:
    s = new_sequencer(tmp_path)
    assert [s.reserve(b"a"), s.reserve(b"b"), s.reserve(b"c")] == [0, 1, 2]
    assert SequenceStore(tmp_path / "seq.json", FP).load() == 3


def test_same_sequence_with_modified_plaintext_forbidden(tmp_path: Path) -> None:
    s = new_sequencer(tmp_path)
    seq = s.reserve(b"original")
    with pytest.raises(NonceReuseError, match="different plaintext"):
        s.record_sent(seq, b"modified", seal(seq, b"modified"))
    s.record_sent(seq, b"original", seal(seq, b"original"))
    with pytest.raises(NonceReuseError, match="already sent"):
        s.record_sent(seq, b"original", seal(seq, b"original"))


def test_retransmission_uses_identical_ciphertext(tmp_path: Path) -> None:
    s = new_sequencer(tmp_path)
    seq = s.reserve(b"state")
    packet = seal(seq, b"state")
    s.record_sent(seq, b"state", packet)
    assert s.retransmit(seq) == packet
    with pytest.raises(NonceReuseError, match="no packet"):
        s.retransmit(seq + 1)


def test_crash_after_reserve_never_reuses_sequence(tmp_path: Path) -> None:
    s = new_sequencer(tmp_path)
    reserved = s.reserve(b"lost in crash")
    restarted = SenderSequencer(SequenceStore(tmp_path / "seq.json", FP))
    assert restarted.reserve(b"after restart") == reserved + 1


@pytest.mark.parametrize("damage", ["delete", "corrupt", "foreign", "garbage_value"])
def test_lost_sequence_state_terminates_session(tmp_path: Path, damage: str) -> None:
    new_sequencer(tmp_path).reserve(b"x")
    path = tmp_path / "seq.json"
    if damage == "delete":
        path.unlink()
    elif damage == "corrupt":
        path.write_text("{not json")
    elif damage == "foreign":
        path.write_text('{"session": "other", "next": 5}')
    else:
        path.write_text(f'{{"session": "{FP}", "next": -3}}')
    with pytest.raises(SessionTerminatedError):
        SenderSequencer(SequenceStore(path, FP))


def test_restoring_old_state_is_refused_as_new_session(tmp_path: Path) -> None:
    new_sequencer(tmp_path)
    with pytest.raises(SessionTerminatedError, match="already exists"):
        SequenceStore(tmp_path / "seq.json", FP).initialize()


def test_sequence_exhaustion(tmp_path: Path) -> None:
    store = SequenceStore(tmp_path / "seq.json", FP)
    store.initialize()
    store.store(MAX_SEQUENCE)
    s = SenderSequencer(store)
    assert s.reserve(b"last") == 2**32 - 2
    with pytest.raises(SessionTerminatedError, match="exhausted"):
        s.reserve(b"one too many")


def test_random_nonces_redraw_duplicates_before_encryption() -> None:
    fixed = iter([b"\x01" * 12, b"\x01" * 12, b"\x02" * 12])
    source = RandomNonceSource(_random=lambda n: next(fixed))
    assert source.next_nonce() == b"\x01" * 12
    assert source.next_nonce() == b"\x02" * 12
    with pytest.raises(SessionTerminatedError, match="budget"):
        RandomNonceSource(max_nonces=0).next_nonce()


# --- receiver -----------------------------------------------------------------


def test_duplicate_nonce_rejected() -> None:
    cache = NonceReplayCache()
    cache.accept(b"n" * 12)
    with pytest.raises(ReplayError, match="replayed nonce"):
        cache.accept(b"n" * 12)


def test_replay_window_edges() -> None:
    w = ReplayWindow(w_back=1024, w_fwd=128)
    with pytest.raises(ReplayError, match="too far ahead"):
        w.check(128)  # first packet: max_seen = -1, so 127 is the limit
    seq = 127
    w.accept(seq)
    while seq < 3000:  # advance in steps that sit exactly on the forward edge
        seq += 128
        w.accept(seq)
    assert w.max_seen == seq
    with pytest.raises(ReplayError, match="too far ahead"):
        w.check(seq + 129)
    w.accept(seq - 1023)  # exactly one inside the backward edge (max - W_back + 1)
    with pytest.raises(ReplayError, match="too old"):
        w.check(seq - 1024)
    with pytest.raises(ReplayError, match="replayed"):
        w.accept(seq)
    w.accept(seq - 5)  # late but inside the window, never seen
    with pytest.raises(ReplayError, match="replayed"):
        w.accept(seq - 5)


def test_no_wraparound() -> None:
    w = ReplayWindow(w_back=1024, w_fwd=8192)
    for s in range(0, 8192 * 4, 8000):
        w.accept(s)
    with pytest.raises(ReplayError, match="too old"):
        w.check(0)
    with pytest.raises(ReplayError, match="out of range"):
        w.check(2**32)


@given(st.lists(st.integers(0, 3000), max_size=400))
def test_window_never_accepts_a_sequence_twice(seqs: list[int]) -> None:
    w = ReplayWindow(w_back=1024, w_fwd=128)
    accepted: set[int] = set()
    for s in seqs:
        try:
            w.accept(s)
        except ReplayError:
            continue
        assert s not in accepted
        accepted.add(s)
    assert len(w._seen) <= w.w_back + w.w_fwd + 1  # memory stays bounded


# --- WP-065 formulas ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("rtt", "jitter", "rate", "expected"),
    [
        (0.1, 0.02, 50.0, (1024, 128)),  # floors
        (0.5, 3.0, 50.0, (1024, 150)),
        (20.0, 0.0, 1000.0, (8192, 128)),  # cap
        (15.0, 200.0, 50.0, (1500, 8192)),
    ],
)
def test_v13_window_formulas(
    rtt: float, jitter: float, rate: float, expected: tuple[int, int]
) -> None:
    assert replay_windows(rtt, jitter, rate) == expected


def test_forward_floor_is_2_56_seconds_at_50_hz() -> None:
    _, w_fwd = replay_windows(0.0, 0.0, 50.0)
    assert w_fwd / 50.0 == 2.56


def test_formula_rejects_bad_inputs() -> None:
    for args in itertools.product((-1.0, float("nan")), (0.0,), (50.0,)):
        with pytest.raises(ValueError, match="finite and non-negative"):
            replay_windows(*args)


def test_link_estimator_feeds_the_window_formula() -> None:
    from esp.session.replay import LinkEstimator  # noqa: PLC0415

    est = LinkEstimator(capacity=200)
    assert est.windows(50.0) == (1024, 128)  # no samples yet: floors
    for i in range(200):
        est.add_rtt(0.05 if i % 50 else 12.0)  # 2 % of samples: 12 s cellular stalls
    w_back, w_fwd = est.windows(50.0)
    assert w_back == 1200  # ceil(2 * 12 s * 50 Hz)
    assert w_fwd == 598  # ceil(11.95 s * 50 Hz)
    for _ in range(200):
        est.add_rtt(0.05)  # old samples age out of the bounded buffer
    assert est.windows(50.0) == (1024, 128)
    with pytest.raises(ValueError, match="finite"):
        est.add_rtt(float("nan"))
