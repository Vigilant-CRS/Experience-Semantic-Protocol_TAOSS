# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""C2SP signed notes, checkpoints and witness cosignatures (ADR-0023, GAP-019).

Byte-exact vectors:

- c2sp.org/signed-note ("example.com/foo" verifier key and note);
- golang.org/x/mod/sumdb/note tests (PeterNeumann signing key, signed note,
  EnochRoot second signature);
- transparency-dev/formats cosignature v1 timestamp decoding.
"""

import base64
import struct

import pytest

from esp.crypto.primitives import SigningKey
from esp.keys.c2sp import (
    EM_DASH,
    SIG_COSIGNATURE_V1,
    SIG_ED25519,
    Checkpoint,
    NoteError,
    NoteSigner,
    NoteVerifier,
    checkpoint_for_tree_head,
    checkpoint_from_log,
    cosign_checkpoint,
    cosignature_timestamp,
    key_id,
    open_note,
    sign_checkpoint,
    sign_note,
    split_note,
    verify_checkpoint,
)
from esp.keys.transparency import TransparencyLog, leaf_hash, merkle_root

pytestmark = pytest.mark.security

# --- official vectors ---------------------------------------------------------------------------

SPEC_VKEY = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
SPEC_NOTE = (
    "This is an example message.\n\n"
    f"{EM_DASH} example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n"  # noqa: E501 - official vector
).encode()
GO_SKEY = "PRIVATE+KEY+PeterNeumann+c74f20a3+AYEKFALVFGyNhPJEMzD1QIDr+Y7hfZx09iUvxdXHKDFz"
GO_VKEY = "PeterNeumann+c74f20a3+ARpc2QcUPDhMQegwxbzhKqiBfsVkmqq/LDE4izWy10TW"
ENOCH_VKEY = "EnochRoot+af0cfe78+ATtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdop"
GO_TEXT = (
    "If you think cryptography is the answer to your problem,\n"
    "then you don't know what your problem is.\n"
)
PETER_SIG = f"{EM_DASH} PeterNeumann x08go/ZJkuBS9UG/SffcvIAQxVBtiFupLLr8pAcElZInNIuGUgYN1FFYC2pZSNXgKvqfqdngotpRZb6KE6RyyBwJnAM=\n"  # noqa: E501 - official vector
ENOCH_SIG = f"{EM_DASH} EnochRoot rwz+eBzmZa0SO3NbfRGzPCpDckykFXSdeX+MNtCOXm2/5n2tiOHp+vAF1aGrQ5ovTG01oOTGwnWLox33WWd1RvMc+QQ=\n"  # noqa: E501 - official vector
COSIG_B64 = "ZGhGuQAAAABm/qTPeyKXD+R2rzyQsxPiP8mXum7qq/iF0u4vanlqJyocWODBt97w9uL+8qT7S5gxEHWWOworDcFiEBYJXORmnFBOBA=="  # noqa: E501 - official vector


def test_spec_verifier_key_verifies_the_spec_note() -> None:
    v = NoteVerifier.from_vkey(SPEC_VKEY)
    assert v.vkey() == SPEC_VKEY
    text, verified = open_note(SPEC_NOTE, [v])
    assert text == "This is an example message.\n"
    assert verified == [v]


def test_go_signing_vector_is_byte_exact() -> None:
    signer = NoteSigner.from_go_skey(GO_SKEY)
    assert signer.verifier.vkey() == GO_VKEY
    assert sign_note(GO_TEXT, [signer]) == (GO_TEXT + "\n" + PETER_SIG).encode()


def test_go_open_vector_with_two_signers() -> None:
    peter, enoch = NoteVerifier.from_vkey(GO_VKEY), NoteVerifier.from_vkey(ENOCH_VKEY)
    note = (GO_TEXT + "\n" + PETER_SIG + ENOCH_SIG).encode()
    assert open_note(note, [peter])[1] == [peter]  # EnochRoot is unknown and ignored
    assert open_note(note, [peter, enoch])[1] == [peter, enoch]
    with pytest.raises(NoteError, match="no verifiable signatures"):
        open_note(note, [])


def test_cosignature_timestamp_vector() -> None:
    blob = base64.b64decode(COSIG_B64)
    assert len(blob) == 4 + 8 + 64
    assert cosignature_timestamp(blob[4:]) == 1727964367
    wrong_type = base64.b64decode(
        "eQjRQm6eSKzFoiYalgwCPXu2y3ijtg68is9M46JKxuZB+dRfTmeQeDBoXnvxZx2ugnkyV+MUMLXpWs1hPb/W/4xkNQY="
    )
    with pytest.raises(NoteError):
        cosignature_timestamp(wrong_type[4:])


def test_key_id_formula_and_cosignature_type_separation() -> None:
    pk = SigningKey.from_seed(b"\x01" * 32).public_bytes
    assert key_id("w", SIG_ED25519, pk) != key_id("w", SIG_COSIGNATURE_V1, pk)
    with pytest.raises(NoteError):
        key_id("has space", SIG_ED25519, pk)
    with pytest.raises(NoteError):
        key_id("has+plus", SIG_ED25519, pk)


# --- checkpoints and witnesses ------------------------------------------------------------------

ORIGIN = "esp.example/registry-log"
LOG = NoteSigner(ORIGIN, SIG_ED25519, SigningKey.from_seed(b"\x10" * 32))
W = [
    NoteSigner(
        f"witness{i}.example/w", SIG_COSIGNATURE_V1, SigningKey.from_seed(bytes([0x20 + i]) * 32)
    )
    for i in range(3)
]
NOW = 1_800_000_000


def _log(n: int = 7) -> TransparencyLog:
    log = TransparencyLog(SigningKey.from_seed(b"\x10" * 32))
    for i in range(n):
        log.append(f"esp/v1/rotation {i}".encode())
    return log


def _cosigned(k: int = 2) -> bytes:
    note = sign_checkpoint(checkpoint_from_log(_log(), ORIGIN), LOG)
    for w in W[:k]:
        note = cosign_checkpoint(note, w, NOW)
    return note


def test_checkpoint_body_format_and_rfc9162_root() -> None:
    log = _log()
    cp = checkpoint_from_log(log, ORIGIN)
    lines = cp.body().split("\n")
    assert lines[0] == ORIGIN
    assert lines[1] == "7"
    assert base64.b64decode(lines[2]) == merkle_root([leaf_hash(log.entry(i)) for i in range(7)])
    assert lines[3] == ""  # the body ends with exactly one newline
    assert Checkpoint.parse(cp.body()) == cp
    assert checkpoint_for_tree_head(log.tree_head(123), ORIGIN) == cp
    assert Checkpoint(ORIGIN, 0, bytes(32)).body().split("\n")[1] == "0"


@pytest.mark.parametrize(
    "body",
    [
        "o\n07\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",  # leading zero
        "o\n7\n",  # too few lines
        "o\n7\nAAAA\n",  # root not 32 bytes
        "o\n7\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n\next\n",  # empty extension
        "o\n7\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",  # no final newline
    ],
)
def test_malformed_checkpoints_refused(body: str) -> None:
    with pytest.raises(NoteError):
        Checkpoint.parse(body)


def test_quorum_of_independent_witnesses_verifies() -> None:
    ok = verify_checkpoint(_cosigned(2), LOG.verifier, [w.verifier for w in W], quorum=2, now_s=NOW)
    assert ok.checkpoint.tree_size == 7
    assert [n for n, _ in ok.witnesses] == ["witness0.example/w", "witness1.example/w"]
    assert all(ts == NOW for _, ts in ok.witnesses)


def test_quorum_shortfall_refused() -> None:
    with pytest.raises(NoteError, match="need 3"):
        verify_checkpoint(_cosigned(2), LOG.verifier, [w.verifier for w in W], quorum=3)


def test_unknown_witnesses_do_not_count() -> None:
    stranger = NoteSigner(
        "witness9.example/w", SIG_COSIGNATURE_V1, SigningKey.from_seed(b"\x99" * 32)
    )
    note = cosign_checkpoint(_cosigned(1), stranger, NOW)
    with pytest.raises(NoteError, match="need 2"):
        verify_checkpoint(note, LOG.verifier, [w.verifier for w in W], quorum=2)


def test_log_key_never_counts_as_its_own_witness() -> None:
    self_witness = NoteSigner("self.example/w", SIG_COSIGNATURE_V1, LOG.key)
    note = cosign_checkpoint(_cosigned(1), self_witness, NOW)
    with pytest.raises(NoteError, match="need 2"):
        verify_checkpoint(note, LOG.verifier, [W[0].verifier, self_witness.verifier], quorum=2)


def test_same_witness_twice_counts_once() -> None:
    note = cosign_checkpoint(_cosigned(1), W[0], NOW + 5)
    with pytest.raises(NoteError, match="need 2"):
        verify_checkpoint(note, LOG.verifier, [w.verifier for w in W], quorum=2)


def test_tampered_body_or_signature_refused() -> None:
    note = _cosigned(2)
    text, _ = split_note(note)
    forged = note.replace(text.encode(), text.replace("\n7\n", "\n8\n").encode(), 1)
    with pytest.raises(NoteError, match="does not verify"):
        verify_checkpoint(forged, LOG.verifier, [w.verifier for w in W], quorum=2)
    lines = note.decode().split("\n")
    sig_line = lines[-2]  # last cosignature
    name, b64 = sig_line.split(" ")[1:]
    blob = bytearray(base64.b64decode(b64))
    blob[-1] ^= 1
    bad = (
        note.decode()
        .replace(sig_line, f"{EM_DASH} {name} {base64.b64encode(bytes(blob)).decode()}")
        .encode()
    )
    with pytest.raises(NoteError, match="does not verify"):
        verify_checkpoint(bad, LOG.verifier, [w.verifier for w in W], quorum=2)


def test_wrong_key_name_or_key_id_is_just_unknown() -> None:
    note = _cosigned(2)
    renamed = note.replace(b"witness0.example/w", b"witnessX.example/w")
    with pytest.raises(NoteError, match="need 2"):
        verify_checkpoint(renamed, LOG.verifier, [w.verifier for w in W], quorum=2)
    # a vkey whose declared ID does not match its name and key is refused outright
    bad_vkey = W[0].verifier.vkey().replace(f"+{W[0].verifier.key_id:08x}+", "+00000000+")
    with pytest.raises(NoteError, match="does not match"):
        NoteVerifier.from_vkey(bad_vkey)


def test_log_signature_is_mandatory_and_bound_to_the_origin() -> None:
    other_log = NoteSigner(ORIGIN, SIG_ED25519, SigningKey.from_seed(b"\x11" * 32))
    with pytest.raises(NoteError, match="no verifiable"):
        verify_checkpoint(_cosigned(2), other_log.verifier, [w.verifier for w in W], quorum=2)
    wrong_name = NoteSigner("other.example/log", SIG_ED25519, LOG.key)
    with pytest.raises(NoteError, match="origin"):
        sign_checkpoint(checkpoint_from_log(_log(), ORIGIN), wrong_name)


def test_future_cosignatures_refused_when_a_clock_is_given() -> None:
    note = cosign_checkpoint(
        sign_checkpoint(checkpoint_from_log(_log(), ORIGIN), LOG), W[0], NOW + 3600
    )
    with pytest.raises(NoteError, match="future"):
        verify_checkpoint(note, LOG.verifier, [W[0].verifier], quorum=1, now_s=NOW)
    assert verify_checkpoint(note, LOG.verifier, [W[0].verifier], quorum=1).witnesses


def test_cosignature_message_layout() -> None:
    note = _cosigned(1)
    text, sigs = split_note(note)
    ts = struct.unpack(">Q", sigs[1].signature[:8])[0]
    expected = b"cosignature/v1\ntime " + str(ts).encode() + b"\n" + text.encode()
    from esp.crypto.primitives import ed25519_verify  # noqa: PLC0415

    ed25519_verify(W[0].key.public_bytes, expected, sigs[1].signature[8:])


def test_control_characters_and_missing_blank_line_refused() -> None:
    with pytest.raises(NoteError):
        split_note(b"text\x01\n\n" + PETER_SIG.encode())
    with pytest.raises(NoteError):
        split_note(GO_TEXT.encode() + PETER_SIG.encode())
    with pytest.raises(NoteError):
        sign_note("no newline", [LOG])


def test_esp_tree_head_format_still_verifies() -> None:
    """Backwards compatibility: the ESP STH and the C2SP checkpoint describe the same tree."""
    from esp.keys.transparency import cosign  # noqa: PLC0415

    log = _log()
    head = cosign(log.tree_head(5), SigningKey.from_seed(b"\x30" * 32))
    head.verify(witnesses=[SigningKey.from_seed(b"\x30" * 32).public_bytes], quorum=1)
    assert checkpoint_for_tree_head(head, ORIGIN).root == log.root()


def test_vkeys_whose_base64_contains_plus_round_trip() -> None:
    for seed in range(256):
        v = NoteSigner(
            "plus.example/k", SIG_ED25519, SigningKey.from_seed(bytes([seed]) * 32)
        ).verifier
        if "+" in v.vkey().split("+", 2)[2]:
            assert NoteVerifier.from_vkey(v.vkey()) == v
            return
    pytest.fail("no key with '+' in its base64 found")  # pragma: no cover


def test_verifier_refuses_a_checkpoint_whose_origin_is_not_the_log_key_name() -> None:
    """A log key must not vouch for another log's origin line."""
    impostor = NoteSigner("impostor.example/log", SIG_ED25519, SigningKey.from_seed(b"\x12" * 32))
    note = sign_note(checkpoint_from_log(_log(), ORIGIN).body(), [impostor])
    with pytest.raises(NoteError, match="origin"):
        verify_checkpoint(note, impostor.verifier, [], quorum=0)
