# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""WP-038: study harness — ethics guard, randomization, consent, anonymized export."""

import dataclasses
from collections import Counter

import pytest

from esp.study.harness import (
    ConsentForm,
    Enrollment,
    EthicsApproval,
    EthicsRefused,
    Item,
    Mode,
    Scale,
    StudyError,
    StudyProtocol,
    allocation_schedule,
    export_responses,
    require_approval,
    schedule_commitment,
)

pytestmark = pytest.mark.security
NOW = 10**18
SEED = b"\x11" * 32
KEY = b"\x22" * 32
PROTOCOL = StudyProtocol(
    study_id="esp-interp-pilot",
    version="0.1.0",
    arms=("text_only", "taoss_rendered", "taoss_plus_text"),
    items=(
        Item("i1", "synthetic:frame:1", Scale.CORRECT),
        Item("i2", "synthetic:frame:2", Scale.LIKERT5),
    ),
    block_size=6,
    target_n=30,
    preregistration_digest="ab" * 32,
)
FORM = ConsentForm(
    version="1",
    text="You take part in a study about ...",
    required=("participate", "data_use"),
    optional=("share_comments",),
)


def approval(**kw: object) -> EthicsApproval:
    fields: dict[str, object] = {
        "board": "Example ethics board",
        "reference": "EK-2026-001",
        "protocol_digest": PROTOCOL.digest(),
        "consent_form_digest": FORM.digest(),
        "valid_from_ns": NOW - 1,
        "valid_until_ns": NOW + 10**15,
    }
    return EthicsApproval(**(fields | kw))  # type: ignore[arg-type]


def enrollment(mode: Mode = Mode.SYNTHETIC_PILOT, appr: EthicsApproval | None = None) -> Enrollment:
    return Enrollment(PROTOCOL, FORM, mode, KEY, allocation_schedule(PROTOCOL, SEED), appr)


# --- ethics guard ---------------------------------------------------------------------------------


def test_live_mode_without_approval_refuses_enrollment() -> None:
    e = enrollment(Mode.LIVE)
    with pytest.raises(EthicsRefused, match="no ethics approval"):
        e.enroll("code-1", {"participate", "data_use"}, age=30, now_ns=NOW)
    assert not e.consents


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ({"protocol_digest": "00" * 32}, "different protocol"),
        ({"consent_form_digest": "00" * 32}, "different consent form"),
        ({"valid_until_ns": NOW - 1}, "not valid"),
        ({"valid_from_ns": NOW + 1}, "not valid"),
    ],
)
def test_approval_must_match_protocol_form_and_time(change: dict[str, object], reason: str) -> None:
    with pytest.raises(EthicsRefused, match=reason):
        require_approval(PROTOCOL, FORM, Mode.LIVE, approval(**change), now_ns=NOW)


def test_protocol_change_invalidates_the_approval() -> None:
    changed = dataclasses.replace(PROTOCOL, target_n=31)
    with pytest.raises(EthicsRefused, match="different protocol"):
        require_approval(changed, FORM, Mode.LIVE, approval(), now_ns=NOW)


def test_live_with_valid_approval_is_evidence_pilot_is_not() -> None:
    live = enrollment(Mode.LIVE, approval())
    live.enroll("code-1", {"participate", "data_use"}, age=30, now_ns=NOW)
    assert export_responses(live)["evidence"] is True
    pilot = enrollment()
    pilot.enroll("code-1", {"participate", "data_use"}, age=30, now_ns=NOW)
    assert export_responses(pilot)["evidence"] is False


# --- randomization --------------------------------------------------------------------------------


def test_permuted_blocks_are_balanced_and_deterministic() -> None:
    s = allocation_schedule(PROTOCOL, SEED)
    assert len(s) == 30
    assert s == allocation_schedule(PROTOCOL, SEED)
    for b in range(0, 30, 6):
        assert Counter(s[b : b + 6]) == dict.fromkeys(PROTOCOL.arms, 2)
    assert s != allocation_schedule(PROTOCOL, b"\x12" * 32)  # the seed matters
    blocks = {s[b : b + 6] for b in range(0, 30, 6)}
    assert len(blocks) > 1  # not the same order in every block


def test_commitment_binds_schedule_and_seed() -> None:
    s = allocation_schedule(PROTOCOL, SEED)
    c = schedule_commitment(s, SEED)
    assert c == schedule_commitment(s, SEED)
    assert c != schedule_commitment(s[::-1], SEED)
    assert c != schedule_commitment(s, b"\x12" * 32)


def test_short_seed_and_bad_protocols_rejected() -> None:
    with pytest.raises(StudyError):
        allocation_schedule(PROTOCOL, b"short")
    with pytest.raises(StudyError, match="multiple"):
        dataclasses.replace(PROTOCOL, block_size=4)
    with pytest.raises(StudyError, match="two distinct arms"):
        dataclasses.replace(PROTOCOL, arms=("a",), block_size=1)
    with pytest.raises(StudyError, match="adult"):
        dataclasses.replace(PROTOCOL, min_age=16)


# --- consent and enrollment -----------------------------------------------------------------------


def test_required_consent_items_are_mandatory_optional_are_not() -> None:
    e = enrollment()
    with pytest.raises(StudyError, match="required consent"):
        e.enroll("code-1", {"participate"}, age=30, now_ns=NOW)
    with pytest.raises(StudyError, match="unknown consent"):
        e.enroll("code-1", {"participate", "data_use", "sell_data"}, age=30, now_ns=NOW)
    p = e.enroll("code-1", {"participate", "data_use"}, age=30, now_ns=NOW)
    assert e.consents[p].form_digest == FORM.digest()


def test_minors_and_double_enrollment_refused() -> None:
    e = enrollment()
    with pytest.raises(StudyError, match="minimum age"):
        e.enroll("code-1", {"participate", "data_use"}, age=17, now_ns=NOW)
    e.enroll("code-1", {"participate", "data_use"}, age=18, now_ns=NOW)
    with pytest.raises(StudyError, match="already enrolled"):
        e.enroll("code-1", {"participate", "data_use"}, age=18, now_ns=NOW)


def test_allocation_follows_the_concealed_schedule_and_stops_at_target() -> None:
    e = enrollment()
    ps = [e.enroll(f"c{i}", {"participate", "data_use"}, age=30, now_ns=NOW) for i in range(30)]
    assert [e.arms[p] for p in ps] == list(e.schedule)
    with pytest.raises(StudyError, match="target sample size"):
        e.enroll("c30", {"participate", "data_use"}, age=30, now_ns=NOW)


def test_pseudonyms_hide_enrollment_codes() -> None:
    e = enrollment()
    p = e.enroll("alice-code-7", {"participate", "data_use"}, age=30, now_ns=NOW)
    assert "alice" not in p
    assert p == e.pseudonym("alice-code-7")
    other_key = Enrollment(PROTOCOL, FORM, Mode.SYNTHETIC_PILOT, b"\x33" * 32, e.schedule)
    assert other_key.pseudonym("alice-code-7") != p


@pytest.mark.parametrize("text", ["write me at jane.doe@example.org", "call +49 170 1234567"])
def test_direct_identifiers_rejected_in_comments_and_demographics(text: str) -> None:
    e = enrollment()
    p = e.enroll("c1", {"participate", "data_use", "share_comments"}, age=30, now_ns=NOW)
    with pytest.raises(StudyError, match="identifier"):
        e.respond(p, "i2", 3, text)
    with pytest.raises(StudyError, match="identifier"):
        e.enroll("c2", {"participate", "data_use"}, age=30, demographics={"x": text}, now_ns=NOW)


def test_responses_validated_against_scale_and_items() -> None:
    e = enrollment()
    p = e.enroll("c1", {"participate", "data_use"}, age=30, now_ns=NOW)
    e.respond(p, "i1", 1)
    with pytest.raises(StudyError, match="scale"):
        e.respond(p, "i1", 2)
    with pytest.raises(StudyError, match="unknown item"):
        e.respond(p, "i9", 1)
    with pytest.raises(StudyError, match="no active consent"):
        e.respond("nobody", "i1", 1)


# --- withdrawal and export ------------------------------------------------------------------------


def _populated() -> tuple[Enrollment, list[str]]:
    e = enrollment()
    ps = []
    for i in range(12):
        granted = {"participate", "data_use"} | ({"share_comments"} if i % 2 else set())
        p = e.enroll(f"c{i}", granted, age=30 if i < 10 else 70, now_ns=NOW)
        e.respond(p, "i1", i % 2)
        e.respond(p, "i2", 3, "clear enough")
        ps.append(p)
    return e, ps


def test_withdrawal_removes_participant_from_export() -> None:
    e, ps = _populated()
    e.withdraw(ps[0], now_ns=NOW + 1)
    out = export_responses(e)
    assert out["withdrawn"] == 1
    assert len(out["participants"]) == 11  # type: ignore[arg-type]
    assert len(out["responses"]) == 22  # type: ignore[arg-type]
    with pytest.raises(StudyError, match="no active consent"):
        e.respond(ps[0], "i1", 1)


def test_export_is_k_anonymous_and_pseudonyms_do_not_leak() -> None:
    e, ps = _populated()
    out = export_responses(e, k=5)
    parts = out["participants"]
    assert isinstance(parts, list)
    bands = Counter(p["demographics"]["age_band"] for p in parts)
    assert bands == {"30-39": 10, "*": 2}  # the two 65+ participants are suppressed
    assert out["suppressed_demographics"] == 2
    text = repr(out)
    assert not any(p in text for p in ps)  # internal pseudonyms never exported
    assert not any(f"c{i}" in {x["id"] for x in parts} for i in range(12))


def test_comments_exported_only_with_optional_consent() -> None:
    e, _ = _populated()
    rows = export_responses(e)["responses"]
    assert isinstance(rows, list)
    with_comment = [r for r in rows if "comment" in r]
    assert len(with_comment) == 6  # the odd participants granted share_comments
