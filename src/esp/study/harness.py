# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Human interpretability study harness (WP-038; V13 ExperienceBench "human interpretability").

The software is prepared. A **real** study runs only with a recorded ethics approval:

- :class:`StudyProtocol`: arms, items, outcome scales, randomization and the
  preregistration digest; its own digest is what the ethics board approves;
- :class:`EthicsApproval` + :func:`require_approval`: ``LIVE`` mode refuses to
  enroll anyone unless an approval pins exactly this protocol digest and is
  valid now. ``SYNTHETIC_PILOT`` runs without approval, and its exports are
  labelled ``evidence=False``;
- :func:`allocation_schedule`: permuted-block randomization derived from a
  secret seed, with a published commitment (allocation concealment);
- :class:`ConsentForm` / :class:`ConsentRecord`: versioned form (text digest,
  required and optional items), withdrawal at any time; withdrawn participants
  vanish from every later export;
- :class:`Enrollment`: pseudonyms are keyed hashes of enrollment codes. No
  names, emails or phone numbers are accepted anywhere in responses;
- :func:`export_responses`: anonymized export with coarsened demographics and a
  k-anonymity check (k = 5 by default); cells below k are suppressed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Final

K_ANONYMITY_DEFAULT: Final = 5
_IDENTIFIER_PATTERNS: Final = (
    re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"),  # email
    re.compile(r"\+?\d[\d\s/().-]{7,}\d"),  # phone-like digit runs
)


class StudyError(ValueError):
    pass


class EthicsRefused(StudyError):  # noqa: N818 - a guard outcome
    pass


class Mode(StrEnum):
    SYNTHETIC_PILOT = "synthetic_pilot"
    LIVE = "live"


class Scale(StrEnum):
    LIKERT5 = "likert5"
    LIKERT7 = "likert7"
    CORRECT = "correct"
    """Binary: did the participant identify the transmitted content?"""


_SCALE_RANGE: Final = {Scale.LIKERT5: (1, 5), Scale.LIKERT7: (1, 7), Scale.CORRECT: (0, 1)}


def _digest(obj: object) -> str:
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


# --- protocol and ethics --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Item:
    item_id: str
    stimulus_ref: str
    """Opaque reference to a stimulus (e.g. a synthetic frame); never raw personal data."""
    outcome: Scale


@dataclass(frozen=True, slots=True)
class StudyProtocol:
    study_id: str
    version: str
    arms: tuple[str, ...]
    """e.g. ("text_only", "taoss_rendered", "taoss_plus_text")."""
    items: tuple[Item, ...]
    block_size: int
    target_n: int
    preregistration_digest: str
    min_age: int = 18

    def __post_init__(self) -> None:
        if len(self.arms) < 2 or len(set(self.arms)) != len(self.arms):
            msg = "a study needs at least two distinct arms"
            raise StudyError(msg)
        if not self.items or len({i.item_id for i in self.items}) != len(self.items):
            msg = "items must be non-empty with unique ids"
            raise StudyError(msg)
        if self.block_size <= 0 or self.block_size % len(self.arms):
            msg = "block size must be a positive multiple of the number of arms"
            raise StudyError(msg)
        if self.target_n <= 0 or not self.preregistration_digest:
            msg = "target_n and a preregistration digest are required"
            raise StudyError(msg)
        if self.min_age < 18:
            msg = "the reference harness only supports adult participants"
            raise StudyError(msg)

    def digest(self) -> str:
        return _digest(asdict(self))


@dataclass(frozen=True, slots=True)
class EthicsApproval:
    board: str
    reference: str
    protocol_digest: str
    consent_form_digest: str
    valid_from_ns: int
    valid_until_ns: int


def require_approval(
    protocol: StudyProtocol,
    form: ConsentForm,
    mode: Mode,
    approval: EthicsApproval | None,
    *,
    now_ns: int,
) -> None:
    """``LIVE`` needs an approval for exactly this protocol and consent form, valid now."""
    if mode is Mode.SYNTHETIC_PILOT:
        return
    if approval is None:
        msg = "no ethics approval recorded: live enrollment refused"
        raise EthicsRefused(msg)
    if approval.protocol_digest != protocol.digest():
        msg = "the approval covers a different protocol version"
        raise EthicsRefused(msg)
    if approval.consent_form_digest != form.digest():
        msg = "the approval covers a different consent form"
        raise EthicsRefused(msg)
    if not approval.valid_from_ns <= now_ns <= approval.valid_until_ns:
        msg = "the ethics approval is not valid at this time"
        raise EthicsRefused(msg)


# --- randomization --------------------------------------------------------------------------------


def allocation_schedule(protocol: StudyProtocol, seed: bytes) -> tuple[str, ...]:
    """Permuted blocks: each block holds every arm equally often, order from HMAC(seed)."""
    if len(seed) < 16:
        msg = "the randomization seed must have at least 16 bytes"
        raise StudyError(msg)
    per_arm = protocol.block_size // len(protocol.arms)
    out: list[str] = []
    block = 0
    while len(out) < protocol.target_n:
        cells = [a for a in protocol.arms for _ in range(per_arm)]
        tags = [
            hmac.new(seed, f"{protocol.digest()}:{block}:{i}".encode(), hashlib.sha256).digest()
            for i in range(len(cells))
        ]
        out.extend(cell for _, cell in sorted(zip(tags, cells, strict=True)))
        block += 1
    return tuple(out[: protocol.target_n])


def schedule_commitment(schedule: Sequence[str], seed: bytes) -> str:
    """Publish before enrollment; reveal ``seed`` after unblinding to prove the schedule."""
    return hashlib.sha256(seed + json.dumps(list(schedule)).encode()).hexdigest()


# --- consent --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ConsentForm:
    version: str
    text: str
    required: tuple[str, ...]
    """Items without which participation is impossible (e.g. "participate", "data_use")."""
    optional: tuple[str, ...] = ()
    """e.g. "reuse_in_future_studies"; declining never excludes a participant."""

    def __post_init__(self) -> None:
        if not self.required or set(self.required) & set(self.optional):
            msg = "required items must be non-empty and disjoint from optional items"
            raise StudyError(msg)

    def digest(self) -> str:
        return _digest(asdict(self))


@dataclass(slots=True)
class ConsentRecord:
    pseudonym: str
    form_digest: str
    granted: frozenset[str]
    given_at_ns: int
    withdrawn_at_ns: int | None = None

    def active(self) -> bool:
        return self.withdrawn_at_ns is None


# --- enrollment and responses ---------------------------------------------------------------------


def _screen_identifiers(text: str) -> None:
    for pattern in _IDENTIFIER_PATTERNS:
        if pattern.search(text):
            msg = "response contains something that looks like a direct identifier"
            raise StudyError(msg)


@dataclass(frozen=True, slots=True)
class Response:
    pseudonym: str
    item_id: str
    value: int
    comment: str = ""


@dataclass
class Enrollment:
    """Runs one study. Holds the pseudonymization key; never stores enrollment codes."""

    protocol: StudyProtocol
    form: ConsentForm
    mode: Mode
    pseudonym_key: bytes
    schedule: tuple[str, ...]
    approval: EthicsApproval | None = None
    consents: dict[str, ConsentRecord] = field(default_factory=dict)
    arms: dict[str, str] = field(default_factory=dict)
    demographics: dict[str, dict[str, str]] = field(default_factory=dict)
    responses: list[Response] = field(default_factory=list)

    def __post_init__(self) -> None:
        if len(self.pseudonym_key) < 32:
            msg = "the pseudonymization key must have at least 32 bytes"
            raise StudyError(msg)

    def pseudonym(self, enrollment_code: str) -> str:
        tag = hmac.new(self.pseudonym_key, enrollment_code.encode(), hashlib.sha256)
        return tag.hexdigest()[:20]

    def enroll(
        self,
        enrollment_code: str,
        granted: set[str],
        *,
        age: int,
        demographics: Mapping[str, str] | None = None,
        now_ns: int,
    ) -> str:
        require_approval(self.protocol, self.form, self.mode, self.approval, now_ns=now_ns)
        if age < self.protocol.min_age:
            msg = "participant below the minimum age"
            raise StudyError(msg)
        missing = set(self.form.required) - granted
        if missing:
            msg = f"required consent items missing: {sorted(missing)}"
            raise StudyError(msg)
        unknown = granted - set(self.form.required) - set(self.form.optional)
        if unknown:
            msg = f"unknown consent items: {sorted(unknown)}"
            raise StudyError(msg)
        p = self.pseudonym(enrollment_code)
        if p in self.consents:
            msg = "already enrolled"
            raise StudyError(msg)
        if len(self.arms) >= len(self.schedule):
            msg = "target sample size reached"
            raise StudyError(msg)
        for v in (demographics or {}).values():
            _screen_identifiers(v)
        self.consents[p] = ConsentRecord(p, self.form.digest(), frozenset(granted), now_ns)
        self.arms[p] = self.schedule[len(self.arms)]  # next concealed allocation
        self.demographics[p] = {"age_band": _age_band(age), **dict(demographics or {})}
        return p

    def respond(self, pseudonym: str, item_id: str, value: int, comment: str = "") -> None:
        record = self.consents.get(pseudonym)
        if record is None or not record.active():
            msg = "no active consent for this participant"
            raise StudyError(msg)
        item = next((i for i in self.protocol.items if i.item_id == item_id), None)
        if item is None:
            msg = "unknown item"
            raise StudyError(msg)
        lo, hi = _SCALE_RANGE[item.outcome]
        if not lo <= value <= hi:
            msg = f"value outside the {item.outcome.value} scale"
            raise StudyError(msg)
        _screen_identifiers(comment)
        self.responses.append(Response(pseudonym, item_id, value, comment))

    def withdraw(self, pseudonym: str, *, now_ns: int) -> None:
        """Withdrawal is always possible and removes the participant from all later exports."""
        record = self.consents.get(pseudonym)
        if record is None:
            msg = "unknown participant"
            raise StudyError(msg)
        record.withdrawn_at_ns = now_ns
        self.responses = [r for r in self.responses if r.pseudonym != pseudonym]
        self.demographics.pop(pseudonym, None)


def _age_band(age: int) -> str:
    if age >= 65:
        return "65+"
    lo = 18 if age < 25 else (age // 10) * 10
    hi = 24 if lo == 18 else lo + 9
    return f"{lo}-{hi}"


def export_responses(
    enrollment: Enrollment, *, k: int = K_ANONYMITY_DEFAULT, quasi_identifiers: Sequence[str] = ()
) -> dict[str, object]:
    """Anonymized export: active consents only, fresh export ids, k-anonymous demographics.

    Participants whose quasi-identifier combination occurs fewer than ``k`` times
    keep their responses, but their demographics are suppressed to ``"*"``.
    Comments are dropped unless the optional ``share_comments`` item was granted.
    """
    active = sorted(p for p, c in enrollment.consents.items() if c.active())
    qi = ("age_band", *quasi_identifiers)
    keys = {p: tuple(enrollment.demographics.get(p, {}).get(q, "?") for q in qi) for p in active}
    counts = Counter(keys.values())
    export_id = {
        p: hashlib.sha256(b"esp/study/export" + enrollment.pseudonym_key + p.encode()).hexdigest()[
            :12
        ]
        for p in active
    }
    participants = []
    suppressed = 0
    for p in active:
        small = counts[keys[p]] < k
        suppressed += small
        participants.append(
            {
                "id": export_id[p],
                "arm": enrollment.arms[p],
                "demographics": dict.fromkeys(qi, "*")
                if small
                else dict(zip(qi, keys[p], strict=True)),
            }
        )
    rows = [
        {
            "id": export_id[r.pseudonym],
            "item": r.item_id,
            "value": r.value,
            **(
                {"comment": r.comment}
                if r.comment and "share_comments" in enrollment.consents[r.pseudonym].granted
                else {}
            ),
        }
        for r in enrollment.responses
        if r.pseudonym in export_id
    ]
    return {
        "study_id": enrollment.protocol.study_id,
        "protocol_digest": enrollment.protocol.digest(),
        "mode": enrollment.mode.value,
        "evidence": enrollment.mode is Mode.LIVE,
        "k_anonymity": k,
        "suppressed_demographics": suppressed,
        "withdrawn": sum(not c.active() for c in enrollment.consents.values()),
        "participants": participants,
        "responses": rows,
    }
