# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Import of the legacy movie ontology as an ESP vocabulary (ADR-0004).

What is imported: emotion tags, viewer-impact tags, synonyms, definitions,
source version metadata, and an explicit mapping to the V13 basic-8 anchors.

What is **not** imported: the retrieval normalization. In the legacy engine
``emotion_sparse`` is L1-normalized (weights sum to 1 across 24 emotion + 6
impact tags). That is a retrieval representation, not a psychological state:
it discards absolute intensity (plan section 5). Legacy retrieval weights are
therefore kept in :class:`LegacyRetrievalWeights` and can never become
:class:`~esp.semantics.affect.CategoryEstimate` intensities.
"""

from __future__ import annotations

import json
import math
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum, unique
from pathlib import Path
from typing import Any, Final

from esp.core.errors import ErrorCode, EspError
from esp.core.taoss_types import TaossType
from esp.ontology.profiles import BASIC8_ID
from esp.ontology.registry import Anchor, AnchorSet, Registry, Vocabulary

VOCABULARY_ID: Final = "esp-emo-movie-legacy-v3"
LABEL_PREFIX: Final = "movie3-"
_LABEL_RE: Final = re.compile(r"^[a-z][a-z0-9_\-]*$")


class LegacyOntologyError(EspError):
    code = ErrorCode.VALIDATION


@unique
class MatchKind(StrEnum):
    """How a legacy tag relates to a basic-8 anchor (SKOS-like)."""

    NARROWER = "narrower"
    """The legacy tag is a more specific form of the basic-8 anchor."""
    APPROXIMATE = "approximate"
    """Related but not equivalent; requires expert review before use."""


@dataclass(frozen=True, slots=True)
class Basic8Mapping:
    basic8_label: str
    match: MatchKind


#: Family-level mapping to ``esp-emo-v13-basic8-v1`` (status: PROPOSED, ADR-0004).
#: Plutchik treats "love" as a joy+trust dyad; "wonder/awe" is related to but
#: not identical with surprise. These are flagged APPROXIMATE on purpose.
FAMILY_TO_BASIC8: Final[Mapping[str, Basic8Mapping]] = {
    "joy": Basic8Mapping("joy", MatchKind.NARROWER),
    "love": Basic8Mapping("trust", MatchKind.APPROXIMATE),
    "wonder": Basic8Mapping("surprise", MatchKind.APPROXIMATE),
    "anticipation": Basic8Mapping("anticipation", MatchKind.NARROWER),
    "fear": Basic8Mapping("fear", MatchKind.NARROWER),
    "sadness": Basic8Mapping("sadness", MatchKind.NARROWER),
    "anger": Basic8Mapping("anger", MatchKind.NARROWER),
}

#: Tag-level overrides for the heterogeneous legacy "darkness" family.
TAG_TO_BASIC8: Final[Mapping[str, Basic8Mapping]] = {
    "disgust": Basic8Mapping("disgust", MatchKind.NARROWER),
    "horror": Basic8Mapping("fear", MatchKind.APPROXIMATE),
    "despair": Basic8Mapping("sadness", MatchKind.APPROXIMATE),
}


@dataclass(frozen=True, slots=True)
class LegacyOntology:
    version: str
    families: Mapping[str, tuple[str, ...]]
    emotion_tags: tuple[str, ...]
    impact_tags: tuple[str, ...]
    synonyms: Mapping[str, tuple[str, ...]]
    definitions: Mapping[str, str]
    normalization_note: str

    @property
    def family_of(self) -> dict[str, str]:
        return {tag: fam for fam, tags in self.families.items() for tag in tags}


@dataclass(frozen=True, slots=True)
class ImportReport:
    """Reproducible record of everything the import could not take over verbatim."""

    source_version: str
    dropped_synonyms: tuple[tuple[str, str, str], ...] = field(default=())
    """``(canonical_tag, synonym, reason)`` triples."""


def _read_json(path: Path) -> dict[str, Any]:
    try:
        with path.open(encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError as exc:
        msg = f"legacy ontology file missing: {path.name}"
        raise LegacyOntologyError(msg) from exc
    if not isinstance(data, dict):
        msg = f"{path.name}: expected a JSON object"
        raise LegacyOntologyError(msg)
    return data


def _string_list(value: object, where: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        msg = f"{where}: expected a list of strings"
        raise LegacyOntologyError(msg)
    return tuple(value)


def load_legacy_ontology(directory: Path) -> LegacyOntology:
    """Load and validate ``config/ontology_v3`` of the legacy repository."""
    emotions = _read_json(directory / "emotions.json")
    impact = _read_json(directory / "wirkung.json")
    synonyms = _read_json(directory / "synonyms.json")
    definitions_file = directory / "tag_definitions.json"
    definitions = _read_json(definitions_file) if definitions_file.exists() else {}

    version = emotions.get("_version")
    if not isinstance(version, str) or impact.get("_version") != version:
        msg = "emotions.json and wirkung.json must share one _version"
        raise LegacyOntologyError(msg)
    tags = _string_list(emotions.get("tags"), "emotions.tags")
    raw_families = emotions.get("families")
    if not isinstance(raw_families, dict):
        msg = "emotions.families: expected an object"
        raise LegacyOntologyError(msg)
    families = {k: _string_list(v, f"families.{k}") for k, v in raw_families.items()}
    impact_tags = _string_list(impact.get("tags"), "wirkung.tags")

    flat = [t for members in families.values() for t in members]
    if sorted(flat) != sorted(tags) or len(set(tags)) != len(tags):
        msg = "every emotion tag must belong to exactly one family"
        raise LegacyOntologyError(msg)
    for name, count, items in (
        ("emotions", emotions.get("_count"), tags),
        ("wirkung", impact.get("_count"), impact_tags),
    ):
        if count != len(items):
            msg = f"{name}._count={count} does not match {len(items)} tags"
            raise LegacyOntologyError(msg)
    if set(tags) & set(impact_tags):
        msg = "emotion and impact tags must be disjoint"
        raise LegacyOntologyError(msg)

    groups = synonyms.get("groups", {})
    if not isinstance(groups, dict):
        msg = "synonyms.groups: expected an object"
        raise LegacyOntologyError(msg)
    syn = {k: _string_list(v, f"synonyms.{k}") for k, v in groups.items()}
    defs = definitions.get("definitions", {})
    if not isinstance(defs, dict) or not all(isinstance(v, str) for v in defs.values()):
        msg = "tag_definitions.definitions: expected an object of strings"
        raise LegacyOntologyError(msg)

    return LegacyOntology(
        version=version,
        families=families,
        emotion_tags=tags,
        impact_tags=impact_tags,
        synonyms=syn,
        definitions=defs,
        normalization_note=str(emotions.get("_normalization", "")),
    )


def basic8_mapping(legacy: LegacyOntology, tag: str) -> Basic8Mapping | None:
    """Mapping of one legacy *emotion* tag to basic-8; ``None`` for impact tags."""
    if tag in TAG_TO_BASIC8:
        return TAG_TO_BASIC8[tag]
    family = legacy.family_of.get(tag)
    if family is None:
        return None
    try:
        return FAMILY_TO_BASIC8[family]
    except KeyError:
        msg = f"legacy family {family!r} (tag {tag!r}) has no basic-8 mapping"
        raise LegacyOntologyError(msg) from None


def _normalize_alias(term: str) -> str:
    return re.sub(r"\s+", "-", term.strip().lower())


def to_registry(legacy: LegacyOntology) -> tuple[Registry, ImportReport]:
    """Convert the legacy vocabulary into an ESP registry (vocabulary + anchors)."""
    all_tags = (*legacy.emotion_tags, *legacy.impact_tags)
    reserved = {LABEL_PREFIX + t for t in all_tags} | set(all_tags)
    counts: dict[str, int] = {}
    for tag in all_tags:
        for s in legacy.synonyms.get(tag, ()):
            alias = _normalize_alias(s)
            counts[alias] = counts.get(alias, 0) + 1

    dropped: list[tuple[str, str, str]] = []
    anchors: list[Anchor] = []
    for tag in all_tags:
        if _LABEL_RE.fullmatch(tag) is None:
            msg = f"legacy tag {tag!r} is not a valid label"
            raise LegacyOntologyError(msg)
        aliases: list[str] = [tag]
        for s in legacy.synonyms.get(tag, ()):
            alias = _normalize_alias(s)
            if _LABEL_RE.fullmatch(alias) is None:
                dropped.append((tag, s, "invalid label syntax"))
            elif alias in reserved:
                dropped.append((tag, s, "collides with a tag"))
            elif counts[alias] > 1:
                dropped.append((tag, s, "ambiguous across tags"))
            elif alias not in aliases:
                aliases.append(alias)
        is_impact = tag in legacy.impact_tags
        kind = "viewer-impact tag (retrieval)" if is_impact else "emotion tag"
        mapping = None if is_impact else basic8_mapping(legacy, tag)
        references = [f"legacy-movie-ontology:{legacy.version}:{tag}"]
        if mapping is not None:
            references.append(
                f"maps-to:{BASIC8_ID}:esp:emo:{mapping.basic8_label}:v1:{mapping.match.value}"
            )
        definition = legacy.definitions.get(tag) or f"Legacy movie ontology {kind} '{tag}'."
        anchors.append(
            Anchor(
                id=f"esp:emo:{LABEL_PREFIX}{tag}:v1",
                type=TaossType.EMO,
                label=f"{LABEL_PREFIX}{tag}",
                vocabulary_id=VOCABULARY_ID,
                definition=f"[{kind}; content-side] {definition}",
                references=tuple(references),
                version=1,
                aliases=tuple(aliases),
            )
        )
    ids = tuple(a.id for a in anchors)
    registry = Registry(
        name=VOCABULARY_ID,
        version=_semver(legacy.version),
        anchors=tuple(anchors),
        vocabularies=(
            Vocabulary(
                id=VOCABULARY_ID,
                type=TaossType.EMO,
                version=_semver(legacy.version),
                title=f"Emotional Movie Search Engine ontology {legacy.version} (adapter)",
                license="LicenseRef-Vigilant-Proprietary",
                anchors=ids,
            ),
        ),
        anchor_sets=(AnchorSet(id=VOCABULARY_ID, type=TaossType.EMO, anchors=ids),),
    )
    return registry, ImportReport(source_version=legacy.version, dropped_synonyms=tuple(dropped))


def _semver(version: str) -> str:
    return version.removeprefix("v")


@dataclass(frozen=True, slots=True)
class LegacyRetrievalWeights:
    """``emotion_sparse`` weights of one film: a **retrieval** representation.

    Weights are L1-normalized by construction (sum = 1). They express a
    relative mix used for similarity search and carry no absolute intensity.
    There is intentionally no conversion to psychological intensities.
    """

    weights: Mapping[str, float]

    def __post_init__(self) -> None:
        if not self.weights:
            msg = "empty retrieval vector"
            raise LegacyOntologyError(msg)
        if any((not math.isfinite(w)) or w < 0.0 for w in self.weights.values()):
            msg = "retrieval weights must be finite and non-negative"
            raise LegacyOntologyError(msg)
        total = math.fsum(self.weights.values())
        if not math.isclose(total, 1.0, rel_tol=0.0, abs_tol=1e-6):
            msg = f"legacy emotion_sparse must be L1-normalized (sum={total})"
            raise LegacyOntologyError(msg)

    def to_category_intensities(self) -> None:
        """Always refuses: retrieval weights are not intensities (plan section 5)."""
        msg = (
            "legacy L1-normalized retrieval weights cannot be converted into "
            "psychological intensities: absolute intensity was discarded"
        )
        raise LegacyOntologyError(msg)
