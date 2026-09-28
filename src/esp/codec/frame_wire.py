# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""ExperienceFrame <-> packet payload (WP-049; ADR-0011, ADR-0014 proposal).

Wire objects per TAOSS type ``t``:

- typed latent ``0x60+t`` (V13);
- anchor coordinates ``0x50`` (layout per ADR-0014 proposal):
  ``type_code u8 · anchor_set_id[16] · similarity_kind u8 · m u16 · float32[m]``,
  coordinates in the anchor-set order of the pinned registry;
- addendum objects (profile ``esp-addendum-v1`` only), body
  ``encoding u8 = 1 · ESP canonical JSON v1``:
  ``0x92`` affect descriptor (EMO), ``0x93`` emotion episode (EMO),
  ``0x94`` intention state (INT), ``0x90`` semantic binding (both endpoint
  types), ``0x95`` frame metadata (frame id, clock stamp, provenance, consent,
  masked types).

**Type-presence invariant (security):** bit ``t`` of ``types_bitmap`` is set
iff at least one wire object of type ``t`` is present. A decoder rejects any
object whose type bit is clear — otherwise an EMO descriptor could be
smuggled past ``EMO_MASKED`` — and any set bit without an object.
"""

from __future__ import annotations

import struct
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, NamedTuple

import numpy as np
from pydantic import ValidationError

from esp.codec.errors import WireError
from esp.codec.header import ConsentFlags, Header
from esp.codec.tlv import (
    ADDENDUM_V1_CODES,
    TYPED_LATENT_CODES,
    LatentEncoding,
    ParsedPayload,
    Tlv,
    decode_typed_latent,
    encode_tlv,
    encode_typed_latent,
    parse_payload,
)
from esp.core.clock import ClockStamp
from esp.core.model import EspModel
from esp.core.taoss_types import TAOSS6_ORDER, TaossType, TaossTypeName, types_to_bitmap
from esp.frame.model import (
    AnchorCoordinate,
    ConsentRef,
    ExperienceFrame,
    FrameProvenance,
    TypeBlock,
)
from esp.ontology.registry import AnchorSet
from esp.semantics.affect import AffectiveDescriptor
from esp.semantics.bindings import SemanticBinding
from esp.semantics.episode import EmotionEpisode
from esp.semantics.intention import IntentionState

ANCHOR_COORDS_CODE: Final = 0x50
SEMANTIC_BINDING_CODE: Final = 0x90
AFFECT_DESCRIPTOR_CODE: Final = 0x92
EMOTION_EPISODE_CODE: Final = 0x93
INTENTION_STATE_CODE: Final = 0x94
FRAME_METADATA_CODE: Final = 0x95
JSON_ENCODING: Final = 1
_FRAME_ID_NS: Final = uuid.UUID("6b2f8a1c-4d3e-4f5a-9b6c-7d8e9fa0b1c2")


class FrameMetadata(EspModel):
    frame_id: uuid.UUID
    schema_version: str
    timestamp: ClockStamp
    provenance: FrameProvenance
    consent: ConsentRef
    masked_types: tuple[TaossTypeName, ...] = ()


@dataclass(frozen=True, slots=True)
class WireOptions:
    encoding: LatentEncoding = LatentEncoding.F32_BE
    addendum: bool = False
    """``esp-addendum-v1`` pinned by both sides (session descriptor)."""
    anchor_sets: Mapping[str, AnchorSet] = field(default_factory=dict)


@dataclass(frozen=True, slots=True)
class EncodedFrame:
    types_bitmap: int
    emo_masked: bool
    payload: bytes


def _json_tlv(code: int, obj: EspModel) -> bytes:
    return encode_tlv(code, bytes([JSON_ENCODING]) + obj.canonical_json())


def _json_body(tlv: Tlv) -> bytes:
    if not tlv.value or tlv.value[0] != JSON_ENCODING:
        msg = f"addendum TLV 0x{tlv.code:02x} has an unknown body encoding"
        raise WireError(msg)
    return tlv.value[1:]


def _anchor_tlv(block: TypeBlock, sets: Mapping[str, AnchorSet]) -> bytes:
    if block.anchor_set_id is None:  # TypeBlock guarantees it; checked explicitly anyway
        msg = "anchor coordinates without anchor_set_id"
        raise WireError(msg)
    anchor_set = sets.get(block.anchor_set_id)
    if anchor_set is None:
        msg = f"anchor set {block.anchor_set_id!r} is not pinned for this session"
        raise WireError(msg)
    given = {a.anchor_id: a.similarity for a in block.anchors}
    if set(given) != set(anchor_set.anchors):
        msg = "anchor coordinates must cover exactly the anchor set"
        raise WireError(msg)
    values = [given[a] for a in anchor_set.anchors]
    body = (
        bytes([block.type.tlv_code])
        + anchor_set.uuid.bytes
        + bytes([0])  # similarity_kind 0 = cosine
        + struct.pack(f">H{len(values)}f", len(values), *values)
    )
    return encode_tlv(ANCHOR_COORDS_CODE, body)


def frame_to_payload(frame: ExperienceFrame, opts: WireOptions) -> EncodedFrame:
    """Encode a (disclosed) frame. Refuses to silently drop information."""
    out: list[bytes] = []
    present: set[TaossType] = set()
    for block in frame.types:  # TAOSS order (frame invariant)
        if block.latent is not None:
            out.append(encode_typed_latent(block.type, np.asarray(block.latent), opts.encoding))
            present.add(block.type)
    for block in frame.types:
        if block.anchors:
            out.append(_anchor_tlv(block, opts.anchor_sets))
            present.add(block.type)
    addendum_objects = [
        *((AFFECT_DESCRIPTOR_CODE, d, TaossType.EMO) for b in frame.types for d in b.affect),
        *((EMOTION_EPISODE_CODE, e, TaossType.EMO) for b in frame.types for e in b.episodes),
        *((INTENTION_STATE_CODE, s, TaossType.INT) for b in frame.types for s in b.intention),
    ]
    if (addendum_objects or frame.bindings) and not opts.addendum:
        msg = "frame carries addendum objects but esp-addendum-v1 is not pinned"
        raise WireError(msg)
    for code, obj, t in addendum_objects:
        out.append(_json_tlv(code, obj))
        present.add(t)
    for binding in frame.bindings:
        out.append(_json_tlv(SEMANTIC_BINDING_CODE, binding))
    if opts.addendum:
        meta = FrameMetadata(
            frame_id=frame.frame_id,
            schema_version=frame.schema_version,
            timestamp=frame.timestamp,
            provenance=frame.provenance,
            consent=frame.consent,
            masked_types=frame.masked_types,
        )
        out.append(_json_tlv(FRAME_METADATA_CODE, meta))
    if TaossType.EMO in present and TaossType.EMO in frame.masked_types:  # pragma: no cover
        msg = "EMO both present and masked"
        raise WireError(msg)
    return EncodedFrame(
        types_bitmap=types_to_bitmap(present),
        emo_masked=TaossType.EMO in frame.masked_types,
        payload=b"".join(out),
    )


def _decode_anchor_tlv(
    tlv: Tlv, sets: Mapping[str, AnchorSet]
) -> tuple[TaossType, str, tuple[AnchorCoordinate, ...]]:
    v = tlv.value
    if len(v) < 20:
        msg = "anchor coordinates truncated"
        raise WireError(msg)
    code, set_uuid, kind = v[0], uuid.UUID(bytes=v[1:17]), v[17]
    (m,) = struct.unpack_from(">H", v, 18)
    if kind != 0 or code not in TYPED_LATENT_CODES or len(v) != 20 + 4 * m:
        msg = "malformed anchor coordinates"
        raise WireError(msg)
    t = TaossType(code - 0x60)
    match = [s for s in sets.values() if s.uuid == set_uuid]
    if len(match) != 1 or match[0].type is not t or len(match[0].anchors) != m:
        msg = "anchor coordinates reference an unknown or mismatching anchor set"
        raise WireError(msg)
    values = struct.unpack_from(f">{m}f", v, 20)
    coords = tuple(
        AnchorCoordinate(anchor_id=a, similarity=float(x))
        for a, x in zip(match[0].anchors, values, strict=True)
    )
    return t, match[0].id, coords


def payload_to_frame(header: Header, payload: bytes, opts: WireOptions) -> ExperienceFrame:
    """Rebuild a frame from an authenticated, accepted payload."""
    parsed = parse_payload(payload, extra_codes=ADDENDUM_V1_CODES if opts.addendum else frozenset())
    try:
        return _rebuild(header, parsed, opts)
    except (ValidationError, ValueError) as exc:
        if isinstance(exc, WireError):
            raise
        msg = f"payload does not form a valid ExperienceFrame: {type(exc).__name__}"
        raise WireError(msg) from exc


def _rebuild(header: Header, parsed: ParsedPayload, opts: WireOptions) -> ExperienceFrame:  # noqa: PLR0912
    blocks: dict[TaossType, dict[str, object]] = {}
    seen: set[TaossType] = set()

    def slot(t: TaossType) -> dict[str, object]:
        seen.add(t)
        return blocks.setdefault(t, {"type": t})

    bindings: list[SemanticBinding] = []
    meta: FrameMetadata | None = None
    for tlv in parsed.known:
        if tlv.code in TYPED_LATENT_CODES:
            latent = decode_typed_latent(tlv, quantized=header.quantized)
            slot(latent.type)["latent"] = tuple(float(x) for x in latent.values)
        elif tlv.code == ANCHOR_COORDS_CODE:
            t, set_id, coords = _decode_anchor_tlv(tlv, opts.anchor_sets)
            s = slot(t)
            if "anchors" in s:
                msg = f"duplicate anchor coordinates for {t.name}"
                raise WireError(msg)
            s["anchor_set_id"], s["anchors"] = set_id, coords
        elif tlv.code == AFFECT_DESCRIPTOR_CODE:
            s = slot(TaossType.EMO)
            s["affect"] = (*s.get("affect", ()), AffectiveDescriptor.from_json(_json_body(tlv)))  # type: ignore[misc]
        elif tlv.code == EMOTION_EPISODE_CODE:
            s = slot(TaossType.EMO)
            s["episodes"] = (*s.get("episodes", ()), EmotionEpisode.from_json(_json_body(tlv)))  # type: ignore[misc]
        elif tlv.code == INTENTION_STATE_CODE:
            s = slot(TaossType.INT)
            s["intention"] = (*s.get("intention", ()), IntentionState.from_json(_json_body(tlv)))  # type: ignore[misc]
        elif tlv.code == SEMANTIC_BINDING_CODE:
            bindings.append(SemanticBinding.from_json(_json_body(tlv)))
        elif tlv.code == FRAME_METADATA_CODE:
            if meta is not None:
                msg = "duplicate frame metadata"
                raise WireError(msg)
            meta = FrameMetadata.from_json(_json_body(tlv))
    declared = {t for t in TAOSS6_ORDER if header.types_bitmap & t.bit}
    if seen != declared:
        msg = (
            "type-presence invariant violated: bitmap "
            f"{sorted(t.name for t in declared)} vs objects {sorted(t.name for t in seen)}"
        )
        raise WireError(msg)
    for b in bindings:
        if not b.endpoint_types <= seen:
            msg = "binding references a type that is not present"
            raise WireError(msg)
    ident = _identity(header, meta)
    return ExperienceFrame(
        timeline_id=header.timeline_id,
        sequence=header.segment_seq,
        profile=header.profile,
        types=tuple(TypeBlock.model_validate(v) for v in blocks.values()),
        masked_types=_masked_types(header, meta),
        bindings=tuple(bindings),
        schema_version=ident.schema_version,
        frame_id=ident.frame_id,
        timestamp=ident.timestamp,
        provenance=ident.provenance,
        consent=ident.consent,
    )


def _masked_types(header: Header, meta: FrameMetadata | None) -> tuple[TaossType, ...]:
    masked = set(meta.masked_types) if meta is not None else set()
    if header.emo_masked:
        masked.add(TaossType.EMO)
    elif TaossType.EMO in masked:
        msg = "frame metadata masks EMO but EMO_MASKED is clear"
        raise WireError(msg)
    return tuple(sorted(masked))


class _Identity(NamedTuple):
    schema_version: str
    frame_id: uuid.UUID
    timestamp: ClockStamp
    provenance: FrameProvenance
    consent: ConsentRef


def _identity(header: Header, meta: FrameMetadata | None) -> _Identity:
    """Frame id, clock stamp, provenance, consent: from metadata or derived from the header."""
    if meta is not None:
        return _Identity(
            meta.schema_version, meta.frame_id, meta.timestamp, meta.provenance, meta.consent
        )
    frame_id = uuid.UUID(
        bytes=uuid.uuid5(_FRAME_ID_NS, f"{header.timeline_id}:{header.segment_seq}").bytes,
        version=4,
    )
    stamp = ClockStamp(
        source_ns=header.timestamp_ns,
        monotonic_ns=header.timestamp_ns,
        clock_domain="esp:header",
        sequence=header.segment_seq,
    )
    return _Identity("1.0", frame_id, stamp, FrameProvenance(), ConsentRef())


def consent_flags_for(encoded: EncodedFrame, base: int = 0) -> int:
    """Header consent flags with EMO_MASKED set iff the frame masks EMO."""
    flags = base & ~int(ConsentFlags.EMO_MASKED)
    return flags | (int(ConsentFlags.EMO_MASKED) if encoded.emo_masked else 0)
