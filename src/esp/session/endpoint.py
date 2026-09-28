# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Transport-agnostic ESP endpoints: establishment, sending and quarantined receiving.

Establishment (ADR-0012, ADR-0013 incl. GAP-025)::

    I -> R  hs1: Noise msg 1  [SESSION_DESCRIPTOR]
    R -> I  hs2: Noise msg 2  [SESSION_DESCRIPTOR]
    R -> I  t1:  transport    [SESSION_BINDING, ReceiverCapability?]
    I -> R  t2:  transport    [SESSION_BINDING, SENDER_CAPABILITY]
    I -> R  ESP packets

Receiving is quarantined (V13 section 9.7): size bounds, header, expected
sender, signature + AEAD, replay window, *minimal* parse (types, latent
norms, declared valence), Accept predicate — and only then the frame
decoder. :attr:`ReceiverEndpoint.decoder_invocations` makes this checkable.

Runtime invariants use :func:`_need` instead of ``assert`` so that they are
never stripped by ``python -O``.
"""

from __future__ import annotations

import dataclasses
import json
import math
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import numpy as np

from esp.codec.errors import WireError
from esp.codec.frame_wire import (
    AFFECT_DESCRIPTOR_CODE,
    WireOptions,
    consent_flags_for,
    frame_to_payload,
    payload_to_frame,
)
from esp.codec.header import ConsentFlags, DpLevel, Header, PrivacyFlags
from esp.codec.tlv import (
    ADDENDUM_V1_CODES,
    TYPED_LATENT_CODES,
    LatentEncoding,
    ParsedPayload,
    Tlv,
    decode_typed_latent,
    encode_tlv,
    parse_payload,
)
from esp.consent.accept import AcceptState, PacketFacts, commit, evaluate
from esp.consent.capability import ReceiverCapability, ReceiverPolicy, Rights, SenderCapability
from esp.consent.revocation import (
    ConsentRevocationReason,
    Effects,
    RevocationIntent,
    RevocationRegistry,
)
from esp.core.errors import EspError
from esp.core.taoss_types import TaossType
from esp.crypto.envelope import open_packet, seal_packet
from esp.crypto.identity import session_binding, verify_session_binding
from esp.crypto.keys import DirectionKeys, TimelineTagRegistry, deterministic_nonce
from esp.crypto.noise_ik import NoiseIK, Role, StaticKeyPair
from esp.crypto.primitives import CryptoError, SigningKey
from esp.crypto.provenance import verify_chain
from esp.decoder.budget import DecodeBudget, decode_cost
from esp.frame.model import DisclosurePolicy, ExperienceFrame, TypeBlock
from esp.keys.lineage import KeyLineage
from esp.privacy.dp import (
    DP_PARAMS_CODE,
    DpAuditor,
    DpConfig,
    DpParams,
    PrivacyBudgetError,
    clip_and_noise,
    rdp_coefficient,
    secure_rng,
)
from esp.privacy.metadata import REGISTRY_NAME as METADATA_REGISTRY
from esp.privacy.metadata import MetadataProtection
from esp.regulatory.guard import (
    Assessment,
    MisdeclarationError,
    RegulatoryDeclaration,
    check_frame,
    require_permitted,
)
from esp.session.control import CloseReason, SessionClose
from esp.session.descriptor import NegotiatedSession, SessionDescriptor, negotiate, transcript_hash
from esp.session.floor import is_sos, sos_tlv
from esp.session.profiles import TypeSetProfile, profile_for
from esp.session.replay import ReplayError, ReplayWindow
from esp.session.sequence import SenderSequencer, SequenceStore, session_fingerprint
from esp.session.state import SessionState, SessionStateError, StateMachine
from esp.xcf.gate import RecallFrame
from esp.xcf.watermark import (
    REPLAY_WATERMARK_CODE,
    ReplayAdvance,
    ReplayVerifier,
    ReplayWatermarker,
    ReplayWatermarkError,
    ReplayWatermarkPolicy,
    is_replay_segment,
)

DESCRIPTOR_CODE = 0x80
SESSION_BINDING_CODE = 0x85
SENDER_CAPABILITY_CODE = 0x22
RECEIVER_CAPABILITY_CODE = 0x21
REVOCATION_CODE = 0x23
SESSION_CLOSE_CODE = 0x81
MAX_DESCRIPTOR_JSON = 64 * 1024


def _need[T](value: T | None, what: str) -> T:
    """Explicit runtime invariant (never stripped like ``assert`` under ``python -O``)."""
    if value is None:
        msg = f"session invariant violated: {what} not established"
        raise SessionStateError(msg)
    return value


def _tlvs(payload: bytes) -> ParsedPayload:
    return parse_payload(payload, extra_codes=ADDENDUM_V1_CODES)


def _descriptor_msg(desc: SessionDescriptor) -> bytes:
    return encode_tlv(DESCRIPTOR_CODE, desc.encode())


def _read_descriptor(payload: bytes) -> SessionDescriptor:
    tlv = _tlvs(payload).get(DESCRIPTOR_CODE)
    if tlv is None:
        msg = "handshake payload lacks a session descriptor"
        raise WireError(msg)
    return SessionDescriptor.decode(tlv.value)


class SenderEndpoint:
    """Initiator: owns a master (issuer) key and sends experience frames."""

    def __init__(
        self,
        *,
        master: SigningKey,
        static: StaticKeyPair,
        responder_static: bytes,
        receiver_identity: bytes,
        descriptor: SessionDescriptor,
        capability: SenderCapability,
        state_dir: Path,
        wire: WireOptions,
        declaration: RegulatoryDeclaration | None,
        dp: DpConfig | None = None,
        metadata: MetadataProtection | None = None,
    ) -> None:
        # WP-078: no declaration, or a prohibited one, and the pipeline does not start
        self.regulatory: Assessment = require_permitted(declaration)
        self._declaration = _need(declaration, "regulatory declaration")
        if capability.issuer_pk != master.public_bytes:
            msg = "capability must be issued by this master key"
            raise CryptoError(msg)
        self._machine = StateMachine()
        self._static = static
        self._responder_static = responder_static
        self._receiver_identity = receiver_identity
        self._descriptor = descriptor
        self._capability = capability
        self._capability_tlv = capability.sign(master)
        self._master = master
        self._revoked = False
        self._state_dir = state_dir
        self._wire = wire
        self._session_key = SigningKey.generate()
        self._timeline = uuid.uuid4()
        self._noise: NoiseIK | None = None
        self._negotiated: NegotiatedSession | None = None
        self._receiver_policy: ReceiverPolicy | None = None
        self._receiver_cap_tlv: bytes | None = None
        self._keys: DirectionKeys | None = None
        self._sequencer: SenderSequencer | None = None
        self._profile: TypeSetProfile | None = None
        self._dp = dp
        _check_metadata_pin(metadata, descriptor)
        self._metadata = metadata
        self._rng = secure_rng()
        self.decoys_sent = 0
        if dp is not None and dp.level != descriptor.dp_level:
            msg = "DP configuration must match the session descriptor dp_level"
            raise PrivacyBudgetError(msg)
        self.transcript: bytes | None = None

    @property
    def state(self) -> SessionState:
        return self._machine.state

    @property
    def session_public_key(self) -> bytes:
        return self._session_key.public_bytes

    @property
    def timeline_id(self) -> uuid.UUID:
        return self._timeline

    @property
    def receiver_capability_tlv(self) -> bytes | None:
        """The verified receiver capability (0x22 TLV), ``None`` under default deny."""
        return self._receiver_cap_tlv

    # --- establishment ------------------------------------------------------------

    def start(self) -> bytes:
        self._machine.advance(SessionState.TRANSPORT_CONNECTING)
        self._noise = NoiseIK(Role.INITIATOR, self._static, remote_static=self._responder_static)
        return self._noise.write_handshake(_descriptor_msg(self._descriptor))

    def on_handshake2(self, message: bytes) -> None:
        try:
            noise = _need(self._noise, "noise")
            peer = _read_descriptor(noise.read_handshake(message))
            self._machine.advance(SessionState.CRYPTO_ESTABLISHED)
            self._machine.advance(SessionState.PROFILE_NEGOTIATION)
            self._negotiated = negotiate(self._descriptor, peer)
            self._profile = _session_profile(self._negotiated)
            _metadata_active(self._metadata, self._negotiated, self._profile)
            self._machine.advance(SessionState.CAPABILITY_NEGOTIATION)
        except EspError:
            self._machine.close()
            raise

    def on_transport1(self, message: bytes) -> bytes:
        """Verify receiver binding/capability; answer with binding + sender capability."""
        try:
            noise = _need(self._noise, "noise")
            negotiated = _need(self._negotiated, "negotiated profile")
            parsed = _tlvs(noise.receive(message))
            binding = parsed.get(SESSION_BINDING_CODE)
            if binding is None:
                msg = "receiver did not bind its session key"
                raise CryptoError(msg)
            verify_session_binding(binding, noise_h=noise.noise_h)
            self._receiver_policy = self._verify_receiver_capability(parsed, noise.noise_h)
            _check_profile_consentable(
                _need(self._profile, "type-set profile"),
                frozenset(self._capability.types),
                self._receiver_policy.accept_types,
            )
            self.transcript = transcript_hash(
                noise_h=noise.noise_h,
                initiator=self._descriptor,
                responder=negotiated.responder,
                sender_capability=self._capability_tlv.encode(),
                receiver_capability=self._receiver_cap_tlv,
            )
            keys = DirectionKeys.from_split_key(noise.split_keys()[0])
            store = SequenceStore(
                self._state_dir / f"seq-{self._timeline}.json", session_fingerprint(keys.aead)
            )
            store.initialize()
            self._sequencer = SenderSequencer(store)
            TimelineTagRegistry().register(keys, self._timeline)
            self._keys = keys
            reply = (
                session_binding(self._session_key, noise.noise_h).encode()
                + self._capability_tlv.encode()
            )
            self._machine.advance(SessionState.CONSENT_ESTABLISHED)
            self._machine.advance(SessionState.ACTIVE)
            return noise.send(reply)
        except EspError:
            self._machine.close()
            raise

    def _verify_receiver_capability(self, parsed: ParsedPayload, noise_h: bytes) -> ReceiverPolicy:
        rc = parsed.get(RECEIVER_CAPABILITY_CODE)
        if rc is None:
            return ReceiverPolicy.default_deny()
        cap = ReceiverCapability.verify(rc, noise_h=noise_h)
        if cap.pk_receiver != self._receiver_identity:
            msg = "receiver capability signed by an unexpected identity"
            raise CryptoError(msg)
        self._receiver_cap_tlv = rc.encode()
        return ReceiverPolicy.from_capability(cap)

    # --- data ------------------------------------------------------------------------

    def effective_policy(self, requested: DisclosurePolicy) -> DisclosurePolicy:
        """Intersect what the sender wants to share with c_S and the receiver policy."""
        receiver = _need(self._receiver_policy, "receiver policy")
        profile = _need(self._profile, "type-set profile")
        allowed = set(self._capability.types) & set(receiver.accept_types) & set(profile.allowed)
        return DisclosurePolicy(
            allowed_types=tuple(t for t in requested.allowed_types if t in allowed),
            bindings=requested.bindings,
            keep_evidence_refs=requested.keep_evidence_refs,
        )

    def send_frame(self, frame: ExperienceFrame, policy: DisclosurePolicy, *, now_ns: int) -> bytes:
        bitmap, flags, payload, masked = self._prepare_frame(frame, policy)
        return self._seal(bitmap, flags, payload, now_ns, masked)

    def send_replay_segment(
        self,
        frame: ExperienceFrame,
        policy: DisclosurePolicy,
        recall: RecallFrame,
        watermarker: ReplayWatermarker,
        *,
        now_ns: int,
    ) -> bytes:
        """A replay segment (RECALL_FRAME 0x51 + REPLAY_WATERMARK 0x89; GAP-016, ADR-0030).

        The header timestamp is the vendor schedule's, and the segment may only be
        sent within the schedule's tolerance of that time: the sender cannot choose
        replay timing.
        """
        if not self._capability.rights & Rights.ALLOW_REPLAY:
            msg = "replay needs ALLOW_REPLAY in the sender capability"
            raise SessionStateError(msg)
        if self._metadata is not None:
            msg = "replay segments are not defined under esp-metadata-protection-v1 (ADR-0030)"
            raise SessionStateError(msg)
        if not self._wire.addendum:
            msg = "the replay watermark needs esp-addendum-v1"
            raise SessionStateError(msg)
        scheduled = watermarker.scheduled_time()
        if abs(now_ns - scheduled) > watermarker.schedule.tolerance_ns:
            msg = "replay segment outside its scheduled time"
            raise ReplayWatermarkError(msg)
        bitmap, flags, payload, masked = self._prepare_frame(frame, policy)
        payload += recall.encode().encode()
        mark, timestamp = watermarker.watermark(self.timeline_id, payload)
        return self._seal(bitmap, flags, payload + mark, timestamp, masked)

    def _prepare_frame(
        self, frame: ExperienceFrame, policy: DisclosurePolicy
    ) -> tuple[int, int, bytes, frozenset[TaossType]]:
        self._machine.require_data()
        if self._revoked:
            msg = "consent was withdrawn: no further frames under this capability"
            raise SessionStateError(msg)
        disclosed = frame.disclose(self.effective_policy(policy))
        check_frame(self._declaration, disclosed)
        trailer = b""
        _need(self._profile, "type-set profile").check(
            frozenset(disclosed.present_types), frozenset(disclosed.masked_types)
        )
        if self._dp is not None:
            disclosed, trailer = self._privatize(disclosed)
        encoded = frame_to_payload(disclosed, self._wire)
        flags = consent_flags_for(encoded, self._rights_flags())
        _need(self._profile, "type-set profile").check_flags(flags)  # e.g. MEB-SURGICAL NO_REPLAY
        masked = frozenset(disclosed.masked_types)
        return encoded.types_bitmap, flags, encoded.payload + trailer, masked

    def _privatize(self, frame: ExperienceFrame) -> tuple[ExperienceFrame, bytes]:
        """Clip + noise every latent, charge the ledger first, return the 0x30 TLV bytes."""
        dp = _need(self._dp, "dp")
        for block in frame.types:
            if block.anchors or block.affect or block.episodes or block.intention or frame.bindings:
                msg = (
                    "with runtime DP only privatized latents may be sent; anchors, descriptors "
                    "and bindings derived from un-noised data would bypass the guarantee"
                )
                raise PrivacyBudgetError(msg)
        rng = secure_rng()
        blocks = []
        for block in frame.types:
            if block.latent is None:
                continue
            noised = clip_and_noise(np.asarray(block.latent), dp.clip_norm, dp.sigma, rng)
            blocks.append(TypeBlock(type=block.type, latent=tuple(float(x) for x in noised)))
        types = [b.type for b in blocks]
        clips = dict.fromkeys(types, dp.clip_norm)
        sigmas = dict.fromkeys(types, dp.sigma)
        k, eps = dp.ledger.charge(rdp_coefficient(clips, sigmas))  # persisted before release
        params = DpParams(
            capability_id=self._capability.capability_id,
            adjacency=dp.adjacency,
            segment_window=0,
            clip_norms=clips,
            sigmas=sigmas,
            composition_k=k,
            epsilon_spent=eps,
            delta_target=dp.ledger.delta_target,
        )
        private = ExperienceFrame.model_validate(frame.model_dump() | {"types": tuple(blocks)})
        return private, params.encode().encode()

    def retransmit(self, segment_seq: int) -> bytes:
        """Identical bytes of an earlier packet: no re-encryption, no new DP release."""
        return _need(self._sequencer, "sequencer").retransmit(segment_seq)

    def send_control(self, tlvs: bytes, *, now_ns: int) -> bytes:
        self._machine.require_data()
        return self._seal(0, self._rights_flags(), tlvs, now_ns)

    def revoke(
        self,
        *,
        now_ns: int,
        effects: Effects = Effects.REVOKE_FUTURE_USE,
        reason: ConsentRevocationReason = ConsentRevocationReason.CONSENT_WITHDRAWN,
    ) -> bytes:
        """Withdraw consent for this capability (capability scope) and stop sending."""
        intent = RevocationIntent(
            capability_id=self._capability.capability_id,
            timeline_id=uuid.UUID(int=0),
            revoke_from_seq=0,
            reason=reason,
            effects=effects,
            capability_issuer_pk=self._capability.issuer_pk,
            signer_pk=self._master.public_bytes,
        )
        packet = self.send_control(intent.sign(self._master).encode(), now_ns=now_ns)
        self._revoked = True
        return packet

    def panic(self, *, now_ns: int) -> bytes:
        """PANIC: revoke with TERMINATE_SESSIONS and close. Must go on CONTROL (plan 31.5)."""
        packet = self.revoke(
            now_ns=now_ns,
            effects=Effects.REVOKE_FUTURE_USE | Effects.TERMINATE_SESSIONS,
            reason=ConsentRevocationReason.CONSENT_WITHDRAWN,
        )
        self._machine.advance(SessionState.CLOSING)
        self._machine.advance(SessionState.CLOSED)
        return packet

    def sos(self, *, now_ns: int) -> bytes:
        """SOS: a 1-bit control signal without EMO/KNO content (GAP-028)."""
        return self.send_control(sos_tlv().encode(), now_ns=now_ns)

    def close(self, *, now_ns: int, reason: CloseReason = CloseReason.NORMAL) -> bytes:
        packet = self.send_control(SessionClose(reason).encode().encode(), now_ns=now_ns)
        self._machine.advance(SessionState.CLOSING)
        self._machine.advance(SessionState.CLOSED)
        return packet

    def abort(self) -> None:
        """Transport lost: V13 mandates a fresh handshake after state loss (no resumption)."""
        self._machine.close()

    def _rights_flags(self) -> int:
        flags = 0
        if not self._capability.rights & Rights.ALLOW_REPLAY:
            flags |= ConsentFlags.NO_REPLAY
        if not self._capability.rights & Rights.ALLOW_STORE:
            flags |= ConsentFlags.NO_STORE
        return int(flags)

    def decoy(self, *, now_ns: int) -> bytes:
        """A decoy packet: indistinguishable from data on the wire, discarded by the receiver."""
        self._machine.require_data()
        if self._metadata is None:
            msg = "decoy traffic requires esp-metadata-protection-v1"
            raise SessionStateError(msg)
        self.decoys_sent += 1
        return self._seal(0, self._rights_flags(), b"", now_ns)

    def _seal(
        self,
        types_bitmap: int,
        consent_flags: int,
        payload: bytes,
        now_ns: int,
        masked: frozenset[TaossType] = frozenset(),
    ) -> bytes:
        sequencer = _need(self._sequencer, "sequencer")
        keys = _need(self._keys, "traffic keys")
        negotiated = _need(self._negotiated, "negotiated profile")
        quantized = self._wire.encoding is LatentEncoding.INT8_SYM
        privacy = negotiated.dp_level | (int(PrivacyFlags.QUANTIZED) if quantized else 0)
        timestamp = now_ns
        if self._metadata is not None:
            payload = self._metadata.protect(
                types_bitmap=types_bitmap,
                masked=masked,
                payload=payload,
                encoding=self._wire.encoding,
                rng=self._rng,
            )
            types_bitmap = self._metadata.bitmap
            consent_flags &= ~int(ConsentFlags.EMO_MASKED)
            timestamp, privacy = self._metadata.header_fields(now_ns, privacy)
        seq = sequencer.reserve(payload)
        header = Header(
            profile=negotiated.profile,
            sf_level=negotiated.sf_level,
            types_bitmap=types_bitmap,
            consent_flags=consent_flags,
            privacy_flags=int(privacy),
            capabilities=0,
            timestamp_ns=timestamp,
            timeline_id=self._timeline,
            segment_seq=seq,
            dt_ms=0,
            phase=0.0,
            sender_id=self._session_key.public_bytes,
            payload_len=0,
            nonce=deterministic_nonce(keys, self._timeline, seq),
        )
        packet = seal_packet(header, payload, keys, self._session_key)
        sequencer.record_sent(seq, payload, packet)
        return packet


@dataclass(frozen=True, slots=True)
class ReceiverHardening:
    """Receiver-side threat mitigations (WP-060; V13 receiver threats T13-T19)."""

    decode_budget: DecodeBudget | None = None
    """T16: throttle decoding instead of exhausting resources."""
    trusted_vendors: frozenset[bytes] | None = None
    """T18: if set, every data packet needs a verified all-trusted provenance chain."""
    anchor_only: bool = False
    """T19: accept anchor coordinates only; raw typed latents are refused."""
    replay_watermark: ReplayWatermarkPolicy | None = None
    """GAP-016: replay segments (0x51) are accepted only with a verified watermark (0x89)."""


@dataclass(frozen=True, slots=True)
class ReceiveResult:
    accepted: bool
    frame: ExperienceFrame | None = None
    violations: tuple[str, ...] = ()
    control: tuple[Tlv, ...] = ()


@dataclass(frozen=True, slots=True)
class _Active:
    """Everything a receiver needs once the session is ACTIVE."""

    keys: DirectionKeys
    peer_session_pk: bytes
    negotiated: NegotiatedSession
    policy: ReceiverPolicy
    sender_cap: SenderCapability
    replay: ReplayWindow
    profile: TypeSetProfile


class ReceiverEndpoint:
    """Responder: publishes a receiver capability and accepts frames under consent."""

    def __init__(
        self,
        *,
        identity: SigningKey,
        static: StaticKeyPair,
        descriptor: SessionDescriptor,
        capability: Callable[[bytes], ReceiverCapability] | None,
        trusted_issuers: frozenset[bytes],
        wire: WireOptions,
        declaration: RegulatoryDeclaration | None,
        lineage: KeyLineage | None = None,
        accept_state: AcceptState | None = None,
        revocations: RevocationRegistry | None = None,
        metadata: MetadataProtection | None = None,
        inspector: Callable[[Header, ParsedPayload], None] | None = None,
        hardening: ReceiverHardening | None = None,
    ) -> None:
        self._hardening = hardening or ReceiverHardening()
        policy = self._hardening.replay_watermark
        self._replay_verifier = None if policy is None else ReplayVerifier(policy)
        self.regulatory: Assessment = require_permitted(declaration)
        self._declaration = _need(declaration, "regulatory declaration")
        self._machine = StateMachine()
        self._inspector = inspector
        self._identity = identity
        self._static = static
        self._descriptor = descriptor
        self._capability_factory = capability
        self._trusted = trusted_issuers
        self._wire = wire
        self._lineage = lineage
        self.accept_state = accept_state if accept_state is not None else AcceptState()
        self.revocations = revocations if revocations is not None else RevocationRegistry()
        self._session_key = SigningKey.generate()
        self._noise: NoiseIK | None = None
        self._negotiated: NegotiatedSession | None = None
        self._policy: ReceiverPolicy | None = None
        self._cap_tlv: bytes | None = None
        self._active: _Active | None = None
        self._timeline: uuid.UUID | None = None
        self.transcript: bytes | None = None
        self.decoder_invocations = 0
        self.rejections: list[tuple[str, ...]] = []
        self.sos_signals = 0
        self._auditor: DpAuditor | None = None
        _check_metadata_pin(metadata, descriptor)
        self._metadata = metadata
        self.decoys_discarded = 0

    @property
    def state(self) -> SessionState:
        return self._machine.state

    @property
    def capability_tlv(self) -> bytes | None:
        """This receiver's signed capability (0x22 TLV), ``None`` under default deny."""
        return self._cap_tlv

    # --- establishment ------------------------------------------------------------

    def on_handshake1(self, message: bytes) -> tuple[bytes, bytes]:
        try:
            self._machine.advance(SessionState.TRANSPORT_CONNECTING)
            noise = NoiseIK(Role.RESPONDER, self._static)
            self._noise = noise
            peer = _read_descriptor(noise.read_handshake(message))
            hs2 = noise.write_handshake(_descriptor_msg(self._descriptor))
            self._machine.advance(SessionState.CRYPTO_ESTABLISHED)
            self._machine.advance(SessionState.PROFILE_NEGOTIATION)
            self._negotiated = negotiate(peer, self._descriptor)
            _metadata_active(self._metadata, self._negotiated, _session_profile(self._negotiated))
            self._machine.advance(SessionState.CAPABILITY_NEGOTIATION)
            payload = session_binding(self._session_key, noise.noise_h).encode()
            if self._capability_factory is None:
                self._policy = ReceiverPolicy.default_deny()
            else:
                cap = self._capability_factory(noise.noise_h)
                if cap.pk_receiver != self._identity.public_bytes:
                    msg = "receiver capability must name this identity"
                    raise CryptoError(msg)
                self._policy = ReceiverPolicy.from_capability(cap)
                self._cap_tlv = cap.sign(self._identity).encode()
                payload += self._cap_tlv
            return hs2, noise.send(payload)
        except EspError:
            self._machine.close()
            raise

    def on_transport2(self, message: bytes) -> None:
        try:
            noise = _need(self._noise, "noise")
            negotiated = _need(self._negotiated, "negotiated profile")
            policy = _need(self._policy, "receiver policy")
            parsed = _tlvs(noise.receive(message))
            binding = parsed.get(SESSION_BINDING_CODE)
            cap_tlv = parsed.get(SENDER_CAPABILITY_CODE)
            if binding is None or cap_tlv is None:
                msg = "sender must bind its session key and present a capability"
                raise CryptoError(msg)
            peer_pk = verify_session_binding(binding, noise_h=noise.noise_h)
            cap = SenderCapability.verify(cap_tlv)
            self._check_issuer(cap)
            if cap.capability_id.bytes in self.revocations.revoked_capabilities:
                msg = "sender capability was revoked; a new consent grant is required"
                raise CryptoError(msg)
            profile = _session_profile(negotiated)
            _check_profile_consentable(profile, frozenset(cap.types), policy.accept_types)
            self._auditor = DpAuditor(ceiling=cap.dp_epsilon_ceiling)
            self.transcript = transcript_hash(
                noise_h=noise.noise_h,
                initiator=negotiated.initiator,
                responder=self._descriptor,
                sender_capability=cap_tlv.encode(),
                receiver_capability=self._cap_tlv,
            )
            self._active = _Active(
                keys=DirectionKeys.from_split_key(noise.split_keys()[0]),
                peer_session_pk=peer_pk,
                negotiated=negotiated,
                policy=policy,
                sender_cap=cap,
                replay=ReplayWindow(negotiated.initiator.w_back, negotiated.initiator.w_fwd),
                profile=profile,
            )
            self._machine.advance(SessionState.CONSENT_ESTABLISHED)
            self._machine.advance(SessionState.ACTIVE)
        except EspError:
            self._machine.close()
            raise

    def abort(self) -> None:
        """Transport lost: this session ends; a reconnect is a new handshake."""
        self._machine.close()

    def notify_key_compromised(self, master_pk: bytes) -> bool:
        """Terminate immediately if this session's authority roots in ``master_pk`` (V13 9.6)."""
        if self._active is not None and self._active.sender_cap.issuer_pk == master_pk:
            self._machine.close()
            return True
        return False

    def _check_issuer(self, cap: SenderCapability) -> None:
        trusted = cap.issuer_pk in self._trusted
        lineage_ok = self._lineage is None or self._lineage.admit_grant(
            cap.issuer_pk, previously_accepted=True, logged_before_cutoff=False
        )
        if not (trusted and lineage_ok):
            msg = "sender capability issuer is not trusted"
            raise CryptoError(msg)

    # --- receiving ------------------------------------------------------------------

    def receive(self, packet: bytes, *, now_ns: int) -> ReceiveResult:
        if self._machine.state is not SessionState.ACTIVE or self._active is None:
            return self._reject(("0:no active session (data before consent or after close)",))
        act = self._active
        try:
            opened = open_packet(
                packet,
                act.keys,
                expected_sender=act.peer_session_pk,
                max_payload_len=act.negotiated.initiator.max_payload_len,
            )
        except (WireError, CryptoError) as exc:
            return self._reject((f"1:{type(exc).__name__}",))
        header = opened.header
        if self._timeline is None:
            self._timeline = header.timeline_id  # the first authenticated packet pins it
        if header.timeline_id != self._timeline:
            return self._reject(("0:unexpected timeline",))
        try:
            act.replay.check(header.segment_seq)
            extra = ADDENDUM_V1_CODES if self._wire.addendum else frozenset()
            plaintext = opened.plaintext
            parsed = parse_payload(plaintext, extra_codes=extra)
            if self._metadata is not None:
                real = self._metadata.unwrap(header, plaintext, parsed)
                header, plaintext = real.header, real.payload
                parsed = parse_payload(plaintext, extra_codes=extra)
        except (ReplayError, WireError) as exc:
            return self._reject((f"1:{exc}",))
        if self._inspector is not None:
            self._inspector(header, parsed)  # authenticated, real view; before any decision
        if header.types_bitmap == 0:
            act.replay.accept(header.segment_seq)
            return self._handle_control(parsed, act)
        return self._accept_data(header, plaintext, parsed, now_ns, act)

    def _accept_data(
        self, header: Header, plaintext: bytes, parsed: ParsedPayload, now_ns: int, act: _Active
    ) -> ReceiveResult:
        try:
            facts = _quarantine_facts(header, parsed)
            masked = frozenset({TaossType.EMO}) if header.emo_masked else frozenset()
            act.profile.check(facts.types, masked)  # MEB: EMO bit / missing EMO_MASKED refused
            act.profile.check_flags(header.consent_flags)
            facts = self._audit_dp(header, parsed, facts, act)
        except (WireError, PrivacyBudgetError) as exc:
            return self._reject((f"8:{exc}",))
        threat = self._screen_threats(parsed)
        if threat is not None:
            return self._reject((threat,))
        try:
            advance = self._screen_replay(header, plaintext, parsed, now_ns, act)
        except ReplayWatermarkError as exc:
            return self._reject((f"replay:{exc}",))
        decision = evaluate(
            facts,
            act.sender_cap,
            act.policy,
            self.accept_state,
            recipient_pk=self._identity.public_bytes,
            now_ns=now_ns,
            clock_tolerance_ns=act.negotiated.clock_tolerance_ms * 1_000_000,
            revocations=self.revocations,
        )
        if not decision.accepted:
            return self._reject(decision.violations)
        return self._decode_and_commit(header, plaintext, facts, now_ns, act, advance=advance)

    def _screen_replay(
        self, header: Header, plaintext: bytes, parsed: ParsedPayload, now_ns: int, act: _Active
    ) -> ReplayAdvance | None:
        """GAP-016 / ADR-0030: replay segments need consent and a verified watermark."""
        if not is_replay_segment(parsed):
            if parsed.all(REPLAY_WATERMARK_CODE):
                msg = "watermark on a non-replay segment"
                raise ReplayWatermarkError(msg)
            return None
        if not act.sender_cap.rights & Rights.ALLOW_REPLAY:
            msg = "replay segment without ALLOW_REPLAY consent"
            raise ReplayWatermarkError(msg)
        if self._replay_verifier is None or self._metadata is not None:
            msg = "no replay-watermark policy: replay segments are refused (fail closed)"
            raise ReplayWatermarkError(msg)
        return self._replay_verifier.check(header, plaintext, parsed, now_ns=now_ns)

    def _decode_and_commit(
        self,
        header: Header,
        plaintext: bytes,
        facts: PacketFacts,
        now_ns: int,
        act: _Active,
        *,
        advance: ReplayAdvance | None = None,
    ) -> ReceiveResult:
        budget = self._hardening.decode_budget
        if budget is not None and not budget.try_spend(now_ns, decode_cost(len(plaintext))):
            # T16: throttle; nothing decoded or committed, a retransmission may succeed later
            return self._reject(("T16:decode budget exhausted (throttled)",))
        self.decoder_invocations += 1  # the frame decoder runs only after acceptance
        try:
            frame = payload_to_frame(header, plaintext, self._wire)
            check_frame(self._declaration, frame)  # never deliver undeclared affect scopes
        except WireError as exc:
            return self._reject((f"1:{exc}",))
        except MisdeclarationError as exc:
            return self._reject((f"regulatory:{exc}",))
        act.replay.accept(header.segment_seq)
        if advance is not None:
            _need(self._replay_verifier, "replay verifier").commit(advance)
        commit(
            facts,
            act.sender_cap,
            self.accept_state,
            recipient_pk=self._identity.public_bytes,
            now_ns=now_ns,
        )
        return ReceiveResult(accepted=True, frame=frame)

    def _screen_threats(self, parsed: ParsedPayload) -> str | None:
        """Cheap pre-decoder screens for T18 (provenance) and T19 (anchor-only)."""
        h = self._hardening
        if h.anchor_only and any(t.code in TYPED_LATENT_CODES for t in parsed.known):
            return "T19:anchor-only receiver refuses raw typed latents"
        if h.trusted_vendors is not None:
            try:
                chain = verify_chain(parsed, trusted_vendors=tuple(h.trusted_vendors))
            except (WireError, CryptoError) as exc:
                return f"T18:{exc}"
            if not chain:
                return "T18:vendor provenance required but missing"
        return None

    def _audit_dp(
        self, header: Header, parsed: ParsedPayload, facts: PacketFacts, act: _Active
    ) -> PacketFacts:
        """Receiver-auditable DP accounting (V13 section 12.4) inside the quarantine."""
        level = header.dp_level
        if level != act.negotiated.dp_level:
            msg = "packet DP_LEVEL differs from the negotiated profile"
            raise WireError(msg)
        tlv = parsed.get(DP_PARAMS_CODE)
        params = None if tlv is None else DpParams.decode(tlv)
        latent_types = frozenset(
            TaossType(t.code - 0x60) for t in parsed.known if t.code in TYPED_LATENT_CODES
        )
        auditor = _need(self._auditor, "dp auditor")
        if level is DpLevel.NONE:
            auditor.audit(level, params, latent_types)
            return facts
        if params is None or params.capability_id != act.sender_cap.capability_id:
            msg = "TLV_DP_PARAMS missing or bound to another capability"
            raise WireError(msg)
        eps = auditor.audit(level, params, latent_types)
        spent = self.accept_state.epsilon_spent.get(act.sender_cap.capability_id.bytes, 0.0)
        return dataclasses.replace(
            facts, creates_dp_release=True, epsilon_increment=max(0.0, eps - spent)
        )

    def _handle_control(self, parsed: ParsedPayload, act: _Active) -> ReceiveResult:
        if self._metadata is not None and not parsed.known:
            self.decoys_discarded += 1  # decoy: authenticated, carries nothing
            return ReceiveResult(accepted=True)
        for tlv in parsed.known:
            if tlv.code == REVOCATION_CODE:
                intent = self.revocations.apply(
                    tlv, capability=act.sender_cap, lineage=self._lineage
                )
                if intent.effects & Effects.TERMINATE_SESSIONS:
                    self._machine.advance(SessionState.CLOSING)
                    self._machine.advance(SessionState.CLOSED)
            elif is_sos(tlv):
                self.sos_signals += 1
            elif tlv.code == SESSION_CLOSE_CODE:
                SessionClose.decode(tlv)
                self._machine.advance(SessionState.CLOSING)
                self._machine.advance(SessionState.CLOSED)
            elif tlv.code == DESCRIPTOR_CODE:
                self._machine.close()  # no silent profile change inside a session
                msg = "session descriptor change requires a new handshake"
                raise SessionStateError(msg)
        return ReceiveResult(accepted=True, control=parsed.known)

    def _reject(self, violations: tuple[str, ...]) -> ReceiveResult:
        self.rejections.append(violations)
        return ReceiveResult(accepted=False, violations=violations)


def _session_profile(negotiated: NegotiatedSession) -> TypeSetProfile:
    return profile_for(negotiated.sf_level, frozenset(negotiated.registries))


def _check_metadata_pin(config: MetadataProtection | None, descriptor: SessionDescriptor) -> None:
    """The descriptor pins metadata protection iff it is configured, with its digest."""
    pinned = descriptor.registries.get(METADATA_REGISTRY)
    if config is None and pinned is not None:
        msg = f"{METADATA_REGISTRY} is pinned but not configured"
        raise WireError(msg)
    if config is not None and pinned != config.digest():
        msg = f"{METADATA_REGISTRY} must be pinned with the configuration digest"
        raise WireError(msg)


def _metadata_active(
    config: MetadataProtection | None, negotiated: NegotiatedSession, profile: TypeSetProfile
) -> None:
    """Refuse sessions where configured protection would silently be off."""
    if config is None:
        return
    if METADATA_REGISTRY not in negotiated.registries:
        msg = "peer does not pin esp-metadata-protection-v1; refusing unprotected session"
        raise WireError(msg)
    if not profile.allowed <= config.constant_types:
        msg = f"constant type set must cover every type {profile.name} allows"
        raise WireError(msg)


def _check_profile_consentable(
    profile: TypeSetProfile,
    sender_types: frozenset[TaossType],
    receiver_types: frozenset[TaossType],
) -> None:
    """Fail at establishment if consent cannot cover the profile's required types."""
    missing = profile.required - (sender_types & receiver_types)
    if missing:
        msg = (
            f"{profile.name} requires {sorted(t.name for t in missing)}, which sender "
            "and receiver consent do not both allow; choose another profile"
        )
        raise CryptoError(msg)


def _quarantine_facts(header: Header, parsed: ParsedPayload) -> PacketFacts:
    """Minimal parse: types, latent norms, declared valence. No semantic decoding."""
    norms: dict[TaossType, float] = {}
    for tlv in parsed.known:
        if tlv.code in TYPED_LATENT_CODES:
            latent = decode_typed_latent(tlv, quantized=header.quantized)
            norms[latent.type] = float(np.linalg.norm(latent.values))
    types = frozenset(t for t in TaossType if header.types_bitmap & t.bit)
    for t in types - set(norms):
        norms[t] = 0.0  # anchor-only / descriptor-only blocks carry no latent energy
    valence: float | None = None
    for tlv in parsed.all(AFFECT_DESCRIPTOR_CODE):
        v = _declared_valence(tlv)
        if v is not None and (valence is None or abs(v) > abs(valence)):
            valence = v
    return PacketFacts(
        authenticated=True,
        types=types,
        consent_flags=header.consent_flags,
        norms=norms,
        valence=valence,
        timeline_id=header.timeline_id,
        segment_seq=header.segment_seq,
    )


def _declared_valence(tlv: Tlv) -> float | None:
    """Read only the ``valence`` field of an affect descriptor (bounded, no model build)."""
    if not tlv.value or tlv.value[0] != 1 or len(tlv.value) > MAX_DESCRIPTOR_JSON:
        msg = "unreadable affect descriptor"
        raise WireError(msg)
    try:
        data = json.loads(tlv.value[1:])
    except ValueError:
        msg = "unreadable affect descriptor"
        raise WireError(msg) from None
    value = data.get("valence") if isinstance(data, dict) else None
    if value is None:
        return None
    if not isinstance(value, float | int) or isinstance(value, bool) or not math.isfinite(value):
        msg = "invalid declared valence"
        raise WireError(msg)
    if not -1.0 <= value <= 1.0:  # T13 pre-screen: bounded even without receiver bounds
        msg = "declared valence outside [-1, 1]"
        raise WireError(msg)
    return float(value)
