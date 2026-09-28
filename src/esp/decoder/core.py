# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Decoder definition with absence symbols and per-type policies (V13 section 7.2).

``D_φ : ⊕_t (R^{d_t} + {⊥_t}) → Y``. A type that was not transmitted reaches the
decoder as :class:`Absent` — never as a vector. ``Absent.intentional`` tells a
deliberate mask (``masked_types``) from a type the sender simply did not
include. Zero is a legitimate latent value, absence is not.

Per type in the decoder's type profile ``T_φ``, the profile *must* declare a
policy:

- ``STRICT_REFUSE``: an absent type refuses the whole decode
  (:class:`DecodeRefused`);
- ``GRACEFUL``: the decoder receives :class:`Absent` and proceeds with reduced
  fidelity; the absence is reported;
- ``PRIOR_IMPUTE``: a profile-pinned default vector is used and the receiver
  is told imputation occurred.

A missing declaration is a configuration error. A decoder that silently
treats ``⊥`` as zero fails :func:`audit_absence_handling`
(``ESP_DECODER_POLICY_FAILED``).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Protocol

import numpy as np
from numpy.typing import NDArray

from esp.core.errors import ErrorCode, EspError
from esp.core.taoss_types import L1_DIMS, TaossType
from esp.decoder.outputs import Output, OutputTag
from esp.frame.model import ExperienceFrame
from esp.session.descriptor import DecoderPolicy

Vector = NDArray[np.float64]


class DecoderPolicyError(EspError):
    code = ErrorCode.DECODER_POLICY_FAILED


class DecodeRefused(EspError):  # noqa: N818 - protocol outcome, not a bug
    code = ErrorCode.DECODER_REFUSED


@dataclass(frozen=True, slots=True)
class Absent:
    """``⊥_t``: type ``t`` was not transmitted."""

    type: TaossType
    intentional: bool
    """True if the sender masked the type (vs. not included)."""


Slot = Vector | Absent


@dataclass(frozen=True, slots=True)
class DecoderProfile:
    decoder_id: str
    version: str
    output_tag: OutputTag
    types: frozenset[TaossType]
    """``T_φ``: the types this decoder can interpret."""
    policies: Mapping[TaossType, DecoderPolicy]
    priors: Mapping[TaossType, tuple[float, ...]] = field(default_factory=dict)
    """Profile-pinned default vectors for ``PRIOR_IMPUTE`` types."""

    def __post_init__(self) -> None:
        if not self.types:
            msg = "a decoder must interpret at least one type"
            raise DecoderPolicyError(msg)
        undeclared = self.types - set(self.policies)
        if undeclared:
            msg = f"no absence policy declared for {sorted(t.name for t in undeclared)}"
            raise DecoderPolicyError(msg)
        for t, policy in self.policies.items():
            prior = self.priors.get(t)
            if policy is DecoderPolicy.PRIOR_IMPUTE:
                if prior is None or len(prior) != L1_DIMS[t]:
                    msg = f"PRIOR_IMPUTE for {t.name} needs a pinned {L1_DIMS[t]}-dim prior"
                    raise DecoderPolicyError(msg)
                if not np.all(np.isfinite(prior)):
                    msg = f"prior for {t.name} must be finite"
                    raise DecoderPolicyError(msg)
            elif prior is not None:
                msg = f"a prior for {t.name} is only allowed under PRIOR_IMPUTE"
                raise DecoderPolicyError(msg)
        object.__setattr__(self, "policies", MappingProxyType(dict(self.policies)))
        object.__setattr__(self, "priors", MappingProxyType(dict(self.priors)))


class Decoder(Protocol):
    @property
    def profile(self) -> DecoderProfile: ...

    def decode(self, inputs: Mapping[TaossType, Slot]) -> Output:
        """Map one slot per type in ``T_φ`` (vector or ``Absent``) to ``Y``."""
        ...


@dataclass(frozen=True, slots=True)
class DecodeResult:
    output: Output
    decoder_id: str
    used: tuple[TaossType, ...]
    absent: tuple[Absent, ...]
    """Types passed as ``⊥`` (GRACEFUL): fidelity is reduced."""
    imputed: tuple[TaossType, ...]
    """Types replaced by the pinned prior: the receiver must be told."""
    unused: tuple[TaossType, ...]
    """Sent but outside ``T_φ``: received, not interpreted."""


def slots_of(frame: ExperienceFrame) -> dict[TaossType, Slot]:
    """Present latents as vectors, everything else as ``⊥`` (masked => intentional)."""
    masked = set(frame.masked_types)
    out: dict[TaossType, Slot] = {}
    for t in TaossType:
        block = frame.block(t)
        if block is not None and block.latent is not None:
            out[t] = np.asarray(block.latent, dtype=np.float64)
        else:
            out[t] = Absent(t, intentional=t in masked)
    return out


def run_decoder(decoder: Decoder, frame: ExperienceFrame) -> DecodeResult:
    """Apply the declared absence policies, then decode on ``T_φ ∩ T_sent``."""
    profile = decoder.profile
    slots = slots_of(frame)
    inputs: dict[TaossType, Slot] = {}
    absent: list[Absent] = []
    imputed: list[TaossType] = []
    for t in sorted(profile.types):
        slot = slots[t]
        if not isinstance(slot, Absent):
            inputs[t] = slot
            continue
        policy = profile.policies[t]
        if policy is DecoderPolicy.STRICT_REFUSE:
            why = "masked" if slot.intentional else "not transmitted"
            msg = f"{profile.decoder_id}: required type {t.name} is {why}"
            raise DecodeRefused(msg)
        if policy is DecoderPolicy.PRIOR_IMPUTE:
            inputs[t] = np.asarray(profile.priors[t], dtype=np.float64)
            imputed.append(t)
        else:
            inputs[t] = slot
            absent.append(slot)
    output = decoder.decode(MappingProxyType(inputs))
    if output.tag is not profile.output_tag:
        msg = f"{profile.decoder_id} produced {output.tag}, profile declares {profile.output_tag}"
        raise DecoderPolicyError(msg)
    sent = {t for t, s in slots.items() if not isinstance(s, Absent)}
    return DecodeResult(
        output=output,
        decoder_id=profile.decoder_id,
        used=tuple(sorted(sent & profile.types)),
        absent=tuple(absent),
        imputed=tuple(imputed),
        unused=tuple(sorted(sent - profile.types)),
    )


def audit_absence_handling(decoder: Decoder, *, probes: int = 8, seed: int = 0) -> None:
    """Fail if a GRACEFUL type's ``⊥`` is decoded exactly like a zero vector.

    Probes random inputs for the other types. If for every probe the output
    with ``⊥_t`` equals the output with ``0``, the decoder silently maps
    absence to zero — a profile violation (``ESP_DECODER_POLICY_FAILED``).
    """
    profile = decoder.profile
    rng = np.random.default_rng(seed)
    for t in sorted(profile.types):
        if profile.policies[t] is not DecoderPolicy.GRACEFUL:
            continue
        distinguished = False
        for _ in range(probes):
            base: dict[TaossType, Slot] = {
                u: rng.normal(size=L1_DIMS[u]) for u in profile.types if u is not t
            }
            with_bottom = decoder.decode({**base, t: Absent(t, intentional=True)})
            with_zero = decoder.decode({**base, t: np.zeros(L1_DIMS[t])})
            if with_bottom != with_zero:
                distinguished = True
                break
        if not distinguished:
            msg = f"{profile.decoder_id} treats absent {t.name} as a zero vector"
            raise DecoderPolicyError(msg)


def check_against_session(
    profile: DecoderProfile, session_policies: Mapping[TaossType, DecoderPolicy]
) -> None:
    """The decoder must apply exactly the policy the session profile declares per type."""
    for t in sorted(profile.types):
        declared = session_policies.get(t)
        if declared is None:
            msg = f"session profile declares no decoder policy for {t.name}"
            raise DecoderPolicyError(msg)
        if profile.policies[t] is not declared:
            msg = (
                f"{profile.decoder_id} applies {profile.policies[t].name} to {t.name}, "
                f"the session profile declares {declared.name}"
            )
            raise DecoderPolicyError(msg)
