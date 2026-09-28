# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Session state machine (plan section 32, WP-024).

::

    DISCONNECTED -> TRANSPORT_CONNECTING -> CRYPTO_ESTABLISHED -> PROFILE_NEGOTIATION
      -> CAPABILITY_NEGOTIATION -> CONSENT_ESTABLISHED -> ACTIVE -> CLOSING -> CLOSED

``CONSENT_UPDATE`` and ``PROFILE_DOWNGRADE`` require a fresh handshake
(the consent objects and descriptors are bound into the transcript), so they
end the session. ``REVOCATION`` either narrows (stays ACTIVE with fewer
rights) or terminates. Any state may go to CLOSED on a fatal error.
"""

from __future__ import annotations

from enum import Enum
from types import MappingProxyType
from typing import Final

from esp.core.errors import ErrorCode, EspError


class SessionState(Enum):
    DISCONNECTED = "disconnected"
    TRANSPORT_CONNECTING = "transport_connecting"
    CRYPTO_ESTABLISHED = "crypto_established"
    PROFILE_NEGOTIATION = "profile_negotiation"
    CAPABILITY_NEGOTIATION = "capability_negotiation"
    CONSENT_ESTABLISHED = "consent_established"
    ACTIVE = "active"
    CLOSING = "closing"
    CLOSED = "closed"


class SessionStateError(EspError):
    code = ErrorCode.SESSION_STATE


S = SessionState
TRANSITIONS: Final = MappingProxyType(
    {
        S.DISCONNECTED: frozenset({S.TRANSPORT_CONNECTING, S.CLOSED}),
        S.TRANSPORT_CONNECTING: frozenset({S.CRYPTO_ESTABLISHED, S.CLOSED}),
        S.CRYPTO_ESTABLISHED: frozenset({S.PROFILE_NEGOTIATION, S.CLOSED}),
        S.PROFILE_NEGOTIATION: frozenset({S.CAPABILITY_NEGOTIATION, S.CLOSED}),
        S.CAPABILITY_NEGOTIATION: frozenset({S.CONSENT_ESTABLISHED, S.CLOSED}),
        S.CONSENT_ESTABLISHED: frozenset({S.ACTIVE, S.CLOSING, S.CLOSED}),
        S.ACTIVE: frozenset({S.CLOSING, S.CLOSED}),
        S.CLOSING: frozenset({S.CLOSED}),
        S.CLOSED: frozenset(),
    }
)

#: States in which application data may be sent or accepted.
DATA_STATES: Final = frozenset({S.ACTIVE})


class StateMachine:
    __slots__ = ("_history", "_state")

    def __init__(self) -> None:
        self._state = S.DISCONNECTED
        self._history: list[SessionState] = [S.DISCONNECTED]

    @property
    def state(self) -> SessionState:
        return self._state

    @property
    def history(self) -> tuple[SessionState, ...]:
        return tuple(self._history)

    def advance(self, target: SessionState) -> None:
        if target not in TRANSITIONS[self._state]:
            msg = f"invalid transition {self._state.name} -> {target.name}"
            raise SessionStateError(msg)
        self._state = target
        self._history.append(target)

    def close(self) -> None:
        if self._state is not S.CLOSED:
            self._state = S.CLOSED
            self._history.append(S.CLOSED)

    def require_data(self) -> None:
        if self._state not in DATA_STATES:
            msg = f"no application data in state {self._state.name} (consent not established)"
            raise SessionStateError(msg)
