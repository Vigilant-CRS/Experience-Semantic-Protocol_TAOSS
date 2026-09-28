# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""QUIC transport adapter (RFC 9000/9001, datagrams RFC 9221) via ``aioquic``.

Stream mapping (client-initiated bidirectional streams)::

    CONTROL -> stream 0     STATE -> stream 4     BULK -> stream 8
    DATAGRAM -> QUIC DATAGRAM frames (unreliable, may be dropped)

Each stream carries length-prefixed ESP messages. QUIC's TLS 1.3 protects
the hop; ESP's Noise/AEAD/signature layer protects end to end (ADR-0001).

Design note: :class:`EspQuicProtocol` only translates aioquic events into an
inbox; :class:`QuicConnection` implements the ESP ``Connection`` interface.
Base-class attributes/methods of ``QuicConnectionProtocol`` are not overridden.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import ipaddress
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any, Final

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.asyncio.server import QuicServer, serve
from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.events import (
    ConnectionTerminated,
    DatagramFrameReceived,
    HandshakeCompleted,
    QuicEvent,
    StreamDataReceived,
)
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from esp.transport.base import (
    DEFAULT_MAX_DATAGRAM_PAYLOAD,
    Channel,
    ConnectionClosedError,
    Message,
    StreamDeframer,
    TransportError,
    check_datagram_size,
)

ALPN: Final = "esp/1"
STREAM_OF: Final = {Channel.CONTROL: 0, Channel.STATE: 4, Channel.BULK: 8}
CHANNEL_OF: Final = {v: k for k, v in STREAM_OF.items()}
MAX_DATAGRAM_FRAME: Final = 65536


class EspQuicProtocol(QuicConnectionProtocol):
    """Translates aioquic events into ESP messages."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:  # noqa: ANN401 - aioquic signature
        super().__init__(*args, **kwargs)
        self.esp_inbox: asyncio.Queue[Message | None] = asyncio.Queue()
        self.esp_handshake_done = asyncio.Event()
        self.esp_terminated = False
        self._deframers = {sid: StreamDeframer() for sid in CHANNEL_OF}

    def quic_event_received(self, event: QuicEvent) -> None:
        if isinstance(event, HandshakeCompleted):
            self.esp_handshake_done.set()
        elif isinstance(event, StreamDataReceived):
            self._on_stream(event)
        elif isinstance(event, DatagramFrameReceived):
            self.esp_inbox.put_nowait(Message(Channel.DATAGRAM, event.data))
        elif isinstance(event, ConnectionTerminated):
            self.esp_terminated = True
            self.esp_inbox.put_nowait(None)

    def _on_stream(self, event: StreamDataReceived) -> None:
        channel = CHANNEL_OF.get(event.stream_id)
        if channel is None:
            self._quic.close(error_code=0x1, reason_phrase="unexpected stream")
            self.transmit()
            return
        try:
            for data in self._deframers[event.stream_id].feed(event.data):
                self.esp_inbox.put_nowait(Message(channel, data))
        except TransportError:
            self._quic.close(error_code=0x2, reason_phrase="framing error")
            self.transmit()


class QuicConnection:
    """ESP ``Connection`` over one QUIC connection."""

    def __init__(self, protocol: EspQuicProtocol) -> None:
        self._protocol = protocol
        self._closed = False

    async def send(self, channel: Channel, data: bytes) -> None:
        if self._closed or self._protocol.esp_terminated:
            msg = "connection closed"
            raise ConnectionClosedError(msg)
        quic = self._protocol._quic
        if channel is Channel.DATAGRAM:
            # an oversized frame would block aioquic's datagram queue forever
            check_datagram_size(data, self.max_datagram_payload)
            quic.send_datagram_frame(data)
        else:
            quic.send_stream_data(STREAM_OF[channel], StreamDeframer.frame(data))
        self._protocol.transmit()

    async def receive(self) -> Message:
        item = await self._protocol.esp_inbox.get()
        if item is None:
            msg = "QUIC connection terminated"
            raise ConnectionClosedError(msg)
        return item

    async def close(self) -> None:
        if not self._closed:
            self._closed = True
            self._protocol.close()

    @property
    def max_datagram_payload(self) -> int:
        return DEFAULT_MAX_DATAGRAM_PAYLOAD

    def rtt_sample(self) -> float | None:
        recovery = getattr(self._protocol._quic, "_loss", None)
        rtt = getattr(recovery, "_rtt_smoothed", None)
        return float(rtt) if rtt else None


def _configuration(*, is_client: bool) -> QuicConfiguration:
    return QuicConfiguration(
        is_client=is_client,
        alpn_protocols=[ALPN],
        max_datagram_frame_size=MAX_DATAGRAM_FRAME,
        idle_timeout=30.0,
    )


def self_signed_certificate(host: str = "localhost") -> tuple[bytes, bytes]:
    """PEM certificate and key for tests (ECDSA P-256, valid for one day)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host)])
    now = datetime.datetime.now(datetime.UTC)
    san: list[x509.GeneralName] = [x509.DNSName(host)]
    with contextlib.suppress(ValueError):
        san.append(x509.IPAddress(ipaddress.ip_address(host)))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


async def serve_quic(
    host: str,
    port: int,
    *,
    certificate_pem: bytes,
    key_pem: bytes,
    on_connection: Callable[[QuicConnection], None],
) -> QuicServer:
    config = _configuration(is_client=False)
    config.certificate = x509.load_pem_x509_certificate(certificate_pem)
    private_key = serialization.load_pem_private_key(key_pem, password=None)
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        msg = "expected an EC private key"
        raise TransportError(msg)
    config.private_key = private_key
    tasks: set[asyncio.Task[None]] = set()

    def factory(*args: Any, **kwargs: Any) -> EspQuicProtocol:  # noqa: ANN401
        protocol = EspQuicProtocol(*args, **kwargs)
        task = asyncio.get_running_loop().create_task(_announce(protocol, on_connection))
        tasks.add(task)
        task.add_done_callback(tasks.discard)
        return protocol

    return await serve(host, port, configuration=config, create_protocol=factory)


async def _announce(
    protocol: EspQuicProtocol, on_connection: Callable[[QuicConnection], None]
) -> None:
    await protocol.esp_handshake_done.wait()
    on_connection(QuicConnection(protocol))


@asynccontextmanager
async def connect_quic(
    host: str, port: int, *, ca_pem: bytes, server_name: str = "localhost"
) -> AsyncIterator[QuicConnection]:
    config = _configuration(is_client=True)
    config.server_name = server_name
    config.load_verify_locations(cadata=ca_pem)
    async with connect(host, port, configuration=config, create_protocol=EspQuicProtocol) as proto:
        if not isinstance(proto, EspQuicProtocol):  # pragma: no cover - factory guarantees it
            msg = "unexpected protocol type"
            raise TransportError(msg)
        yield QuicConnection(proto)
