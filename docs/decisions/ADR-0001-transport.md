# ADR-0001 — Transport: abstraction first, QUIC as reference adapter

- Status: ACCEPTED (2026-09-28)
- Resolves: GAP-010

## Decision

ESP is an application protocol above a `Transport` abstraction with reliable
ordered streams (control, state, bulk) and optional unreliable datagrams.
Reference implementations:

1. an in-memory transport with fault injection (latency, loss, reorder,
   duplication) for M3/M4 tests;
2. QUIC (RFC 9000/9001, datagrams per RFC 9221) via `aioquic`.

Noise IK remains the end-to-end security layer independent of transport
TLS. The double encryption with QUIC is accepted: TLS protects transport
metadata hop by hop, while Noise/ESP protects content end to end.
