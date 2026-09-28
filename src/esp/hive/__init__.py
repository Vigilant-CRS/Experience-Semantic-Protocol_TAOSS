# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Typed Hive (WP-070, V13 "The Typed Hive"; ADR-0021).

A consent-bound collective process on top of Shared Semantic Memory (XCF).
The label *Hive* is earned only by an episode whose preregistered audit
passes. Nothing here implies collective consciousness.

Modules:

- ``tlv``: 0x70-0x73 codecs and grant narrowing.
- ``membership``: IDENTIFIED refs; the ANONYMOUS interface and its test suite.
- ``aggregation``: secure aggregation, distributed noise, EMO histogram, fusion, social choice.
- ``dynamics``: Friedkin-Johnsen bounded coupling.
- ``audit``: preregistered emergence test and admissibility.
- ``episode``: the lifecycle state machine, Collective Intent and sealing.
- ``frost``: FROST(Ed25519, SHA-512) per RFC 9591.
- ``simulation``: a synthetic episode with at least 5 members.
"""
