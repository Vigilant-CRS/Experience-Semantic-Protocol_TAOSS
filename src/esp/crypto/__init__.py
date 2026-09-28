# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Cryptographic envelope (V13 section 9.2, WP-016). No custom cryptography.

Primitives come from ``cryptography`` (ChaCha20-Poly1305, Ed25519, X25519),
``hashlib`` (BLAKE2b) and ``noiseprotocol`` (Noise IK state machine, verified
against the official cacophony test vector in the test suite).
"""
