// SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Independent Rust implementation of the ESP V13 wire codec (WP-040) and a session
//! client (WP-041). Written from the V13 text and the ADRs, not translated from the
//! Python reference; interoperability is checked against the shared vectors and live.
//! `neural` mirrors the neural vendor contract 1.0.0 (WP-090).

pub mod crypto;
pub mod header;
pub mod mls;
pub mod neural;
pub mod session;
pub mod tlv;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum WireError {
    #[error("wire: {0}")]
    Malformed(&'static str),
    #[error("crypto: {0}")]
    Crypto(&'static str),
}

pub type Result<T> = core::result::Result<T, WireError>;
