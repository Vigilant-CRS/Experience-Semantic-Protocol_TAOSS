// SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! The 100-byte fixed header (V13 Appendix A, ADR-0010, ADR-0017).

use crate::{Result, WireError::Malformed};

pub const HEADER_LEN: usize = 100;
pub const TAG_LEN: usize = 16;
pub const SIG_LEN: usize = 64;
pub const OVERHEAD: usize = HEADER_LEN + TAG_LEN + SIG_LEN;
const EMO_BIT: u16 = 1 << 2;
const EMO_MASKED: u16 = 1 << 0;

#[derive(Debug, Clone, PartialEq)]
pub struct Header {
    pub version_minor: u8,
    pub profile: u8,
    pub sf_level: u8,
    pub types_bitmap: u16,
    pub consent_flags: u16,
    pub privacy_flags: u16,
    pub capabilities: u16,
    pub timestamp_ns: u64,
    pub timeline_id: [u8; 16],
    pub segment_seq: u32,
    pub dt_ms: u32,
    pub phase: f32,
    pub sender_id: [u8; 32],
    pub payload_len: u32,
    pub nonce: [u8; 12],
}

impl Header {
    pub fn validate(&self) -> Result<()> {
        if self.profile == 0 {
            return Err(Malformed("profile out of range"));
        }
        if self.sf_level > 7 {
            return Err(Malformed("sf_level out of range"));
        }
        if self.types_bitmap & !0x003F != 0 {
            return Err(Malformed("reserved types_bitmap bits set"));
        }
        if self.consent_flags & !0x0007 != 0 {
            return Err(Malformed("reserved consent_flags bits set"));
        }
        if self.privacy_flags & !0x003F != 0 {
            return Err(Malformed("reserved privacy_flags bits set"));
        }
        if self.privacy_flags & 0x000F > 3 {
            return Err(Malformed("reserved DP_LEVEL value"));
        }
        if self.capabilities & 0x7000 != 0 {
            return Err(Malformed("reserved capabilities bits 12-14 set"));
        }
        if self.types_bitmap & EMO_BIT != 0 && self.consent_flags & EMO_MASKED != 0 {
            return Err(Malformed(
                "mask-bit invariant violated: EMO present and EMO_MASKED set",
            ));
        }
        // RFC 4122 version 4, variant 10xx
        if self.timeline_id[6] >> 4 != 4 || self.timeline_id[8] >> 6 != 0b10 {
            return Err(Malformed("timeline_id must be a UUIDv4"));
        }
        if !self.phase.is_finite() || self.phase.is_sign_negative() || self.phase >= 1.0 {
            return Err(Malformed("phase must be a finite float in [0, 1)"));
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; HEADER_LEN]> {
        self.validate()?;
        let mut b = [0u8; HEADER_LEN];
        b[0..3].copy_from_slice(b"ESP");
        b[3] = 1;
        b[4] = self.version_minor;
        b[5] = self.profile;
        b[6] = self.sf_level;
        b[7] = 0;
        b[8..10].copy_from_slice(&self.types_bitmap.to_be_bytes());
        b[10..12].copy_from_slice(&self.consent_flags.to_be_bytes());
        b[12..14].copy_from_slice(&self.privacy_flags.to_be_bytes());
        b[14..16].copy_from_slice(&self.capabilities.to_be_bytes());
        b[16..24].copy_from_slice(&self.timestamp_ns.to_be_bytes());
        b[24..40].copy_from_slice(&self.timeline_id);
        b[40..44].copy_from_slice(&self.segment_seq.to_be_bytes());
        b[44..48].copy_from_slice(&self.dt_ms.to_be_bytes());
        b[48..52].copy_from_slice(&self.phase.to_bits().to_be_bytes());
        b[52..84].copy_from_slice(&self.sender_id);
        b[84..88].copy_from_slice(&self.payload_len.to_be_bytes());
        b[88..100].copy_from_slice(&self.nonce);
        Ok(b)
    }

    pub fn decode(b: &[u8]) -> Result<Header> {
        if b.len() != HEADER_LEN {
            return Err(Malformed("header must be exactly 100 bytes"));
        }
        if &b[0..3] != b"ESP" {
            return Err(Malformed("bad magic"));
        }
        if b[3] != 1 {
            return Err(Malformed("version_major out of range"));
        }
        if b[7] != 0 {
            return Err(Malformed("reserved byte must be zero"));
        }
        let u16at = |i: usize| u16::from_be_bytes([b[i], b[i + 1]]);
        let u32at = |i: usize| u32::from_be_bytes(b[i..i + 4].try_into().unwrap());
        let h = Header {
            version_minor: b[4],
            profile: b[5],
            sf_level: b[6],
            types_bitmap: u16at(8),
            consent_flags: u16at(10),
            privacy_flags: u16at(12),
            capabilities: u16at(14),
            timestamp_ns: u64::from_be_bytes(b[16..24].try_into().unwrap()),
            timeline_id: b[24..40].try_into().unwrap(),
            segment_seq: u32at(40),
            dt_ms: u32at(44),
            phase: f32::from_bits(u32at(48)),
            sender_id: b[52..84].try_into().unwrap(),
            payload_len: u32at(84),
            nonce: b[88..100].try_into().unwrap(),
        };
        h.validate()?;
        Ok(h)
    }
}
