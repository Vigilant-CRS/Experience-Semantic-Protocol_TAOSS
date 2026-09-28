// SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Session establishment (ADR-0012, ADR-0013 incl. GAP-025/026) — WP-041.
//!
//! ```text
//! I -> R  hs1: Noise IK msg 1  [SESSION_DESCRIPTOR 0x80]
//! R -> I  hs2: Noise IK msg 2  [SESSION_DESCRIPTOR 0x80]
//! R -> I  t1:  transport       [SESSION_BINDING 0x85, RECEIVER_CAPABILITY 0x21?]
//! I -> R  t2:  transport       [SESSION_BINDING 0x85, SENDER_CAPABILITY 0x22]
//! ESP packets keyed by DirectionKeys::from_split_key(k_i2r)
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::crypto::blake2b256;
use crate::tlv::{encode, Tlv};
use crate::{
    Result,
    WireError::{Crypto, Malformed},
};

pub const PROTOCOL: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2b";
pub const PROLOGUE: &[u8] = b"esp/v1";

fn domain(code: u8) -> &'static [u8] {
    match code {
        0x21 => b"esp/v1/receiver-capability",
        0x22 => b"esp/v1/capability",
        0x23 => b"esp/v1/revocation",
        0x85 => b"esp/v1/session-binding",
        _ => b"",
    }
}

fn signed_message(code: u8, body: &[u8]) -> Vec<u8> {
    let mut m = domain(code).to_vec();
    m.push(code);
    m.extend_from_slice(&((body.len() + 64) as u32).to_be_bytes());
    m.extend_from_slice(body);
    m
}

pub fn sign_tlv(code: u8, body: &[u8], key: &SigningKey) -> Tlv {
    let sig = key.sign(&signed_message(code, body));
    let mut value = body.to_vec();
    value.extend_from_slice(&sig.to_bytes());
    Tlv { code, value }
}

pub fn verify_signed(tlv: &Tlv, pk: &[u8; 32]) -> Result<Vec<u8>> {
    if domain(tlv.code).is_empty() || tlv.value.len() < 64 {
        return Err(Malformed("not a canonical signed TLV"));
    }
    let (body, sig) = tlv.value.split_at(tlv.value.len() - 64);
    let vk = VerifyingKey::from_bytes(pk).map_err(|_| Crypto("bad public key"))?;
    let sig = Signature::from_bytes(sig.try_into().unwrap());
    vk.verify_strict(&signed_message(tlv.code, body), &sig)
        .map_err(|_| Crypto("signature invalid"))?;
    Ok(body.to_vec())
}

/// ESP ``noise_h``: BLAKE2b-256("esp/v1/noise-h" || h) of the 64-byte Noise hash (GAP-026).
pub fn noise_h(handshake_hash: &[u8]) -> [u8; 32] {
    let mut d = b"esp/v1/noise-h".to_vec();
    d.extend_from_slice(handshake_hash);
    blake2b256(&d)
}

pub fn session_binding(session: &SigningKey, nh: &[u8; 32]) -> Tlv {
    let mut body = vec![1u8];
    body.extend_from_slice(&session.verifying_key().to_bytes());
    body.extend_from_slice(nh);
    sign_tlv(0x85, &body, session)
}

pub fn verify_session_binding(tlv: &Tlv, nh: &[u8; 32]) -> Result<[u8; 32]> {
    if tlv.code != 0x85 || tlv.value.len() != 1 + 32 + 32 + 64 {
        return Err(Malformed("malformed session binding"));
    }
    let pk: [u8; 32] = tlv.value[1..33].try_into().unwrap();
    let body = verify_signed(tlv, &pk)?;
    if body[0] != 1 || &body[33..65] != nh {
        return Err(Crypto("session binding belongs to another transcript"));
    }
    Ok(pk)
}

/// Canonical session descriptor with defaults matching the reference (no registries).
#[derive(Clone, Debug)]
pub struct Descriptor {
    pub profile: u8,
    pub sf_level: u8,
    pub dp_level: u8,
    pub w_back: u16,
    pub w_fwd: u16,
    pub max_payload_len: u32,
    pub clock_tolerance_ms: u32,
}

impl Default for Descriptor {
    fn default() -> Self {
        Descriptor {
            profile: 1,
            sf_level: 0,
            dp_level: 0,
            w_back: 1024,
            w_fwd: 128,
            max_payload_len: 1 << 20,
            clock_tolerance_ms: 2000,
        }
    }
}

impl Descriptor {
    pub fn encode(&self) -> Vec<u8> {
        let mut v = vec![
            1u8,
            self.profile,
            self.sf_level,
            0, /* deterministic nonces */
            0, /* classical */
            self.dp_level,
        ];
        v.extend_from_slice(&self.w_back.to_be_bytes());
        v.extend_from_slice(&self.w_fwd.to_be_bytes());
        for _ in 0..4 {
            v.extend_from_slice(&0u32.to_be_bytes()); // declared rates
        }
        v.extend_from_slice(&self.max_payload_len.to_be_bytes());
        v.extend_from_slice(&self.clock_tolerance_ms.to_be_bytes());
        v.push(0); // no registries
        v.extend_from_slice(&[0u8; 6]); // decoder_policy: STRICT_REFUSE for all six types
        v
    }

    pub fn tlv(&self) -> Vec<u8> {
        encode(&Tlv {
            code: 0x80,
            value: self.encode(),
        })
    }
}

pub struct SenderCapability {
    pub capability_id: [u8; 16],
    pub types_allowed: u16,
    pub max_segments: u64,
    pub valid_until_ns: u64,
    pub audience: [u8; 32],
    pub nonce: [u8; 16],
}

impl SenderCapability {
    /// ``>B16sHBQfQB32s32s16s`` — 121 bytes before the signature (V13 section 11).
    pub fn sign(&self, issuer: &SigningKey) -> Tlv {
        let mut b = vec![1u8];
        b.extend_from_slice(&self.capability_id);
        b.extend_from_slice(&self.types_allowed.to_be_bytes());
        b.push(0); // rights: none (NO_REPLAY, NO_STORE on the wire)
        b.extend_from_slice(&self.max_segments.to_be_bytes());
        b.extend_from_slice(&0f32.to_be_bytes()); // dp_epsilon_ceiling
        b.extend_from_slice(&self.valid_until_ns.to_be_bytes());
        b.push(0); // audience_mode = recipient public key
        b.extend_from_slice(&self.audience);
        b.extend_from_slice(&issuer.verifying_key().to_bytes());
        b.extend_from_slice(&self.nonce);
        debug_assert_eq!(b.len(), 121);
        sign_tlv(0x22, &b, issuer)
    }
}

/// Receiver capability (0x21) accepting ``types`` with per-type norm caps; no EMO -> no valence bounds.
pub fn receiver_capability(
    receiver: &SigningKey,
    types: u16,
    max_norm: f32,
    valid: (u64, u64),
    nonce: [u8; 16],
    nh: &[u8; 32],
) -> Tlv {
    let n = types.count_ones() as u8;
    let mut b = vec![1u8];
    b.extend_from_slice(&types.to_be_bytes());
    b.push(n);
    for _ in 0..n {
        b.extend_from_slice(&max_norm.to_be_bytes());
    }
    if types & (1 << 2) != 0 {
        b.extend_from_slice(&(-1f32).to_be_bytes());
        b.extend_from_slice(&1f32.to_be_bytes());
    }
    b.extend_from_slice(&1000u16.to_be_bytes()); // rate limit
    b.extend_from_slice(&valid.0.to_be_bytes());
    b.extend_from_slice(&valid.1.to_be_bytes());
    b.extend_from_slice(&nonce);
    b.extend_from_slice(&receiver.verifying_key().to_bytes());
    b.extend_from_slice(nh);
    sign_tlv(0x21, &b, receiver)
}

/// Fields of a verified sender capability the Rust receiver enforces.
pub struct VerifiedSenderCap {
    pub capability_id: [u8; 16],
    pub types_allowed: u16,
    pub audience: [u8; 32],
    pub issuer: [u8; 32],
    pub valid_until_ns: u64,
}

pub fn verify_sender_capability(tlv: &Tlv) -> Result<VerifiedSenderCap> {
    if tlv.code != 0x22 || tlv.value.len() != 121 + 64 {
        return Err(Malformed("malformed sender capability"));
    }
    // version(0) id(1..17) types(17..19) rights(19) max_segments(20..28) eps(28..32)
    // valid_until(32..40) audience_mode(40) audience(41..73) issuer(73..105) nonce(105..121)
    let issuer: [u8; 32] = tlv.value[73..105].try_into().unwrap();
    let b = verify_signed(tlv, &issuer)?;
    if b[0] != 1 || b[19] & !0x03 != 0 || b[40] != 0 {
        return Err(Malformed("unsupported capability fields"));
    }
    Ok(VerifiedSenderCap {
        capability_id: b[1..17].try_into().unwrap(),
        types_allowed: u16::from_be_bytes([b[17], b[18]]),
        valid_until_ns: u64::from_be_bytes(b[32..40].try_into().unwrap()),
        audience: b[41..73].try_into().unwrap(),
        issuer,
    })
}

/// Capability-scope revocation intent (0x23, ``>B16s16sQBB32s32s`` + sig): withdraw consent.
pub fn revocation_intent(capability_id: [u8; 16], issuer: &SigningKey) -> Tlv {
    let pk = issuer.verifying_key().to_bytes();
    let mut b = vec![1u8];
    b.extend_from_slice(&capability_id);
    b.extend_from_slice(&[0u8; 16]); // timeline all-zero => capability scope
    b.extend_from_slice(&0u64.to_be_bytes()); // revoke_from_seq (ignored for capability scope)
    b.push(1); // reason CONSENT_WITHDRAWN
    b.push(1); // effects REVOKE_FUTURE_USE
    b.extend_from_slice(&pk); // capability_issuer_pk
    b.extend_from_slice(&pk); // signer_pk
    debug_assert_eq!(b.len(), 107);
    sign_tlv(0x23, &b, issuer)
}

/// Verify a revocation against the accepted capability; returns the revoked capability id.
pub fn verify_revocation(tlv: &Tlv, cap: &VerifiedSenderCap) -> Result<[u8; 16]> {
    if tlv.code != 0x23 || tlv.value.len() != 107 + 64 {
        return Err(Malformed("malformed revocation intent"));
    }
    let signer: [u8; 32] = tlv.value[75..107].try_into().unwrap();
    let body = verify_signed(tlv, &signer)?;
    let cid: [u8; 16] = body[1..17].try_into().unwrap();
    let issuer: [u8; 32] = body[43..75].try_into().unwrap();
    if body[0] != 1 || cid != cap.capability_id || issuer != cap.issuer || signer != cap.issuer {
        return Err(Crypto(
            "revocation does not match the capability or its issuer",
        ));
    }
    Ok(cid)
}
