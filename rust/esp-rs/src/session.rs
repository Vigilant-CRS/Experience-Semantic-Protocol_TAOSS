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
    /// The interop peer implements only classical SF0 without optional registries or DP.
    /// Unsupported descriptors fail closed instead of being silently ignored.
    pub fn decode(tlv: &Tlv) -> Result<Self> {
        let b = &tlv.value;
        if tlv.code != 0x80 || b.len() != 41 || b[..6] != [1, 1, 0, 0, 0, 0] || b[34..] != [0; 7] {
            return Err(Malformed("unsupported session descriptor"));
        }
        let d = Descriptor {
            profile: b[1],
            sf_level: b[2],
            dp_level: b[5],
            w_back: u16::from_be_bytes(b[6..8].try_into().unwrap()),
            w_fwd: u16::from_be_bytes(b[8..10].try_into().unwrap()),
            max_payload_len: u32::from_be_bytes(b[26..30].try_into().unwrap()),
            clock_tolerance_ms: u32::from_be_bytes(b[30..34].try_into().unwrap()),
        };
        if !(1024..=8192).contains(&d.w_back)
            || !(128..=8192).contains(&d.w_fwd)
            || d.max_payload_len == 0
        {
            return Err(Malformed("invalid descriptor limits"));
        }
        Ok(d)
    }

    pub fn negotiated(&self, peer: &Self) -> Self {
        Descriptor {
            max_payload_len: self.max_payload_len.min(peer.max_payload_len),
            clock_tolerance_ms: self.clock_tolerance_ms.min(peer.clock_tolerance_ms),
            w_back: self.w_back.min(peer.w_back),
            w_fwd: self.w_fwd.min(peer.w_fwd),
            ..self.clone()
        }
    }

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
    pub max_segments: u64,
    pub rights: u8,
    pub dp_epsilon_ceiling: f32,
}

pub fn verify_sender_capability(tlv: &Tlv) -> Result<VerifiedSenderCap> {
    if tlv.code != 0x22 || tlv.value.len() != 121 + 64 {
        return Err(Malformed("malformed sender capability"));
    }
    // version(0) id(1..17) types(17..19) rights(19) max_segments(20..28) eps(28..32)
    // valid_until(32..40) audience_mode(40) audience(41..73) issuer(73..105) nonce(105..121)
    let issuer: [u8; 32] = tlv.value[73..105].try_into().unwrap();
    let b = verify_signed(tlv, &issuer)?;
    let types = u16::from_be_bytes([b[17], b[18]]);
    let ceiling = f32::from_be_bytes(b[28..32].try_into().unwrap());
    if b[0] != 1
        || b[19] & !0x03 != 0
        || b[40] != 0
        || types & !0x3f != 0
        || !ceiling.is_finite()
        || ceiling < 0.0
    {
        return Err(Malformed("unsupported capability fields"));
    }
    Ok(VerifiedSenderCap {
        capability_id: b[1..17].try_into().unwrap(),
        max_segments: u64::from_be_bytes(b[20..28].try_into().unwrap()),
        rights: b[19],
        dp_epsilon_ceiling: ceiling,
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

/// Verified recipient consent used by the sender before sending any KNO data.
pub struct VerifiedReceiverCap {
    pub types: u16,
    pub kno_norm: f32,
    pub rate_limit_hz: u16,
    pub valid_from_ns: u64,
    pub valid_until_ns: u64,
}

pub fn verify_receiver_capability(
    tlv: &Tlv,
    identity: &[u8; 32],
    nh: &[u8; 32],
) -> Result<VerifiedReceiverCap> {
    if tlv.code != 0x21 || tlv.value.len() < 166 {
        return Err(Malformed("malformed receiver capability"));
    }
    let b = verify_signed(tlv, identity)?;
    let types = u16::from_be_bytes([b[1], b[2]]);
    let n = b[3] as usize;
    let end_norms = 4 + n * 4;
    let off = end_norms + if types & 4 != 0 { 8 } else { 0 };
    if b[0] != 1 || types & !0x3f != 0 || n != types.count_ones() as usize || b.len() != off + 98 {
        return Err(Malformed("invalid receiver capability fields"));
    }
    for chunk in b[4..end_norms].as_chunks::<4>().0 {
        let norm = f32::from_be_bytes(*chunk);
        if !norm.is_finite() || norm < 0.0 {
            return Err(Malformed("invalid norm cap"));
        }
    }
    if types & 4 != 0 {
        let lo = f32::from_be_bytes(b[end_norms..end_norms + 4].try_into().unwrap());
        let hi = f32::from_be_bytes(b[end_norms + 4..off].try_into().unwrap());
        if !lo.is_finite() || !hi.is_finite() || lo < -1.0 || hi > 1.0 || lo > hi {
            return Err(Malformed("invalid valence bounds"));
        }
    }
    if &b[off + 34..off + 66] != identity || &b[off + 66..off + 98] != nh {
        return Err(Crypto("receiver consent identity/transcript mismatch"));
    }
    let result = VerifiedReceiverCap {
        types,
        kno_norm: if types & 1 != 0 {
            f32::from_be_bytes(b[4..8].try_into().unwrap())
        } else {
            0.0
        },
        rate_limit_hz: u16::from_be_bytes(b[off..off + 2].try_into().unwrap()),
        valid_from_ns: u64::from_be_bytes(b[off + 2..off + 10].try_into().unwrap()),
        valid_until_ns: u64::from_be_bytes(b[off + 10..off + 18].try_into().unwrap()),
    };
    if result.valid_from_ns > result.valid_until_ns {
        return Err(Malformed("invalid consent interval"));
    }
    Ok(result)
}

/// Fail-closed data predicate for the deliberately limited KNO / DP-NONE interop profile.
pub fn check_kno_packet(
    cap: &VerifiedSenderCap,
    desc: &Descriptor,
    h: &crate::header::Header,
    payload: &[u8],
    now_ns: u64,
    accepted: u64,
) -> Result<f64> {
    if h.profile != desc.profile
        || h.sf_level != desc.sf_level
        || h.privacy_flags & 0x0f != 0
        || h.types_bitmap != 1
        || cap.types_allowed & 1 == 0
        || cap
            .valid_until_ns
            .saturating_add(desc.clock_tolerance_ms as u64 * 1_000_000)
            < now_ns
        || accepted >= cap.max_segments
    {
        return Err(Malformed("packet outside negotiated consent"));
    }
    if (cap.rights & 1 == 0 && h.consent_flags & 2 == 0)
        || (cap.rights & 2 == 0 && h.consent_flags & 4 == 0)
    {
        return Err(Malformed("packet requests rights not granted"));
    }
    let tlvs = crate::tlv::split(payload)?;
    // This peer cannot interpret optional semantics; no unknown payload can be accepted as KNO.
    if tlvs.len() != 1 || tlvs[0].code != 0x60 {
        return Err(Malformed("unsupported KNO payload"));
    }
    let latent = crate::tlv::decode_latent(&tlvs[0])?;
    if (latent.encoding == crate::tlv::Encoding::Int8Sym) != (h.privacy_flags & 0x10 != 0) {
        return Err(Malformed("quantization flag mismatch"));
    }
    let norm = latent.values.iter().map(|x| x * x).sum::<f64>().sqrt();
    if !norm.is_finite() || norm > 1000.0 {
        return Err(Malformed("receiver norm cap exceeded"));
    }
    Ok(norm)
}

#[cfg(test)]
mod tests {
    //! Negative consent cases of the limited interop profile (2026-09-29 review, F14).
    use super::*;
    use crate::header::Header;
    use crate::tlv::{encode, encode_latent, Encoding};

    const NOW: u64 = 1_000_000_000_000;

    fn cap() -> VerifiedSenderCap {
        VerifiedSenderCap {
            capability_id: [7; 16],
            types_allowed: 0x3f,
            audience: [1; 32],
            issuer: [2; 32],
            valid_until_ns: NOW + 1_000_000_000,
            max_segments: 3,
            rights: 0,
            dp_epsilon_ceiling: 0.0,
        }
    }

    fn header() -> Header {
        Header {
            version_minor: 0,
            profile: 1,
            sf_level: 0,
            types_bitmap: 1,
            consent_flags: 0x06, // NO_REPLAY | NO_STORAGE: nothing beyond the grant
            privacy_flags: 0,
            capabilities: 0,
            timestamp_ns: NOW,
            timeline_id: [3; 16],
            segment_seq: 0,
            dt_ms: 20,
            phase: 0.0,
            sender_id: [4; 32],
            payload_len: 0,
            nonce: [0; 12],
        }
    }

    fn kno(scale: f64) -> Vec<u8> {
        let values: Vec<f64> = (0..240).map(|i| scale * ((i % 7) as f64 - 3.0)).collect();
        encode(&encode_latent(0, &values, Encoding::F32Be).unwrap())
    }

    fn check(cap: &VerifiedSenderCap, h: &Header, payload: &[u8], accepted: u64) -> bool {
        check_kno_packet(cap, &Descriptor::default(), h, payload, NOW, accepted).is_ok()
    }

    #[test]
    fn valid_kno_packet_is_accepted() {
        assert!(check(&cap(), &header(), &kno(0.01), 0));
    }

    #[test]
    fn max_segments_is_enforced() {
        assert!(check(&cap(), &header(), &kno(0.01), 2));
        assert!(!check(&cap(), &header(), &kno(0.01), 3));
    }

    #[test]
    fn expired_capability_is_refused_per_packet() {
        let mut c = cap();
        c.valid_until_ns = NOW - 3_000_000_000; // beyond the 2 s clock tolerance
        assert!(!check(&c, &header(), &kno(0.01), 0));
    }

    #[test]
    fn profile_and_sf_level_must_match_the_session() {
        let mut h = header();
        h.profile = 2;
        assert!(!check(&cap(), &h, &kno(0.01), 0));
        let mut h = header();
        h.sf_level = 7;
        assert!(!check(&cap(), &h, &kno(0.01), 0));
    }

    #[test]
    fn types_outside_the_grant_are_refused() {
        let mut c = cap();
        c.types_allowed = 0x3e; // no KNO
        assert!(!check(&c, &header(), &kno(0.01), 0));
        let mut h = header();
        h.types_bitmap = 0x05; // KNO + EMO: this peer only accepts KNO
        assert!(!check(&cap(), &h, &kno(0.01), 0));
    }

    #[test]
    fn rights_not_granted_are_refused() {
        let mut h = header();
        h.consent_flags = 0; // packet would allow replay and storage
        assert!(!check(&cap(), &h, &kno(0.01), 0));
    }

    #[test]
    fn norm_cap_is_enforced() {
        assert!(!check(&cap(), &header(), &kno(1000.0), 0));
    }

    #[test]
    fn foreign_payload_is_refused() {
        let other = encode(&encode_latent(2, &[0.1; 64], Encoding::F32Be).unwrap());
        assert!(!check(&cap(), &header(), &other, 0));
    }
}
