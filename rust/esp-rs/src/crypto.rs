// SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Traffic keys, deterministic nonces (ADR-0009) and the packet envelope (V13 section 9.2):
//! `header(100) || ciphertext || tag(16) || Ed25519(header || ciphertext || tag)`.

use blake2::digest::consts::{U32, U8};
use blake2::digest::{Mac, Update, VariableOutput};
use blake2::{Blake2bMac, Blake2bVar};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce, Tag};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

use crate::header::{Header, HEADER_LEN, OVERHEAD, SIG_LEN, TAG_LEN};
use crate::{
    Result,
    WireError::{Crypto, Malformed},
};

fn keyed32(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut mac = <Blake2bMac<U32> as Mac>::new_from_slice(key).expect("key length <= 64");
    Mac::update(&mut mac, data);
    mac.finalize().into_bytes().into()
}

fn keyed8(key: &[u8], data: &[u8]) -> [u8; 8] {
    let mut mac = <Blake2bMac<U8> as Mac>::new_from_slice(key).expect("key length <= 64");
    Mac::update(&mut mac, data);
    mac.finalize().into_bytes().into()
}

pub fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut h = Blake2bVar::new(32).expect("valid size");
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_variable(&mut out).expect("size matches");
    out
}

#[derive(Clone)]
pub struct DirectionKeys {
    pub aead: [u8; 32],
    pub nonce: [u8; 32],
}

impl DirectionKeys {
    pub fn from_split_key(k_split: &[u8; 32]) -> Self {
        DirectionKeys {
            aead: keyed32(k_split, b"esp/v1/aead-key"),
            nonce: keyed32(k_split, b"esp/v1/nonce-key"),
        }
    }

    pub fn nonce_for(&self, timeline_id: &[u8; 16], segment_seq: u32) -> [u8; 12] {
        let mut data = b"esp/v1/timeline-tag".to_vec();
        data.extend_from_slice(timeline_id);
        let tag = keyed8(&self.nonce, &data);
        let mut n = [0u8; 12];
        n[..8].copy_from_slice(&tag);
        n[8..].copy_from_slice(&segment_seq.to_be_bytes());
        n
    }
}

pub fn seal(
    header: &Header,
    plaintext: &[u8],
    keys: &DirectionKeys,
    signer: &SigningKey,
) -> Result<Vec<u8>> {
    if header.sender_id != signer.verifying_key().to_bytes() {
        return Err(Crypto(
            "header sender_id must equal the session signing key",
        ));
    }
    let mut h = header.clone();
    h.payload_len = plaintext.len() as u32;
    let raw = h.encode()?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.aead));
    let mut body = plaintext.to_vec();
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(&h.nonce), &raw, &mut body)
        .map_err(|_| Crypto("aead failure"))?;
    let mut packet = raw.to_vec();
    packet.extend_from_slice(&body);
    packet.extend_from_slice(&tag);
    let sig = signer.sign(&packet);
    packet.extend_from_slice(&sig.to_bytes());
    Ok(packet)
}

pub fn open(
    packet: &[u8],
    keys: &DirectionKeys,
    expected_sender: &[u8; 32],
    max_payload: usize,
) -> Result<(Header, Vec<u8>)> {
    if packet.len() < OVERHEAD {
        return Err(Malformed("packet shorter than the fixed overhead"));
    }
    if packet.len() > OVERHEAD + max_payload {
        return Err(Malformed("packet exceeds max_payload_len"));
    }
    let h = Header::decode(&packet[..HEADER_LEN])?;
    if h.payload_len as usize > max_payload || packet.len() != OVERHEAD + h.payload_len as usize {
        return Err(Malformed("packet length does not match payload_len"));
    }
    if &h.sender_id != expected_sender {
        return Err(Crypto("unexpected sender"));
    }
    let end = HEADER_LEN + h.payload_len as usize;
    let vk = VerifyingKey::from_bytes(&h.sender_id).map_err(|_| Crypto("bad sender key"))?;
    let sig = Signature::from_bytes(
        packet[end + TAG_LEN..]
            .try_into()
            .map_err(|_| Malformed("bad signature length"))?,
    );
    debug_assert_eq!(packet.len() - end - TAG_LEN, SIG_LEN);
    vk.verify_strict(&packet[..end + TAG_LEN], &sig)
        .map_err(|_| Crypto("signature invalid"))?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&keys.aead));
    let mut body = packet[HEADER_LEN..end].to_vec();
    cipher
        .decrypt_in_place_detached(
            Nonce::from_slice(&h.nonce),
            &packet[..HEADER_LEN],
            &mut body,
            Tag::from_slice(&packet[end..end + TAG_LEN]),
        )
        .map_err(|_| Crypto("aead authentication failed"))?;
    Ok((h, body))
}
