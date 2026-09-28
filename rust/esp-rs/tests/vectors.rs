// SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! WP-040: the Rust codec against the shared conformance vectors (`vectors/`).

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use esp_rs::crypto::{open, seal, DirectionKeys};
use esp_rs::header::{Header, HEADER_LEN};
use esp_rs::tlv::{decode_latent, encode_latent, split, Encoding};
use serde_json::Value;

fn vectors(rel: &str) -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../vectors")
        .join(rel);
    let doc: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    doc["vectors"].as_array().unwrap().clone()
}

fn hx(v: &Value) -> Vec<u8> {
    hex::decode(v.as_str().unwrap()).unwrap()
}

#[test]
fn valid_headers_roundtrip_byte_exact() {
    let vs = vectors("wire/header_valid.json");
    assert!(!vs.is_empty());
    for v in vs {
        let raw = hx(&v["hex"]);
        let h = Header::decode(&raw).unwrap_or_else(|e| panic!("{}: {e}", v["description"]));
        assert_eq!(h.encode().unwrap().to_vec(), raw);
        assert_eq!(
            h.types_bitmap as u64,
            v["fields"]["types_bitmap"].as_u64().unwrap()
        );
        assert_eq!(
            h.timestamp_ns,
            v["fields"]["timestamp_ns"].as_u64().unwrap()
        );
    }
}

#[test]
fn invalid_headers_are_rejected() {
    for v in vectors("malformed/header_invalid.json") {
        let raw = hx(&v["hex"]);
        assert!(
            Header::decode(&raw).is_err(),
            "{} must be rejected",
            v["name"]
        );
    }
}

#[test]
fn latents_decode_and_reencode() {
    for v in vectors("wire/latent_valid.json") {
        let raw = hx(&v["hex"]);
        let tlvs = split(&raw).unwrap();
        assert_eq!(tlvs.len(), 1);
        let lat = decode_latent(&tlvs[0]).unwrap_or_else(|e| panic!("{}: {e}", v["name"]));
        let enc = match v["encoding"].as_str().unwrap() {
            "F32_BE" => Encoding::F32Be,
            "F16_BE" => Encoding::F16Be,
            _ => Encoding::Int8Sym,
        };
        let input: Vec<f64> = v["input_values"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_f64().unwrap())
            .collect();
        let again = encode_latent(lat.type_index, &input, enc).unwrap();
        assert_eq!(esp_rs::tlv::encode(&again), raw, "{}", v["name"]);
    }
}

#[test]
fn invalid_latents_are_rejected() {
    for v in vectors("malformed/latent_invalid.json") {
        let raw = hx(&v["hex"]);
        let rejected = match split(&raw) {
            Err(_) => true,
            Ok(t) => t.len() != 1 || decode_latent(&t[0]).is_err(),
        };
        assert!(rejected, "{} must be rejected", v["name"]);
    }
}

#[test]
fn python_sealed_packet_opens_and_reseals_identically() {
    for v in vectors("crypto/packet_valid.json") {
        let k_split: [u8; 32] = hx(&v["k_split"]).try_into().unwrap();
        let keys = DirectionKeys::from_split_key(&k_split);
        assert_eq!(keys.aead.to_vec(), hx(&v["k_aead"]));
        assert_eq!(keys.nonce.to_vec(), hx(&v["k_nonce"]));
        let seed: [u8; 32] = hx(&v["ed25519_seed"]).try_into().unwrap();
        let signer = SigningKey::from_bytes(&seed);
        let packet = hx(&v["packet_hex"]);
        let (h, pt) = open(&packet, &keys, &signer.verifying_key().to_bytes(), 1 << 20).unwrap();
        assert_eq!(h.nonce, keys.nonce_for(&h.timeline_id, h.segment_seq));
        assert_eq!(h.nonce.to_vec(), hx(&v["nonce"]));
        // deterministic: Rust seals the same plaintext to the same bytes (Ed25519 is deterministic)
        let again = seal(&h, &pt, &keys, &signer).unwrap();
        assert_eq!(again, packet);
        let mut tampered = packet.clone();
        tampered[HEADER_LEN] ^= 1;
        assert!(open(
            &tampered,
            &keys,
            &signer.verifying_key().to_bytes(),
            1 << 20
        )
        .is_err());
    }
}
