// SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! TLVs (`code u8 · length u32 · value`) and typed latents 0x60..0x65 (V13 section 7).

use crate::{Result, WireError::Malformed};

pub const DIMS: [u16; 6] = [240, 64, 64, 64, 64, 16]; // KNO INT EMO CTX SEN TEM

#[derive(Debug, Clone, PartialEq)]
pub struct Tlv {
    pub code: u8,
    pub value: Vec<u8>,
}

pub fn split(data: &[u8]) -> Result<Vec<Tlv>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < data.len() {
        if data.len() - i < 5 {
            return Err(Malformed("TLV header truncated"));
        }
        let code = data[i];
        let len = u32::from_be_bytes(data[i + 1..i + 5].try_into().unwrap()) as usize;
        i += 5;
        if data.len() - i < len {
            return Err(Malformed("TLV value truncated"));
        }
        out.push(Tlv {
            code,
            value: data[i..i + len].to_vec(),
        });
        i += len;
        if out.len() > 1024 {
            return Err(Malformed("too many TLVs"));
        }
    }
    Ok(out)
}

pub fn encode(t: &Tlv) -> Vec<u8> {
    let mut v = Vec::with_capacity(5 + t.value.len());
    v.push(t.code);
    v.extend_from_slice(&(t.value.len() as u32).to_be_bytes());
    v.extend_from_slice(&t.value);
    v
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Encoding {
    F32Be = 0,
    F16Be = 1,
    Int8Sym = 2,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Latent {
    pub type_index: u8,
    pub encoding: Encoding,
    pub scale: f32,
    pub values: Vec<f64>,
}

pub fn decode_latent(t: &Tlv) -> Result<Latent> {
    if !(0x60..=0x65).contains(&t.code) {
        return Err(Malformed("not a typed-latent code"));
    }
    let ti = t.code - 0x60;
    let v = &t.value;
    if v.len() < 8 {
        return Err(Malformed("typed latent sub-header truncated"));
    }
    let encoding = match v[0] {
        0 => Encoding::F32Be,
        1 => Encoding::F16Be,
        2 => Encoding::Int8Sym,
        _ => return Err(Malformed("unknown latent encoding")),
    };
    if v[1] != 0 {
        return Err(Malformed("typed latent flags must be zero in v1"));
    }
    let dims = u16::from_be_bytes([v[2], v[3]]);
    if dims != DIMS[ti as usize] {
        return Err(Malformed("wrong latent dimension"));
    }
    let scale = f32::from_be_bytes(v[4..8].try_into().unwrap());
    let width = match encoding {
        Encoding::F32Be => 4,
        Encoding::F16Be => 2,
        Encoding::Int8Sym => 1,
    };
    let body = &v[8..];
    if body.len() != dims as usize * width {
        return Err(Malformed("typed latent body length mismatch"));
    }
    let values: Vec<f64> = match encoding {
        Encoding::F32Be => {
            if scale != 1.0 {
                return Err(Malformed("scale must be exactly 1.0 for float encodings"));
            }
            body.as_chunks::<4>()
                .0
                .iter()
                .map(|c| f32::from_be_bytes(*c) as f64)
                .collect()
        }
        Encoding::F16Be => {
            if scale != 1.0 {
                return Err(Malformed("scale must be exactly 1.0 for float encodings"));
            }
            body.as_chunks::<2>()
                .0
                .iter()
                .map(|c| half::f16::from_be_bytes(*c).to_f64())
                .collect()
        }
        Encoding::Int8Sym => {
            if !(scale.is_finite() && scale > 0.0) {
                return Err(Malformed("INT8_SYM scale must be finite and > 0"));
            }
            let mut out = Vec::with_capacity(body.len());
            for &byte in body {
                let q = byte as i8;
                if q == -128 {
                    return Err(Malformed("INT8_SYM byte -128 is invalid in v1"));
                }
                out.push(q as f64 * scale as f64);
            }
            out
        }
    };
    if values.iter().any(|x| !x.is_finite()) {
        return Err(Malformed("typed latent contains NaN or infinity"));
    }
    Ok(Latent {
        type_index: ti,
        encoding,
        scale,
        values,
    })
}

/// Encode with the V13 reference rules (F32/F16: `-0.0` -> `+0.0`; INT8: `s = max(max|x|/127, 2^-24)` in binary32, round half to even).
pub fn encode_latent(type_index: u8, values: &[f64], encoding: Encoding) -> Result<Tlv> {
    if type_index > 5 || values.len() != DIMS[type_index as usize] as usize {
        return Err(Malformed("wrong type or dimension"));
    }
    if values.iter().any(|x| !x.is_finite()) {
        return Err(Malformed("typed latent values must be finite"));
    }
    let mut v = vec![encoding as u8, 0];
    v.extend_from_slice(&(values.len() as u16).to_be_bytes());
    match encoding {
        Encoding::F32Be => {
            v.extend_from_slice(&1.0f32.to_be_bytes());
            for &x in values {
                let f = x as f32;
                if !f.is_finite() {
                    return Err(Malformed("value overflows F32_BE"));
                }
                v.extend_from_slice(&(if f == 0.0 { 0.0f32 } else { f }).to_be_bytes());
            }
        }
        Encoding::F16Be => {
            v.extend_from_slice(&1.0f32.to_be_bytes());
            for &x in values {
                let f = half::f16::from_f64(x);
                if !f.is_finite() {
                    return Err(Malformed("value overflows F16_BE"));
                }
                let f = if f.to_f64() == 0.0 {
                    half::f16::from_f64(0.0)
                } else {
                    f
                };
                v.extend_from_slice(&f.to_be_bytes());
            }
        }
        Encoding::Int8Sym => {
            let peak = values.iter().fold(0.0f64, |m, x| m.max(x.abs()));
            let s = ((peak / 127.0).max(2f64.powi(-24))) as f32;
            v.extend_from_slice(&s.to_be_bytes());
            for &x in values {
                let q = (x / s as f64).round_ties_even().clamp(-127.0, 127.0) as i8;
                v.push(q as u8);
            }
        }
    }
    Ok(Tlv {
        code: 0x60 + type_index,
        value: v,
    })
}
