// SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! `esp-rs` — interop peer for the Python reference (WP-041/042).
//!
//! Framing on TCP (test transport): `len u32 BE · channel u8 · data`, channel
//! 0 = CONTROL, 1 = STATE. Keys are passed as hex; output is JSON lines.
//!
//! ```text
//! esp-rs send    --addr H:P --responder-static HEX --receiver-id HEX --master-seed HEX --static-seed HEX --frames N
//! esp-rs receive --addr H:P --static-seed HEX --identity-seed HEX --trusted HEX --frames N
//! esp-rs neural-sim [--blocks N] [--samples M] [--seed S] [--break MODE]
//! ```
//!
//! `neural-sim` prints a neural adapter transcript as JSON lines (info, blocks,
//! verdict of the Rust contract checker) for the conformance cross-check (WP-090).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use esp_rs::crypto::{open, seal, DirectionKeys};
use esp_rs::header::Header;
use esp_rs::session::*;
use esp_rs::tlv::{self, encode_latent, split, Encoding, Tlv};
use rand_core::OsRng;

type Res<T> = Result<T, Box<dyn std::error::Error>>;

fn args() -> HashMap<String, String> {
    let a: Vec<String> = std::env::args().collect();
    let mut m = HashMap::new();
    m.insert("cmd".into(), a.get(1).cloned().unwrap_or_default());
    let mut i = 2;
    while i + 1 < a.len() {
        m.insert(a[i].trim_start_matches("--").to_string(), a[i + 1].clone());
        i += 2;
    }
    m
}

fn key32(m: &HashMap<String, String>, k: &str) -> Res<[u8; 32]> {
    let v = hex::decode(m.get(k).ok_or(format!("missing --{k}"))?)?;
    Ok(v.try_into()
        .map_err(|_| format!("--{k} must be 32 bytes"))?)
}

fn send_frame(s: &mut TcpStream, channel: u8, data: &[u8]) -> Res<()> {
    s.write_all(&((data.len() + 1) as u32).to_be_bytes())?;
    s.write_all(&[channel])?;
    s.write_all(data)?;
    Ok(())
}

fn recv_frame(s: &mut TcpStream) -> Res<(u8, Vec<u8>)> {
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > (1 << 20) + 4096 {
        return Err("bad frame length".into());
    }
    let mut buf = vec![0u8; n];
    s.read_exact(&mut buf)?;
    Ok((buf[0], buf[1..].to_vec()))
}

fn now_ns() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
}

fn tlv_with(tlvs: &[Tlv], code: u8) -> Res<Tlv> {
    Ok(tlvs
        .iter()
        .find(|t| t.code == code)
        .cloned()
        .ok_or(format!("TLV 0x{code:02x} missing"))?)
}

fn uuid4(seed: &[u8]) -> [u8; 16] {
    let mut id: [u8; 16] = esp_rs::crypto::blake2b256(seed)[..16].try_into().unwrap();
    id[6] = (id[6] & 0x0f) | 0x40;
    id[8] = (id[8] & 0x3f) | 0x80;
    id
}

fn sender(m: &HashMap<String, String>) -> Res<()> {
    let master = SigningKey::from_bytes(&key32(m, "master-seed")?);
    let receiver_id = key32(m, "receiver-id")?;
    let frames: u32 = m.get("frames").map_or(Ok(3), |v| v.parse())?;
    let mut stream = TcpStream::connect(m.get("addr").ok_or("missing --addr")?)?;
    let mut hs = snow::Builder::new(PROTOCOL.parse()?)
        .local_private_key(&key32(m, "static-seed")?)
        .remote_public_key(&key32(m, "responder-static")?)
        .prologue(PROLOGUE)
        .build_initiator()?;
    let mut buf = vec![0u8; 65535];
    let n = hs.write_message(&Descriptor::default().tlv(), &mut buf)?;
    send_frame(&mut stream, 0, &buf[..n])?;
    let (_, hs2) = recv_frame(&mut stream)?;
    let mut payload = vec![0u8; 65535];
    let n = hs.read_message(&hs2, &mut payload)?;
    let peer_desc = tlv_with(&split(&payload[..n])?, 0x80)?;
    let negotiated = Descriptor::default().negotiated(&Descriptor::decode(&peer_desc)?);
    let nh = noise_h(hs.get_handshake_hash());
    let (k_i2r, _) = hs.dangerously_get_raw_split();
    let mut transport = hs.into_transport_mode()?;
    let (_, t1) = recv_frame(&mut stream)?;
    let n = transport.read_message(&t1, &mut payload)?;
    let t1_tlvs = split(&payload[..n])?;
    let receiver_session = verify_session_binding(&tlv_with(&t1_tlvs, 0x85)?, &nh)?;
    let receiver_cap = verify_receiver_capability(&tlv_with(&t1_tlvs, 0x21)?, &receiver_id, &nh)?;
    if receiver_cap.types & 1 == 0 || receiver_cap.rate_limit_hz == 0 {
        return Err("receiver has not consented to KNO data".into());
    }
    let session = SigningKey::generate(&mut OsRng); // fresh per session
    let cap = SenderCapability {
        capability_id: uuid4(&nh),
        types_allowed: 0x3F,
        max_segments: 1000,
        valid_until_ns: now_ns() + 3_600_000_000_000,
        audience: receiver_id,
        nonce: nh[..16].try_into().unwrap(),
    };
    let mut t2 = tlv::encode(&session_binding(&session, &nh));
    t2.extend(tlv::encode(&cap.sign(&master)));
    let n = transport.write_message(&t2, &mut buf)?;
    send_frame(&mut stream, 0, &buf[..n])?;
    let keys = DirectionKeys::from_split_key(&k_i2r);
    let timeline = uuid4(&[nh.as_slice(), b"timeline"].concat());
    let revoke_after: Option<u32> = m.get("revoke-after").map(|v| v.parse()).transpose()?;
    let ignore_revocation = m.get("ignore-revocation").is_some_and(|v| v == "yes");
    let mut seq = 0u32;
    let mut sent = 0u32;
    let header_for = |seq: u32, types: u16| Header {
        version_minor: 0,
        profile: 1,
        sf_level: 0,
        types_bitmap: types,
        consent_flags: 0b110,
        privacy_flags: 0,
        capabilities: 0,
        timestamp_ns: now_ns(),
        timeline_id: timeline,
        segment_seq: seq,
        dt_ms: 0,
        phase: 0.0,
        sender_id: session.verifying_key().to_bytes(),
        payload_len: 0,
        nonce: keys.nonce_for(&timeline, seq),
    };
    let mut revoked = false;
    while sent < frames {
        if revoke_after == Some(sent) && !revoked {
            let body = tlv::encode(&revocation_intent(cap.capability_id, &master));
            send_frame(
                &mut stream,
                0,
                &seal(&header_for(seq, 0), &body, &keys, &session)?,
            )?;
            seq += 1;
            revoked = true;
            if !ignore_revocation {
                break; // an honest sender stops after withdrawing consent
            }
        }
        let values: Vec<f64> = (0..240)
            .map(|i| ((i as f64 + seq as f64) * 0.37).sin())
            .collect();
        let body = tlv::encode(&encode_latent(0, &values, Encoding::F32Be)?);
        let now = now_ns();
        if now < receiver_cap.valid_from_ns
            || now > receiver_cap.valid_until_ns
            || now > cap.valid_until_ns
            || u64::from(sent) >= cap.max_segments
            || values.iter().map(|x| x * x).sum::<f64>().sqrt() > f64::from(receiver_cap.kno_norm)
            || body.len() > negotiated.max_payload_len as usize
        {
            return Err("frame exceeds consent or negotiated limits".into());
        }
        std::thread::sleep(std::time::Duration::from_secs_f64(
            1.0 / f64::from(receiver_cap.rate_limit_hz),
        ));
        send_frame(
            &mut stream,
            1,
            &seal(&header_for(seq, 1), &body, &keys, &session)?,
        )?;
        seq += 1;
        sent += 1;
    }
    println!(
        "{}",
        serde_json::json!({"event": "sent", "frames": sent, "revoked": revoked, "noise_h": hex::encode(nh),
            "receiver_session": hex::encode(receiver_session), "receiver_capability": true,
            "peer_descriptor_len": peer_desc.value.len()})
    );
    Ok(())
}

fn receiver(m: &HashMap<String, String>) -> Res<()> {
    let identity = SigningKey::from_bytes(&key32(m, "identity-seed")?);
    let trusted = key32(m, "trusted")?;
    let frames: u32 = m.get("frames").map_or(Ok(3), |v| v.parse())?;
    let listener = TcpListener::bind(m.get("addr").ok_or("missing --addr")?)?;
    println!(
        "{}",
        serde_json::json!({"event": "listening", "port": listener.local_addr()?.port()})
    );
    std::io::stdout().flush()?;
    let (mut stream, _) = listener.accept()?;
    let mut hs = snow::Builder::new(PROTOCOL.parse()?)
        .local_private_key(&key32(m, "static-seed")?)
        .prologue(PROLOGUE)
        .build_responder()?;
    let mut payload = vec![0u8; 65535];
    let mut buf = vec![0u8; 65535];
    let (_, hs1) = recv_frame(&mut stream)?;
    let n = hs.read_message(&hs1, &mut payload)?;
    let negotiated = Descriptor::default().negotiated(&Descriptor::decode(&tlv_with(
        &split(&payload[..n])?,
        0x80,
    )?)?);
    let n = hs.write_message(&Descriptor::default().tlv(), &mut buf)?;
    send_frame(&mut stream, 0, &buf[..n])?;
    let nh = noise_h(hs.get_handshake_hash());
    let (k_i2r, _) = hs.dangerously_get_raw_split();
    let mut transport = hs.into_transport_mode()?;
    let session = SigningKey::generate(&mut OsRng);
    let now = now_ns();
    let mut t1 = tlv::encode(&session_binding(&session, &nh));
    t1.extend(tlv::encode(&receiver_capability(
        &identity,
        0x01,
        1000.0,
        (0, now + 3_600_000_000_000),
        nh[..16].try_into().unwrap(),
        &nh,
    )));
    let n = transport.write_message(&t1, &mut buf)?;
    send_frame(&mut stream, 0, &buf[..n])?;
    let (_, t2) = recv_frame(&mut stream)?;
    let n = transport.read_message(&t2, &mut payload)?;
    let tlvs = split(&payload[..n])?;
    let peer = verify_session_binding(&tlv_with(&tlvs, 0x85)?, &nh)?;
    let cap = verify_sender_capability(&tlv_with(&tlvs, 0x22)?)?;
    if cap.issuer != trusted
        || cap.audience != identity.verifying_key().to_bytes()
        || cap.valid_until_ns < now
    {
        return Err("sender capability not acceptable".into());
    }
    println!(
        "{}",
        serde_json::json!({"event": "active", "noise_h": hex::encode(nh), "capability": hex::encode(cap.capability_id)})
    );
    let keys = DirectionKeys::from_split_key(&k_i2r);
    let _ = frames;
    let mut accepted = 0u32;
    let mut revoked = false;
    let mut replay = std::collections::BTreeSet::new();
    let mut highest = 0u32;
    let mut timeline = None;
    let mut recent = std::collections::VecDeque::new();
    loop {
        let (channel, packet) = match recv_frame(&mut stream) {
            Ok(f) => f,
            Err(_) => break, // peer closed
        };
        let (h, pt) = open(&packet, &keys, &peer, negotiated.max_payload_len as usize)?;
        if h.profile != negotiated.profile
            || h.sf_level != negotiated.sf_level
            || h.privacy_flags & 0x0f != 0
            || timeline.is_some_and(|t| t != h.timeline_id)
        {
            return Err("packet does not match the negotiated session".into());
        }
        if replay.contains(&h.segment_seq)
            || h.segment_seq < highest.saturating_sub(negotiated.w_back as u32)
            || h.segment_seq > highest.saturating_add(negotiated.w_fwd as u32)
        {
            println!(
                "{}",
                serde_json::json!({"event": "rejected", "seq": h.segment_seq, "reason": "replay"})
            );
            continue;
        }
        if h.types_bitmap == 0 {
            let controls = split(&pt)?;
            for t in &controls {
                verify_revocation(t, &cap)?;
            }
            for t in controls {
                if t.code == 0x23 {
                    verify_revocation(&t, &cap)?;
                    revoked = true;
                    println!(
                        "{}",
                        serde_json::json!({"event": "revoked", "seq": h.segment_seq})
                    );
                }
            }
            replay.insert(h.segment_seq);
            highest = highest.max(h.segment_seq);
            replay.retain(|seq| *seq >= highest.saturating_sub(negotiated.w_back as u32));
            timeline = Some(h.timeline_id);
            continue;
        }
        if revoked {
            println!(
                "{}",
                serde_json::json!({"event": "rejected", "seq": h.segment_seq, "reason": "revoked"})
            );
            continue;
        }
        let received_at = now_ns();
        while recent
            .front()
            .is_some_and(|at| *at <= received_at.saturating_sub(1_000_000_000))
        {
            recent.pop_front();
        }
        let checked = check_kno_packet(&cap, &negotiated, &h, &pt, received_at, accepted.into());
        let norm = match checked {
            Ok(norm) if recent.len() < 1000 && received_at <= now + 3_600_000_000_000 => norm,
            _ => {
                println!(
                    "{}",
                    serde_json::json!({"event":"rejected", "seq":h.segment_seq, "reason":"consent"})
                );
                continue;
            }
        };
        replay.insert(h.segment_seq);
        highest = highest.max(h.segment_seq);
        replay.retain(|seq| *seq >= highest.saturating_sub(negotiated.w_back as u32));
        timeline = Some(h.timeline_id);
        recent.push_back(received_at);
        accepted += 1;
        println!(
            "{}",
            serde_json::json!({"event": "frame", "channel": channel, "seq": h.segment_seq, "types": 1, "norms": [norm]})
        );
    }
    println!(
        "{}",
        serde_json::json!({"event": "closed", "accepted": accepted, "revoked": revoked})
    );
    Ok(())
}

fn neural_sim(m: &HashMap<String, String>) -> Res<()> {
    use esp_rs::neural;
    let num = |k: &str, d: usize| -> Res<usize> {
        Ok(match m.get(k) {
            Some(v) => v.parse()?,
            None => d,
        })
    };
    let blocks = num("blocks", 4)?;
    let samples = num("samples", 64)?;
    let seed = num("seed", 1)? as u64;
    if samples < 6 {
        return Err("--samples must be at least 6".into());
    }
    let mode = m.get("break").map_or("none", String::as_str);
    let (info, items) = neural::transcript(mode, blocks, samples, seed).ok_or(format!(
        "unknown --break {mode}; one of {:?}",
        neural::BREAK_MODES
    ))?;
    let report = neural::check_transcript(&info, &items, samples);
    let mut out = std::io::stdout().lock();
    writeln!(out, "{}", neural::info_json(&info))?;
    for item in &items {
        writeln!(out, "{}", neural::item_json(item))?;
    }
    writeln!(out, "{}", neural::verdict_json(&report))?;
    Ok(())
}

/// `esp-rs mls --name <id>`: one long-lived MLS member (GAP-017, ADR-0021).
///
/// Reads one JSON request per stdin line and writes one JSON response per stdout line.
/// Keys and group state live only in this process; the caller relays opaque MLS
/// messages (hex) between members, like an untrusted delivery service.
///
/// Requests (`op`): `key_package`, `create`, `add {key_packages}`, `join {welcome}`,
/// `process {message}`, `remove {members}`, `update`, `export {label, context, length}`,
/// `state`. Every response has `ok` and, on success, the current `epoch`.
fn mls_member(m: &HashMap<String, String>) -> Res<()> {
    use esp_rs::mls::Member;
    use serde_json::{json, Value};
    use std::io::BufRead;
    let name = m.get("name").ok_or("missing --name")?;
    let mut member = Member::new(name)?;
    let stdin = std::io::stdin();
    let mut out = std::io::stdout();
    for line in stdin.lock().lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let reply = (|| -> Res<Value> {
            let req: Value = serde_json::from_str(&line)?;
            let op = req["op"].as_str().ok_or("missing op")?;
            let hexfield = |k: &str| -> Res<Vec<u8>> {
                Ok(hex::decode(req[k].as_str().ok_or(format!("missing {k}"))?)?)
            };
            let commit_json = |c: esp_rs::mls::CommitOut| {
                json!({"commit": hex::encode(c.commit),
                       "welcome": c.welcome.map(hex::encode), "epoch": c.epoch})
            };
            Ok(match op {
                "key_package" => json!({"key_package": hex::encode(member.key_package()?)}),
                "create" => json!({"epoch": member.create()?}),
                "add" => {
                    let kps = req["key_packages"]
                        .as_array()
                        .ok_or("missing key_packages")?
                        .iter()
                        .map(|v| hex::decode(v.as_str().unwrap_or_default()))
                        .collect::<Result<Vec<_>, _>>()?;
                    commit_json(member.add(&kps)?)
                }
                "join" => json!({"epoch": member.join(&hexfield("welcome")?)?}),
                "process" => json!({"epoch": member.process(&hexfield("message")?)?}),
                "remove" => {
                    let names = req["members"]
                        .as_array()
                        .ok_or("missing members")?
                        .iter()
                        .map(|v| v.as_str().unwrap_or_default().to_string())
                        .collect::<Vec<_>>();
                    commit_json(member.remove(&names)?)
                }
                "update" => commit_json(member.update()?),
                "export" => {
                    let label = req["label"].as_str().ok_or("missing label")?;
                    let length = req["length"].as_u64().ok_or("missing length")? as usize;
                    let secret = member.export(label, &hexfield("context")?, length)?;
                    json!({"secret": hex::encode(secret), "epoch": member.epoch()?})
                }
                "state" => json!({
                    "active": member.active(),
                    "epoch": member.epoch().ok(),
                    "members": member.members().unwrap_or_default(),
                }),
                _ => return Err(format!("unknown op {op}").into()),
            })
        })();
        let mut v = match reply {
            Ok(v) => v,
            Err(e) => json!({"ok": false, "error": e.to_string()}),
        };
        if v.get("ok").is_none() {
            v["ok"] = json!(true);
        }
        writeln!(out, "{v}")?;
        out.flush()?;
    }
    Ok(())
}

fn main() {
    let m = args();
    let result = match m["cmd"].as_str() {
        "send" => sender(&m),
        "receive" => receiver(&m),
        "neural-sim" => neural_sim(&m),
        "mls" => mls_member(&m),
        _ => Err("usage: esp-rs send|receive|neural-sim|mls ...".into()),
    };
    if let Err(e) = result {
        eprintln!("esp-rs: {e}");
        std::process::exit(1);
    }
}
