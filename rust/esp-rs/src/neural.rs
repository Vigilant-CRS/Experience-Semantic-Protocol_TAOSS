// SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! Neural vendor contract 1.0.0 (WP-090, M18), independent Rust implementation.
//!
//! Mirrors the Python SDK (`esp.neural_sdk`) rule for rule: a [`NeuralAdapter`]
//! yields neutral [`SampleBlock`]s (never emotions or intentions), and
//! [`check_transcript`] applies the same contract checks with the same rule
//! names. The conformance runner compares both checkers on the output of
//! `esp-rs neural-sim` (JSON lines, see `esp.neural_sdk.jsonl`).
//!
//! Invasive sources are admitted only as declared recordings (`L4-REPLAY`).
//! A C ABI for device drivers is future work; it is not part of contract 1.0.0.

use serde_json::{json, Value};

pub const CONTRACT_VERSION: &str = "1.0.0";

const NON_INVASIVE: &[&str] = &["eeg", "emg", "eye"];
const INVASIVE: &[&str] = &[
    "ecog",
    "seeg",
    "lfp",
    "mua",
    "spikes",
    "spike_counts",
    "neural_features",
];
const AUXILIARY: &[&str] = &["motion", "behavior", "event", "audio"];
const UNITS: &[&str] = &[
    "Hz",
    "bpm",
    "breaths_per_min",
    "s",
    "ms",
    "us",
    "ns",
    "S",
    "uS",
    "V",
    "mV",
    "uV",
    "K",
    "degC",
    "m",
    "mm",
    "m_per_s2",
    "g0",
    "rad_per_s",
    "Pa",
    "1",
    "percent",
    "px",
    "count",
];
const OPEN_LICENSES: &[&str] = &[
    "CC-BY-4.0",
    "CC0-1.0",
    "CC-BY-SA-4.0",
    "PDDL-1.0",
    "ODC-BY-1.0",
];
/// Words a channel name must never be (as a whole `_`/`.`/`-` separated token).
const INTERPRETIVE: &[&str] = &[
    "emo",
    "emotion",
    "affect",
    "mood",
    "valence",
    "arousal",
    "intensity",
    "intent",
    "intention",
    "joy",
    "trust",
    "fear",
    "surprise",
    "sadness",
    "anger",
    "disgust",
    "anticipation",
    "stress",
    "thought",
    "mind",
];

#[derive(Clone, Debug, PartialEq)]
pub struct ChannelSpec {
    pub name: String,
    pub modality: String,
    pub unit: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Device {
    pub device_id: String,
    pub kind: String,
    pub sampling_rate_hz: Option<f64>,
    pub synthetic: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    L3,
    L4,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Electrode {
    pub name: String,
    pub group: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct Descriptor {
    pub manufacturer: String,
    pub model: String,
    pub firmware: String,
    pub device_id: String,
    pub modalities: Vec<String>,
    pub electrodes: Vec<Electrode>,
    pub unit: String,
    pub clock_domain: String,
    pub sampling_rate_hz: Option<f64>,
    pub bin_width_s: Option<f64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct ReplayDeclaration {
    pub dataset_id: String,
    pub version: String,
    pub license: String,
    pub consent_basis: String,
    pub url: String,
}

#[derive(Clone, Debug, PartialEq)]
pub struct AdapterInfo {
    pub adapter_id: String,
    pub device: Device,
    pub channels: Vec<ChannelSpec>,
    pub nominal_rate_hz: f64,
    pub level: Level,
    pub clock_domain: String,
    pub descriptor: Option<Descriptor>,
    pub replay: Option<ReplayDeclaration>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SampleBlock {
    pub stream: String,
    pub channels: Vec<ChannelSpec>,
    pub device: Device,
    pub clock_domain: String,
    pub timestamps_ns: Vec<i64>,
    /// `values[sample][channel]`
    pub values: Vec<Vec<f64>>,
    pub nominal_rate_hz: Option<f64>,
}

/// A neural source. `read` returns the next block, or `None` at the end.
pub trait NeuralAdapter {
    fn info(&self) -> &AdapterInfo;
    fn start(&mut self);
    fn read(&mut self, max_samples: usize) -> Option<SampleBlock>;
    fn stop(&mut self);
}

/// One read as seen by the checker: a block, or anything else (malformed output).
#[derive(Clone, Debug, PartialEq)]
pub enum Item {
    Block(SampleBlock),
    Malformed(Value),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Violation {
    pub rule: String,
    pub detail: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct Report {
    pub blocks: usize,
    pub samples: usize,
    pub violations: Vec<Violation>,
}

impl Report {
    pub fn ok(&self) -> bool {
        self.violations.is_empty()
    }
}

fn v(rule: &str, detail: impl Into<String>) -> Violation {
    Violation {
        rule: rule.into(),
        detail: detail.into(),
    }
}

/// Same semantics as the Python regex `(^|[_.-])(word)($|[_.-])` on the lowercased name.
pub fn interpretive(name: &str) -> bool {
    name.to_lowercase()
        .split(['_', '.', '-'])
        .any(|tok| INTERPRETIVE.contains(&tok))
}

fn device_id_ok(id: &str) -> bool {
    let mut chars = id.chars();
    let first_ok = chars.next().is_some_and(|c| c.is_ascii_alphanumeric());
    let rest_ok = id.len() <= 128
        && id
            .chars()
            .skip(1)
            .all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c));
    let lower = id.to_lowercase();
    let serial = lower.contains("serial")
        || lower.contains("s/n")
        || lower.contains("sn:")
        || lower.contains("sn=");
    first_ok && rest_ok && !serial
}

/// Descriptor checks shared by every profile (rules as in `check_descriptor`).
pub fn check_descriptor(d: &Descriptor) -> Vec<Violation> {
    let mut out = Vec::new();
    if !device_id_ok(&d.device_id) {
        out.push(v(
            "device_id",
            "device id must be pseudonymous, not a serial",
        ));
    }
    let known = |m: &String| {
        NON_INVASIVE.contains(&m.as_str())
            || INVASIVE.contains(&m.as_str())
            || AUXILIARY.contains(&m.as_str())
    };
    if d.modalities.is_empty() || !d.modalities.iter().all(known) {
        out.push(v("modality", "unknown or empty modality set"));
    }
    if !UNITS.contains(&d.unit.as_str()) {
        out.push(v("unit", format!("unit {:?} is not normalized", d.unit)));
    }
    match (d.sampling_rate_hz, d.bin_width_s) {
        (Some(_), Some(_)) | (None, None) => out.push(v(
            "rate",
            "declare exactly one of sampling rate or bin width",
        )),
        (Some(r), None) if r <= 0.0 => out.push(v("rate", "rate must be positive")),
        (None, Some(b)) if b <= 0.0 => out.push(v("rate", "rate must be positive")),
        _ => {}
    }
    if d.electrodes.is_empty() {
        out.push(v("electrodes", "no electrodes declared"));
    }
    let mut names: Vec<&str> = d.electrodes.iter().map(|e| e.name.as_str()).collect();
    names.sort_unstable();
    if names.windows(2).any(|w| w[0] == w[1]) {
        out.push(v("electrodes", "electrode names must be unique"));
    }
    if d.clock_domain.is_empty() {
        out.push(v("clock", "clock domain required"));
    }
    out
}

fn invasive(d: &Descriptor) -> bool {
    d.modalities.iter().any(|m| INVASIVE.contains(&m.as_str()))
}

fn check_replay_profile(d: &Descriptor, r: &ReplayDeclaration) -> Vec<Violation> {
    let mut out = check_descriptor(d);
    if !OPEN_LICENSES.contains(&r.license.as_str()) {
        out.push(v("replay", format!("license {:?} not open", r.license)));
    }
    if r.consent_basis.trim().is_empty() {
        out.push(v("replay", "consent basis must be documented"));
    }
    if !r.url.starts_with("https://") || r.version.is_empty() {
        out.push(v("replay", "pinned https source and version needed"));
    }
    out
}

fn check_live_profile(d: &Descriptor, replay: Option<&ReplayDeclaration>) -> Vec<Violation> {
    let mut out = check_descriptor(d);
    if invasive(d) {
        out.push(v("profile", "invasive modalities need L4-REPLAY"));
    }
    if replay.is_some() {
        out.push(v("profile", "a replay declaration makes this L4-REPLAY"));
    }
    out
}

fn prefixed(prefix: &str, issues: Vec<Violation>) -> impl Iterator<Item = Violation> + '_ {
    issues.into_iter().map(move |i| Violation {
        rule: format!("{prefix}:{}", i.rule),
        detail: i.detail,
    })
}

/// Declaration checks (Python `_check_info`).
pub fn check_info(info: &AdapterInfo) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut invasive_allowed = false;
    match (info.level, &info.descriptor, &info.replay) {
        (Level::L4, Some(d), Some(r)) => {
            out.extend(prefixed("replay", check_replay_profile(d, r)));
            invasive_allowed = true;
        }
        (Level::L4, _, _) => out.push(v(
            "level",
            "live invasive (L4) sources have no v1 profile and are refused",
        )),
        (Level::L3, Some(d), r) => {
            out.extend(prefixed("descriptor", check_live_profile(d, r.as_ref())))
        }
        (Level::L3, None, _) => {}
    }
    if info.channels.is_empty() {
        out.push(v("channels", "no channels declared"));
    }
    if info.nominal_rate_hz.is_nan() || info.nominal_rate_hz <= 0.0 {
        out.push(v("rate", "nominal rate must be positive"));
    }
    for c in &info.channels {
        let m = c.modality.as_str();
        let allowed = NON_INVASIVE.contains(&m)
            || (invasive_allowed && (INVASIVE.contains(&m) || AUXILIARY.contains(&m)));
        if !allowed {
            out.push(v(
                "modality",
                format!("{}: {} is not a neural signal", c.name, m),
            ));
        }
        if !UNITS.contains(&c.unit.as_str()) {
            out.push(v(
                "unit",
                format!("{}: unit {:?} not normalized", c.name, c.unit),
            ));
        }
        if interpretive(&c.name) {
            out.push(v(
                "neutral",
                format!("channel {:?} names an interpretation", c.name),
            ));
        }
    }
    out
}

/// The full contract over a sequence of reads (Python `check_adapter_contract`).
pub fn check_transcript(info: &AdapterInfo, items: &[Item], max_samples: usize) -> Report {
    let mut report = Report {
        violations: check_info(info),
        ..Report::default()
    };
    let mut last: Option<i64> = None;
    for item in items {
        let b = match item {
            Item::Block(b) => b,
            Item::Malformed(_) => {
                report
                    .violations
                    .push(v("output", "read() returned a non-block"));
                break;
            }
        };
        report.blocks += 1;
        report.samples += b.timestamps_ns.len();
        if b.channels != info.channels {
            report
                .violations
                .push(v("channels", "block channels differ"));
        }
        if b.device != info.device || b.clock_domain != info.clock_domain {
            report
                .violations
                .push(v("identity", "device or clock domain differs"));
        }
        if b.timestamps_ns.len() > max_samples {
            report
                .violations
                .push(v("size", "block exceeds max_samples"));
        }
        let ts = &b.timestamps_ns;
        let inner = ts.windows(2).any(|w| w[1] <= w[0]);
        let across = matches!((last, ts.first()), (Some(l), Some(&f)) if f <= l);
        if inner || across {
            report
                .violations
                .push(v("clock", "timestamps not strictly increasing"));
        }
        if let Some(&t) = ts.last() {
            last = Some(t);
        }
    }
    if report.blocks == 0 {
        report
            .violations
            .push(v("output", "adapter produced no block"));
    }
    report
}

/// Run an adapter for up to `reads` reads and check the contract.
pub fn check_adapter(adapter: &mut dyn NeuralAdapter, reads: usize, max_samples: usize) -> Report {
    adapter.start();
    let mut items = Vec::new();
    for _ in 0..reads {
        match adapter.read(max_samples) {
            Some(b) => items.push(Item::Block(b)),
            None => break,
        }
    }
    adapter.stop();
    let info = adapter.info().clone();
    check_transcript(&info, &items, max_samples)
}

// --- simulator -----------------------------------------------------------------------------------

/// Deterministic synthetic source: EEG-like voltages (L3) or binned spike counts (L4-REPLAY).
pub struct Simulator {
    info: AdapterInfo,
    state: u64,
    seed: u64,
    pos: usize,
    total: usize,
    running: bool,
}

fn splitmix(state: &mut u64) -> f64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^= z >> 31;
    (z >> 11) as f64 / (1u64 << 53) as f64
}

pub fn l3_info(n_channels: usize, seed: u64) -> AdapterInfo {
    let names = ["fz", "cz", "pz", "oz", "f3", "f4", "p3", "p4"];
    AdapterInfo {
        adapter_id: format!("esp-rs-neural-sim-{seed}"),
        device: Device {
            device_id: format!("rs-sim-neural-{seed}"),
            kind: "neural-simulator".into(),
            sampling_rate_hz: Some(256.0),
            synthetic: true,
        },
        channels: names[..n_channels.min(names.len())]
            .iter()
            .map(|n| ChannelSpec {
                name: (*n).into(),
                modality: "eeg".into(),
                unit: "uV".into(),
            })
            .collect(),
        nominal_rate_hz: 256.0,
        level: Level::L3,
        clock_domain: format!("rs-sim-neural-{seed}:mono"),
        descriptor: None,
        replay: None,
    }
}

pub fn l4_replay_info(n_channels: usize, seed: u64) -> AdapterInfo {
    let electrodes: Vec<Electrode> = (0..n_channels)
        .map(|i| Electrode {
            name: format!("ch{i:03}"),
            group: "array-a".into(),
        })
        .collect();
    let clock = format!("rs-replay-{seed}:nwb");
    AdapterInfo {
        adapter_id: format!("esp-rs-replay-sim-{seed}"),
        device: Device {
            device_id: format!("rs-replay-{seed}"),
            kind: "intracortical-array".into(),
            sampling_rate_hz: Some(50.0),
            synthetic: true,
        },
        channels: electrodes
            .iter()
            .map(|e| ChannelSpec {
                name: e.name.clone(),
                modality: "spike_counts".into(),
                unit: "count".into(),
            })
            .collect(),
        nominal_rate_hz: 50.0,
        level: Level::L4,
        clock_domain: clock.clone(),
        descriptor: Some(Descriptor {
            manufacturer: "(synthetic)".into(),
            model: "array sim".into(),
            firmware: "n/a".into(),
            device_id: format!("rs-replay-{seed}"),
            modalities: vec!["spike_counts".into()],
            electrodes,
            unit: "count".into(),
            clock_domain: clock,
            sampling_rate_hz: None,
            bin_width_s: Some(0.02),
        }),
        replay: Some(ReplayDeclaration {
            dataset_id: "esp-rs:synthetic-spikes".into(),
            version: "1.0.0".into(),
            license: "CC0-1.0".into(),
            consent_basis: "synthetic data; no participant".into(),
            url: "https://example.org/esp-rs/synthetic-spikes".into(),
        }),
    }
}

impl Simulator {
    pub fn new(info: AdapterInfo, seed: u64, total_samples: usize) -> Self {
        Self {
            info,
            state: seed,
            seed,
            pos: 0,
            total: total_samples,
            running: false,
        }
    }
}

impl NeuralAdapter for Simulator {
    fn info(&self) -> &AdapterInfo {
        &self.info
    }

    fn start(&mut self) {
        self.running = true;
        self.pos = 0;
        self.state = self.seed;
    }

    fn read(&mut self, max_samples: usize) -> Option<SampleBlock> {
        assert!(self.running, "adapter not started");
        let n = max_samples.min(self.total - self.pos);
        if n == 0 {
            return None;
        }
        let rate = self.info.nominal_rate_hz;
        let spikes = self.info.level == Level::L4;
        let chans = self.info.channels.len();
        let mut timestamps_ns = Vec::with_capacity(n);
        let mut values = Vec::with_capacity(n);
        for i in self.pos..self.pos + n {
            timestamps_ns.push((i as f64 * (1e9 / rate)).round() as i64);
            let t = i as f64 / rate;
            let row = (0..chans)
                .map(|c| {
                    let u = splitmix(&mut self.state);
                    if spikes {
                        (u * 5.0).floor()
                    } else {
                        10.0 * (2.0 * std::f64::consts::PI * 10.0 * t + c as f64).sin()
                            + (u - 0.5) * 8.0
                    }
                })
                .collect();
            values.push(row);
        }
        self.pos += n;
        Some(SampleBlock {
            stream: self.info.adapter_id.clone(),
            channels: self.info.channels.clone(),
            device: self.info.device.clone(),
            clock_domain: self.info.clock_domain.clone(),
            timestamps_ns,
            values,
            nominal_rate_hz: Some(rate),
        })
    }

    fn stop(&mut self) {
        self.running = false;
    }
}

// --- break modes (for the cross-implementation conformance check) -------------------------------

pub const BREAK_MODES: &[&str] = &[
    "none",
    "l4-replay",
    "non-monotonic-clock",
    "interpretive-channel",
    "l4-live-undeclared",
    "channel-change",
    "identity-change",
    "oversize-block",
    "wrong-block-type",
    "bad-unit",
    "replay-closed-license",
];

/// A transcript for `mode`: declaration plus reads, deliberately broken in one way.
pub fn transcript(
    mode: &str,
    blocks: usize,
    samples: usize,
    seed: u64,
) -> Option<(AdapterInfo, Vec<Item>)> {
    if !BREAK_MODES.contains(&mode) {
        return None;
    }
    let mut info = match mode {
        "l4-replay" | "replay-closed-license" => l4_replay_info(4, seed),
        _ => l3_info(4, seed),
    };
    match mode {
        "interpretive-channel" => info.channels[0].name = "valence".into(),
        "l4-live-undeclared" => info.level = Level::L4,
        "bad-unit" => info
            .channels
            .iter_mut()
            .for_each(|c| c.unit = "microvolt".into()),
        "replay-closed-license" => {
            if let Some(r) = info.replay.as_mut() {
                r.license = "LicenseRef-proprietary".into();
            }
        }
        _ => {}
    }
    let mut sim = Simulator::new(info.clone(), seed, blocks * samples + samples + 1);
    sim.start();
    let mut items = Vec::new();
    for i in 0..blocks {
        let size = if mode == "oversize-block" && i == 1 {
            samples + 1
        } else {
            samples
        };
        let Some(mut b) = sim.read(size) else { break };
        if i == 1 {
            match mode {
                "non-monotonic-clock" => b.timestamps_ns[5] = b.timestamps_ns[4],
                "channel-change" => b.channels.swap(0, 1),
                "identity-change" => b.clock_domain = "other:mono".into(),
                "wrong-block-type" => {
                    items.push(Item::Malformed(json!({"type": "garbage"})));
                    continue;
                }
                _ => {}
            }
        }
        items.push(Item::Block(b));
    }
    sim.stop();
    Some((info, items))
}

// --- JSON lines (esp.neural_sdk.jsonl) ------------------------------------------------------------

fn channels_json(chs: &[ChannelSpec]) -> Value {
    Value::Array(
        chs.iter()
            .map(|c| json!({"name": c.name, "modality": c.modality, "unit": c.unit}))
            .collect(),
    )
}

fn device_json(d: &Device) -> Value {
    json!({
        "device_id": d.device_id,
        "kind": d.kind,
        "sampling_rate_hz": d.sampling_rate_hz,
        "synthetic": d.synthetic,
    })
}

pub fn info_json(info: &AdapterInfo) -> Value {
    let descriptor = info.descriptor.as_ref().map(|d| {
        json!({
            "manufacturer": d.manufacturer,
            "model": d.model,
            "firmware": d.firmware,
            "device_id": d.device_id,
            "modalities": d.modalities,
            "electrodes": d.electrodes.iter()
                .map(|e| json!({"name": e.name, "group": e.group}))
                .collect::<Vec<_>>(),
            "unit": d.unit,
            "clock_domain": d.clock_domain,
            "sampling_rate_hz": d.sampling_rate_hz,
            "bin_width_s": d.bin_width_s,
        })
    });
    let replay = info.replay.as_ref().map(|r| {
        json!({
            "dataset_id": r.dataset_id,
            "version": r.version,
            "license": r.license,
            "consent_basis": r.consent_basis,
            "url": r.url,
        })
    });
    json!({
        "type": "info",
        "contract_version": CONTRACT_VERSION,
        "adapter_id": info.adapter_id,
        "level": match info.level { Level::L3 => "L3", Level::L4 => "L4" },
        "device": device_json(&info.device),
        "channels": channels_json(&info.channels),
        "nominal_rate_hz": info.nominal_rate_hz,
        "clock_domain": info.clock_domain,
        "descriptor": descriptor,
        "replay": replay,
    })
}

pub fn item_json(item: &Item) -> Value {
    match item {
        Item::Malformed(v) => v.clone(),
        Item::Block(b) => json!({
            "type": "block",
            "stream": b.stream,
            "channels": channels_json(&b.channels),
            "device": device_json(&b.device),
            "clock_domain": b.clock_domain,
            "timestamps_ns": b.timestamps_ns,
            "values": b.values,
            "nominal_rate_hz": b.nominal_rate_hz,
        }),
    }
}

pub fn verdict_json(r: &Report) -> Value {
    json!({
        "type": "verdict",
        "ok": r.ok(),
        "blocks": r.blocks,
        "samples": r.samples,
        "violations": r.violations.iter()
            .map(|x| json!({"rule": x.rule, "detail": x.detail}))
            .collect::<Vec<_>>(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn rules(mode: &str) -> BTreeSet<String> {
        let (info, items) = transcript(mode, 4, 64, 1).unwrap();
        check_transcript(&info, &items, 64)
            .violations
            .into_iter()
            .map(|x| x.rule)
            .collect()
    }

    fn set(xs: &[&str]) -> BTreeSet<String> {
        xs.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn simulators_pass_the_contract() {
        let mut l3 = Simulator::new(l3_info(4, 7), 7, 1000);
        let r = check_adapter(&mut l3, 8, 128);
        assert!(r.ok(), "{:?}", r.violations);
        assert_eq!((r.blocks, r.samples), (8, 1000));
        let mut l4 = Simulator::new(l4_replay_info(4, 7), 7, 300);
        assert!(check_adapter(&mut l4, 8, 64).ok());
    }

    #[test]
    fn simulator_is_deterministic_and_regular() {
        let run = || transcript("none", 3, 32, 5).unwrap().1;
        assert_eq!(run(), run());
        let Item::Block(b) = &run()[1] else { panic!() };
        assert_eq!(b.timestamps_ns[0], (32.0 * 1e9 / 256.0_f64).round() as i64);
    }

    #[test]
    fn every_break_mode_is_refused_with_its_rule() {
        let expected: &[(&str, &[&str])] = &[
            ("none", &[]),
            ("l4-replay", &[]),
            ("non-monotonic-clock", &["clock"]),
            ("interpretive-channel", &["neutral"]),
            ("l4-live-undeclared", &["level"]),
            ("channel-change", &["channels"]),
            ("identity-change", &["identity"]),
            ("oversize-block", &["size"]),
            ("wrong-block-type", &["output"]),
            ("bad-unit", &["unit"]),
            ("replay-closed-license", &["replay:replay"]),
        ];
        assert_eq!(expected.len(), BREAK_MODES.len());
        for (mode, want) in expected {
            assert_eq!(rules(mode), set(want), "mode {mode}");
        }
        assert!(transcript("unknown", 1, 1, 0).is_none());
    }

    #[test]
    fn clock_must_increase_across_blocks() {
        let (info, mut items) = transcript("none", 3, 16, 2).unwrap();
        items.swap(0, 1);
        let r = check_transcript(&info, &items, 16);
        let got: BTreeSet<_> = r.violations.into_iter().map(|x| x.rule).collect();
        assert_eq!(got, set(&["clock"]));
    }

    #[test]
    fn invasive_channels_are_refused_without_a_replay_declaration() {
        let mut info = l4_replay_info(2, 0);
        info.replay = None;
        let got: BTreeSet<_> = check_info(&info).into_iter().map(|x| x.rule).collect();
        assert_eq!(got, set(&["level", "modality"]));
        let mut l3 = l4_replay_info(2, 0);
        l3.level = Level::L3;
        l3.replay = None;
        let got: BTreeSet<_> = check_info(&l3).into_iter().map(|x| x.rule).collect();
        assert_eq!(got, set(&["descriptor:profile", "modality"]));
    }

    #[test]
    fn interpretive_names_match_whole_tokens_only() {
        for bad in [
            "valence",
            "fz_emotion",
            "stress.index",
            "fear",
            "intent-1",
            "EMO",
        ] {
            assert!(interpretive(bad), "{bad}");
        }
        for ok in [
            "fz",
            "emotional",
            "ch001",
            "mindful",
            "frontal-intensive",
            "x_emo2",
        ] {
            assert!(!interpretive(ok), "{ok}");
        }
    }

    #[test]
    fn descriptor_rules() {
        let base = l4_replay_info(2, 0).descriptor.unwrap();
        let rule = |d: &Descriptor| -> BTreeSet<String> {
            check_descriptor(d).into_iter().map(|x| x.rule).collect()
        };
        assert!(rule(&base).is_empty());
        let mut d = base.clone();
        d.device_id = "serial-00123".into();
        assert_eq!(rule(&d), set(&["device_id"]));
        let mut d = base.clone();
        d.sampling_rate_hz = Some(30000.0);
        assert_eq!(rule(&d), set(&["rate"]));
        let mut d = base.clone();
        d.electrodes.push(d.electrodes[0].clone());
        assert_eq!(rule(&d), set(&["electrodes"]));
        let mut d = base;
        d.unit = "spikes".into();
        d.clock_domain.clear();
        assert_eq!(rule(&d), set(&["unit", "clock"]));
    }

    #[test]
    fn json_lines_carry_the_contract_version() {
        let (info, items) = transcript("l4-replay", 2, 8, 0).unwrap();
        let i = info_json(&info);
        assert_eq!(i["contract_version"], CONTRACT_VERSION);
        assert_eq!(i["level"], "L4");
        assert_eq!(item_json(&items[0])["type"], "block");
        let r = check_transcript(&info, &items, 8);
        assert_eq!(verdict_json(&r)["ok"], true);
    }
}
