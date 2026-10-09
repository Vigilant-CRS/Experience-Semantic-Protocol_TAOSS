// SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! C ABI for neural vendor adapters (WP-090; header `include/esp_neural.h`).
//!
//! A device maker writes the adapter in C or C++ and exports
//! `esp_neural_adapter_create(config, vtable)`. [`CAdapter`] loads the library, wraps the
//! vtable and validates **everything** that crosses the boundary before it becomes a
//! contract object: NULL pointers, UTF-8, lengths, the ABI version, the declared level and
//! infinite samples. Bad vendor input becomes a contract violation, never undefined
//! behaviour on the host side (as long as the vendor honours the documented buffer lengths,
//! which no C interface can verify).
//!
//! Ownership: all memory belongs to the vendor. Info pointers stay valid until `destroy`;
//! block buffers until the host calls `release`, which it does exactly once per successful
//! `read`, right after copying.

use crate::neural::{
    check_transcript, AdapterInfo, ChannelSpec, Descriptor, Device, Electrode, Item, Level,
    NeuralAdapter, ReplayDeclaration, Report, SampleBlock,
};
use serde_json::json;
use std::ffi::{c_char, c_void, CStr, CString};

pub const ABI_VERSION: u32 = 1;
pub const OK: i32 = 0;
pub const END: i32 = 1;
/// Upper bound on samples × channels in one block (guards against absurd vendor lengths).
pub const MAX_BLOCK_VALUES: usize = 1 << 24;

#[repr(C)]
pub struct EspChannel {
    pub name: *const c_char,
    pub modality: *const c_char,
    pub unit: *const c_char,
}

#[repr(C)]
pub struct EspElectrode {
    pub name: *const c_char,
    pub group: *const c_char,
}

#[repr(C)]
pub struct EspDescriptor {
    pub manufacturer: *const c_char,
    pub model: *const c_char,
    pub firmware: *const c_char,
    pub device_id: *const c_char,
    pub n_modalities: u32,
    pub modalities: *const *const c_char,
    pub n_electrodes: u32,
    pub electrodes: *const EspElectrode,
    pub unit: *const c_char,
    pub clock_domain: *const c_char,
    pub sampling_rate_hz: f64,
    pub bin_width_s: f64,
}

#[repr(C)]
pub struct EspReplay {
    pub dataset_id: *const c_char,
    pub version: *const c_char,
    pub license: *const c_char,
    pub consent_basis: *const c_char,
    pub url: *const c_char,
}

#[repr(C)]
pub struct EspInfo {
    pub abi_version: u32,
    pub adapter_id: *const c_char,
    pub device_id: *const c_char,
    pub device_kind: *const c_char,
    pub device_sampling_rate_hz: f64,
    pub synthetic: i32,
    pub n_channels: u32,
    pub channels: *const EspChannel,
    pub nominal_rate_hz: f64,
    pub level: i32,
    pub clock_domain: *const c_char,
    pub descriptor: *const EspDescriptor,
    pub replay: *const EspReplay,
}

#[repr(C)]
pub struct EspBlock {
    pub n_samples: u32,
    pub n_channels: u32,
    pub timestamps_ns: *const i64,
    pub values: *const f64,
}

type InfoFn = unsafe extern "C" fn(*mut c_void, *mut EspInfo) -> i32;
type CtlFn = unsafe extern "C" fn(*mut c_void) -> i32;
type ReadFn = unsafe extern "C" fn(*mut c_void, u32, *mut EspBlock) -> i32;
type ReleaseFn = unsafe extern "C" fn(*mut c_void, *const EspBlock);
type DestroyFn = unsafe extern "C" fn(*mut c_void);
pub type CreateFn = unsafe extern "C" fn(*const c_char, *mut EspVtable) -> i32;

#[repr(C)]
pub struct EspVtable {
    pub abi_version: u32,
    pub ctx: *mut c_void,
    pub info: Option<InfoFn>,
    pub start: Option<CtlFn>,
    pub read: Option<ReadFn>,
    pub release: Option<ReleaseFn>,
    pub stop: Option<CtlFn>,
    pub destroy: Option<DestroyFn>,
}

impl EspVtable {
    pub fn empty() -> Self {
        Self {
            abi_version: 0,
            ctx: std::ptr::null_mut(),
            info: None,
            start: None,
            read: None,
            release: None,
            stop: None,
            destroy: None,
        }
    }
}

/// Copy a vendor C string; NULL or invalid UTF-8 is refused.
///
/// # Safety
/// `p` must be NULL or point to a NUL-terminated string that stays valid for the call.
unsafe fn string(p: *const c_char, what: &str) -> Result<String, String> {
    if p.is_null() {
        return Err(format!("{what} is NULL"));
    }
    // SAFETY: non-NULL and NUL-terminated per the caller's contract (header: valid until destroy).
    let s = unsafe { CStr::from_ptr(p) };
    s.to_str()
        .map(str::to_owned)
        .map_err(|_| format!("{what} is not valid UTF-8"))
}

/// View `n` vendor elements; NULL with `n > 0` is refused.
///
/// # Safety
/// `p` must be NULL or point to at least `n` initialised elements valid for the call.
unsafe fn slice<'a, T>(p: *const T, n: u32, what: &str) -> Result<&'a [T], String> {
    if n == 0 {
        return Ok(&[]);
    }
    if p.is_null() {
        return Err(format!("{what} is NULL"));
    }
    // SAFETY: non-NULL, `n` elements per the header's ownership rules.
    Ok(unsafe { std::slice::from_raw_parts(p, n as usize) })
}

fn positive(x: f64) -> Option<f64> {
    (x.is_finite() && x > 0.0).then_some(x)
}

/// Convert the vendor's info struct into the contract's [`AdapterInfo`].
///
/// # Safety
/// All pointers in `ci` must follow the header's ownership rules.
unsafe fn convert_info(ci: &EspInfo) -> Result<AdapterInfo, String> {
    if ci.abi_version != ABI_VERSION {
        return Err(format!(
            "info abi_version {} != {ABI_VERSION}",
            ci.abi_version
        ));
    }
    let level = match ci.level {
        3 => Level::L3,
        4 => Level::L4,
        other => return Err(format!("level must be 3 or 4, got {other}")),
    };
    if !(ci.synthetic == 0 || ci.synthetic == 1) {
        return Err("synthetic must be 0 or 1".into());
    }
    // SAFETY: forwarded from the caller's contract for every pointer below.
    unsafe {
        let mut channels = Vec::new();
        for c in slice(ci.channels, ci.n_channels, "channels")? {
            channels.push(ChannelSpec {
                name: string(c.name, "channel name")?,
                modality: string(c.modality, "channel modality")?,
                unit: string(c.unit, "channel unit")?,
            });
        }
        let descriptor = if ci.descriptor.is_null() {
            None
        } else {
            let d = &*ci.descriptor;
            let mut modalities = Vec::new();
            for m in slice(d.modalities, d.n_modalities, "modalities")? {
                modalities.push(string(*m, "modality")?);
            }
            let mut electrodes = Vec::new();
            for e in slice(d.electrodes, d.n_electrodes, "electrodes")? {
                electrodes.push(Electrode {
                    name: string(e.name, "electrode name")?,
                    group: string(e.group, "electrode group")?,
                });
            }
            Some(Descriptor {
                manufacturer: string(d.manufacturer, "manufacturer")?,
                model: string(d.model, "model")?,
                firmware: string(d.firmware, "firmware")?,
                device_id: string(d.device_id, "descriptor device_id")?,
                modalities,
                electrodes,
                unit: string(d.unit, "descriptor unit")?,
                clock_domain: string(d.clock_domain, "descriptor clock_domain")?,
                sampling_rate_hz: positive(d.sampling_rate_hz),
                bin_width_s: positive(d.bin_width_s),
            })
        };
        let replay = if ci.replay.is_null() {
            None
        } else {
            let r = &*ci.replay;
            Some(ReplayDeclaration {
                dataset_id: string(r.dataset_id, "dataset_id")?,
                version: string(r.version, "version")?,
                license: string(r.license, "license")?,
                consent_basis: string(r.consent_basis, "consent_basis")?,
                url: string(r.url, "url")?,
            })
        };
        Ok(AdapterInfo {
            adapter_id: string(ci.adapter_id, "adapter_id")?,
            device: Device {
                device_id: string(ci.device_id, "device_id")?,
                kind: string(ci.device_kind, "device_kind")?,
                sampling_rate_hz: positive(ci.device_sampling_rate_hz),
                synthetic: ci.synthetic == 1,
            },
            channels,
            nominal_rate_hz: ci.nominal_rate_hz,
            level,
            clock_domain: string(ci.clock_domain, "clock_domain")?,
            descriptor,
            replay,
        })
    }
}

fn malformed(reason: &str) -> Item {
    Item::Malformed(json!({"type": "malformed", "reason": reason}))
}

/// A vendor adapter loaded through the C ABI.
pub struct CAdapter {
    vt: EspVtable,
    info: AdapterInfo,
    started: bool,
    // keep the library loaded for as long as the vtable is used (dropped last)
    _lib: Option<libloading::Library>,
}

impl CAdapter {
    /// Wrap a vendor vtable (e.g. from a statically linked adapter).
    ///
    /// # Safety
    /// `vt` must come from `esp_neural_adapter_create` and follow the header's contract.
    pub unsafe fn from_vtable(
        vt: EspVtable,
        lib: Option<libloading::Library>,
    ) -> Result<Self, String> {
        let destroy_on_err = |vt: &EspVtable| {
            if let Some(d) = vt.destroy {
                // SAFETY: vendor callback on its own context, called once.
                unsafe { d(vt.ctx) }
            }
        };
        if vt.abi_version != ABI_VERSION {
            destroy_on_err(&vt);
            return Err(format!(
                "vtable abi_version {} != {ABI_VERSION}",
                vt.abi_version
            ));
        }
        let (Some(info_fn), Some(_), Some(_), Some(_), Some(_), Some(_)) =
            (vt.info, vt.start, vt.read, vt.release, vt.stop, vt.destroy)
        else {
            destroy_on_err(&vt);
            return Err("vtable has a NULL callback".into());
        };
        // SAFETY: EspInfo holds only integers, floats and raw pointers; all-zero is valid.
        let mut ci: EspInfo = unsafe { std::mem::zeroed() };
        // SAFETY: vendor callback fills a host-owned struct; pointers inside follow the header.
        let rc = unsafe { info_fn(vt.ctx, &mut ci) };
        if rc != OK {
            destroy_on_err(&vt);
            return Err(format!("info() returned {rc}"));
        }
        // SAFETY: pointers in `ci` are valid until destroy (header ownership rules).
        match unsafe { convert_info(&ci) } {
            Ok(info) => Ok(Self {
                vt,
                info,
                started: false,
                _lib: lib,
            }),
            Err(e) => {
                destroy_on_err(&vt);
                Err(e)
            }
        }
    }

    /// Load `path` (a shared library exporting `esp_neural_adapter_create`) with `config`.
    pub fn load(path: &str, config: Option<&str>) -> Result<Self, String> {
        // SAFETY: loading a vendor library runs its initialisers; that is the point of a
        // plug-in interface and the operator chose the path.
        let lib = unsafe { libloading::Library::new(path) }.map_err(|e| e.to_string())?;
        let create: CreateFn = {
            // SAFETY: the symbol type is fixed by the header.
            let sym = unsafe { lib.get::<CreateFn>(b"esp_neural_adapter_create\0") }
                .map_err(|e| e.to_string())?;
            *sym
        };
        let cfg = config
            .map(CString::new)
            .transpose()
            .map_err(|_| "config contains NUL".to_string())?;
        let mut vt = EspVtable::empty();
        let cfg_ptr = cfg.as_ref().map_or(std::ptr::null(), |c| c.as_ptr());
        // SAFETY: vendor entry point filling a host-owned vtable.
        let rc = unsafe { create(cfg_ptr, &mut vt) };
        if rc != OK {
            return Err(format!("esp_neural_adapter_create returned {rc}"));
        }
        // SAFETY: `vt` was produced by the vendor entry point.
        unsafe { Self::from_vtable(vt, Some(lib)) }
    }

    /// One read as the checker sees it: a block, a malformed read, or `None` at the end.
    pub fn read_item(&mut self, max_samples: usize) -> Option<Item> {
        let read = self.vt.read?;
        let release = self.vt.release?;
        let mut b = EspBlock {
            n_samples: 0,
            n_channels: 0,
            timestamps_ns: std::ptr::null(),
            values: std::ptr::null(),
        };
        let request = u32::try_from(max_samples).unwrap_or(u32::MAX);
        // SAFETY: vendor callback filling a host-owned block struct.
        let rc = unsafe { read(self.vt.ctx, request, &mut b) };
        if rc == END {
            return None;
        }
        if rc != OK {
            return Some(malformed("read() reported an error"));
        }
        let item = self.copy_block(&b);
        // SAFETY: exactly one release per successful read, after copying.
        unsafe { release(self.vt.ctx, &b) };
        Some(item)
    }

    fn copy_block(&self, b: &EspBlock) -> Item {
        let (n, c) = (b.n_samples as usize, b.n_channels as usize);
        if n.saturating_mul(c.max(1)) > MAX_BLOCK_VALUES {
            return malformed("block larger than the host limit");
        }
        // SAFETY: lengths as declared by the vendor; NULL with a non-zero length is refused.
        let ts = match unsafe { slice(b.timestamps_ns, b.n_samples, "timestamps") } {
            Ok(t) => t.to_vec(),
            Err(_) => return malformed("NULL timestamp buffer"),
        };
        let total = u32::try_from(n * c).unwrap_or(u32::MAX);
        // SAFETY: as above, `n_samples * n_channels` values.
        let flat = match unsafe { slice(b.values, total, "values") } {
            Ok(v) => v,
            Err(_) => return malformed("NULL value buffer"),
        };
        if flat.iter().any(|x| x.is_infinite()) {
            return malformed("infinite sample (use NaN for dropouts)");
        }
        let values: Vec<Vec<f64>> = if c == 0 {
            vec![Vec::new(); n]
        } else {
            flat.chunks(c).map(<[f64]>::to_vec).collect()
        };
        let declared = &self.info.channels;
        // A block whose width differs from the declaration keeps its own width; the checker
        // reports it as `channels` (names beyond the declaration are marked undeclared).
        let channels: Vec<ChannelSpec> = (0..c)
            .map(|i| {
                declared.get(i).cloned().unwrap_or(ChannelSpec {
                    name: format!("undeclared{i}"),
                    modality: declared
                        .first()
                        .map_or("eeg".into(), |d| d.modality.clone()),
                    unit: declared.first().map_or("uV".into(), |d| d.unit.clone()),
                })
            })
            .collect();
        Item::Block(SampleBlock {
            stream: self.info.adapter_id.clone(),
            channels,
            device: self.info.device.clone(),
            clock_domain: self.info.clock_domain.clone(),
            timestamps_ns: ts,
            values,
            nominal_rate_hz: Some(self.info.nominal_rate_hz),
        })
    }

    /// Start, read up to `reads` items, stop: the transcript the checker needs.
    pub fn transcript(&mut self, reads: usize, max_samples: usize) -> Vec<Item> {
        self.start();
        let mut items = Vec::new();
        for _ in 0..reads {
            match self.read_item(max_samples) {
                Some(item @ Item::Malformed(_)) => {
                    items.push(item);
                    break;
                }
                Some(item) => items.push(item),
                None => break,
            }
        }
        self.stop();
        items
    }

    /// Run the contract check of `esp_rs::neural` on this adapter.
    pub fn check(&mut self, reads: usize, max_samples: usize) -> (Vec<Item>, Report) {
        let items = self.transcript(reads, max_samples);
        let report = check_transcript(&self.info, &items, max_samples);
        (items, report)
    }
}

impl NeuralAdapter for CAdapter {
    fn info(&self) -> &AdapterInfo {
        &self.info
    }

    fn start(&mut self) {
        if let Some(f) = self.vt.start {
            // SAFETY: vendor callback on its own context.
            if unsafe { f(self.vt.ctx) } == OK {
                self.started = true;
            }
        }
    }

    fn read(&mut self, max_samples: usize) -> Option<SampleBlock> {
        match self.read_item(max_samples)? {
            Item::Block(b) => Some(b),
            Item::Malformed(_) => None,
        }
    }

    fn stop(&mut self) {
        if let Some(f) = self.vt.stop {
            // SAFETY: vendor callback on its own context.
            unsafe { f(self.vt.ctx) };
        }
        self.started = false;
    }
}

impl Drop for CAdapter {
    fn drop(&mut self) {
        if self.started {
            self.stop();
        }
        if let Some(d) = self.vt.destroy {
            // SAFETY: called exactly once, before the library is unloaded (`_lib` drops after).
            unsafe { d(self.vt.ctx) }
        }
    }
}
