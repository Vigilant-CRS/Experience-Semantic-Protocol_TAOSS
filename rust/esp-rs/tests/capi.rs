// SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
// SPDX-License-Identifier: AGPL-3.0-or-later
//! WP-090: the C ABI (`include/esp_neural.h`) — layout, the example adapter and refusals.

use esp_rs::neural::NeuralAdapter;
use esp_rs::neural_capi::{
    CAdapter, EspBlock, EspChannel, EspDescriptor, EspElectrode, EspInfo, EspReplay, EspVtable,
    ABI_VERSION, END, OK,
};
use std::collections::BTreeSet;
use std::ffi::{c_char, c_void};
use std::mem::{offset_of, size_of};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

const CRATE: &str = env!("CARGO_MANIFEST_DIR");

fn out_dir() -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("capi");
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn have_cc() -> bool {
    Command::new("cc").arg("--version").output().is_ok()
}

/// The example adapter, compiled once with warnings as errors.
fn example_lib() -> &'static Path {
    static LIB: OnceLock<PathBuf> = OnceLock::new();
    LIB.get_or_init(|| {
        let out = out_dir().join("libesp_example_adapter.so");
        let src =
            Path::new(CRATE).join("../../examples/neural_vendor_adapter_c/esp_example_adapter.c");
        let st = Command::new("cc")
            .args([
                "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror", "-I",
            ])
            .arg(Path::new(CRATE).join("include"))
            .arg(src)
            .arg("-o")
            .arg(&out)
            .arg("-lm")
            .status()
            .unwrap();
        assert!(st.success(), "cc failed");
        out
    })
}

fn rules(lib: &Path, mode: &str) -> BTreeSet<String> {
    let mut a = CAdapter::load(lib.to_str().unwrap(), Some(mode)).unwrap();
    let (_, report) = a.check(6, 64);
    report.violations.into_iter().map(|v| v.rule).collect()
}

#[test]
fn every_example_mode_gives_exactly_its_rule() {
    if !have_cc() {
        eprintln!("skipped: no C compiler");
        return;
    }
    let lib = example_lib();
    let cases: &[(&str, &[&str])] = &[
        ("", &[]),
        ("l4-replay", &[]),
        ("nan-dropout", &[]),
        ("non-monotonic-clock", &["clock"]),
        ("interpretive-channel", &["neutral"]),
        ("l4-live-undeclared", &["level"]),
        ("null-buffer", &["output"]),
        ("length-mismatch", &["channels"]),
        ("inf-sample", &["output"]),
        ("read-error", &["output"]),
    ];
    for (mode, want) in cases {
        let want: BTreeSet<String> = want.iter().map(|s| (*s).to_string()).collect();
        assert_eq!(rules(lib, mode), want, "mode {mode:?}");
    }
}

#[test]
fn clean_example_streams_to_the_end() {
    if !have_cc() {
        return;
    }
    let mut a = CAdapter::load(example_lib().to_str().unwrap(), None).unwrap();
    assert_eq!(a.info().channels.len(), 4);
    a.start();
    let mut samples = 0;
    let mut last = i64::MIN;
    while let Some(b) = a.read(1000) {
        assert!(b.timestamps_ns.iter().all(|&t| t > last));
        last = *b.timestamps_ns.last().unwrap();
        samples += b.timestamps_ns.len();
    }
    a.stop();
    assert_eq!(samples, 4096);
}

#[test]
fn missing_library_or_symbol_is_an_error() {
    assert!(CAdapter::load("/nonexistent/libnope.so", None).is_err());
    if !have_cc() {
        return;
    }
    let dir = out_dir();
    let src = dir.join("nosym.c");
    std::fs::write(&src, "int other(void) { return 0; }\n").unwrap();
    let lib = dir.join("libnosym.so");
    let st = Command::new("cc")
        .args(["-shared", "-fPIC"])
        .arg(&src)
        .arg("-o")
        .arg(&lib)
        .status()
        .unwrap();
    assert!(st.success());
    let err = CAdapter::load(lib.to_str().unwrap(), None).err().unwrap();
    assert!(err.contains("esp_neural_adapter_create"), "{err}");
}

/// `#[repr(C)]` mirrors must match what a C compiler makes of the header.
#[test]
fn rust_mirrors_match_the_c_layout() {
    if !have_cc() {
        return;
    }
    let dir = out_dir();
    let src = dir.join("layout.c");
    let mut c = String::from(
        "#include <stddef.h>\n#include <stdio.h>\n#include \"esp_neural.h\"\n\
         #define S(T) printf(#T \" %zu\\n\", sizeof(T));\n\
         #define O(T, f) printf(#T \".\" #f \" %zu\\n\", offsetof(T, f));\nint main(void) {\n",
    );
    let fields: &[(&str, &[&str])] = &[
        ("esp_neural_channel", &["name", "modality", "unit"]),
        ("esp_neural_electrode", &["name", "group"]),
        (
            "esp_neural_descriptor",
            &[
                "manufacturer",
                "model",
                "firmware",
                "device_id",
                "n_modalities",
                "modalities",
                "n_electrodes",
                "electrodes",
                "unit",
                "clock_domain",
                "sampling_rate_hz",
                "bin_width_s",
            ],
        ),
        (
            "esp_neural_replay",
            &["dataset_id", "version", "license", "consent_basis", "url"],
        ),
        (
            "esp_neural_info",
            &[
                "abi_version",
                "adapter_id",
                "device_id",
                "device_kind",
                "device_sampling_rate_hz",
                "synthetic",
                "n_channels",
                "channels",
                "nominal_rate_hz",
                "level",
                "clock_domain",
                "descriptor",
                "replay",
            ],
        ),
        (
            "esp_neural_block",
            &["n_samples", "n_channels", "timestamps_ns", "values"],
        ),
        (
            "esp_neural_vtable",
            &[
                "abi_version",
                "ctx",
                "info",
                "start",
                "read",
                "release",
                "stop",
                "destroy",
            ],
        ),
    ];
    for (t, fs) in fields {
        c += &format!("S({t})\n");
        for f in *fs {
            c += &format!("O({t}, {f})\n");
        }
    }
    c += "return 0; }\n";
    std::fs::write(&src, c).unwrap();
    let exe = dir.join("layout");
    let st = Command::new("cc")
        .arg("-I")
        .arg(Path::new(CRATE).join("include"))
        .arg(&src)
        .arg("-o")
        .arg(&exe)
        .status()
        .unwrap();
    assert!(st.success());
    let out = String::from_utf8(Command::new(&exe).output().unwrap().stdout).unwrap();
    let c_layout: Vec<(String, usize)> = out
        .lines()
        .map(|l| {
            let (k, v) = l.rsplit_once(' ').unwrap();
            (k.to_string(), v.parse().unwrap())
        })
        .collect();
    macro_rules! rs {
        ($t:ty, $c:literal; $($f:ident),*) => {{
            let mut v = vec![(concat!($c).to_string(), size_of::<$t>())];
            $(v.push((concat!($c, ".", stringify!($f)).to_string(), offset_of!($t, $f)));)*
            v
        }};
    }
    let mut rust_layout = Vec::new();
    rust_layout.extend(rs!(EspChannel, "esp_neural_channel"; name, modality, unit));
    rust_layout.extend(rs!(EspElectrode, "esp_neural_electrode"; name, group));
    rust_layout.extend(
        rs!(EspDescriptor, "esp_neural_descriptor"; manufacturer, model, firmware,
        device_id, n_modalities, modalities, n_electrodes, electrodes, unit, clock_domain,
        sampling_rate_hz, bin_width_s),
    );
    rust_layout.extend(
        rs!(EspReplay, "esp_neural_replay"; dataset_id, version, license,
        consent_basis, url),
    );
    rust_layout.extend(
        rs!(EspInfo, "esp_neural_info"; abi_version, adapter_id, device_id,
        device_kind, device_sampling_rate_hz, synthetic, n_channels, channels, nominal_rate_hz,
        level, clock_domain, descriptor, replay),
    );
    rust_layout.extend(
        rs!(EspBlock, "esp_neural_block"; n_samples, n_channels, timestamps_ns,
        values),
    );
    rust_layout.extend(
        rs!(EspVtable, "esp_neural_vtable"; abi_version, ctx, info, start, read,
        release, stop, destroy),
    );
    assert_eq!(c_layout, rust_layout);
}

// ---- refusals at the boundary, driven by vtables written in Rust ----------------------------

static DESTROYED: AtomicUsize = AtomicUsize::new(0);

/// Which piece of `info` the fake vendor gets wrong.
#[derive(Clone, Copy)]
#[repr(usize)]
enum Bad {
    Nothing,
    InfoAbi,
    Level,
    NullString,
    Utf8,
    NullChannels,
    Synthetic,
    InfoFails,
}

static BAD_UTF8: [u8; 3] = [0xff, 0xfe, 0];

unsafe extern "C" fn fake_info(ctx: *mut c_void, out: *mut EspInfo) -> i32 {
    let bad: Bad = match ctx as usize {
        1 => Bad::InfoAbi,
        2 => Bad::Level,
        3 => Bad::NullString,
        4 => Bad::Utf8,
        5 => Bad::NullChannels,
        6 => Bad::Synthetic,
        7 => Bad::InfoFails,
        _ => Bad::Nothing,
    };
    if matches!(bad, Bad::InfoFails) {
        return -1;
    }
    let info = EspInfo {
        abi_version: if matches!(bad, Bad::InfoAbi) {
            2
        } else {
            ABI_VERSION
        },
        adapter_id: c"fake".as_ptr(),
        device_id: match bad {
            Bad::NullString => std::ptr::null(),
            Bad::Utf8 => BAD_UTF8.as_ptr().cast::<c_char>(),
            _ => c"fake-1".as_ptr(),
        },
        device_kind: c"eeg-amplifier".as_ptr(),
        device_sampling_rate_hz: 0.0,
        synthetic: if matches!(bad, Bad::Synthetic) { 7 } else { 1 },
        n_channels: 1,
        channels: if matches!(bad, Bad::NullChannels) {
            std::ptr::null()
        } else {
            // leaked on purpose: must outlive the adapter (tests only)
            Box::leak(Box::new(EspChannel {
                name: c"ch001".as_ptr(),
                modality: c"eeg".as_ptr(),
                unit: c"uV".as_ptr(),
            }))
        },
        nominal_rate_hz: 100.0,
        level: if matches!(bad, Bad::Level) { 5 } else { 3 },
        clock_domain: c"fake:mono".as_ptr(),
        descriptor: std::ptr::null(),
        replay: std::ptr::null(),
    };
    // SAFETY: the host passes a valid, writable EspInfo.
    unsafe { out.write(info) };
    OK
}
unsafe extern "C" fn fake_ctl(_: *mut c_void) -> i32 {
    OK
}
unsafe extern "C" fn fake_read(_: *mut c_void, _: u32, _: *mut EspBlock) -> i32 {
    END
}
unsafe extern "C" fn fake_release(_: *mut c_void, _: *const EspBlock) {}
unsafe extern "C" fn fake_destroy(_: *mut c_void) {
    DESTROYED.fetch_add(1, Ordering::SeqCst);
}

fn fake_vtable(bad: Bad) -> EspVtable {
    EspVtable {
        abi_version: ABI_VERSION,
        ctx: bad as usize as *mut c_void,
        info: Some(fake_info),
        start: Some(fake_ctl),
        read: Some(fake_read),
        release: Some(fake_release),
        stop: Some(fake_ctl),
        destroy: Some(fake_destroy),
    }
}

fn wrap(vt: EspVtable) -> Result<CAdapter, String> {
    // SAFETY: the fake vtable follows the header (static strings, no-op callbacks).
    unsafe { CAdapter::from_vtable(vt, None) }
}

#[test]
fn boundary_refusals_destroy_the_vendor_context_exactly_once() {
    let before = DESTROYED.load(Ordering::SeqCst);
    let ok = wrap(fake_vtable(Bad::Nothing)).unwrap();
    assert_eq!(ok.info().channels[0].name, "ch001");
    drop(ok);
    let mut refused = 0;
    for (bad, needle) in [
        (Bad::InfoAbi, "abi_version"),
        (Bad::Level, "level"),
        (Bad::NullString, "NULL"),
        (Bad::Utf8, "UTF-8"),
        (Bad::NullChannels, "NULL"),
        (Bad::Synthetic, "synthetic"),
        (Bad::InfoFails, "info()"),
    ] {
        let err = wrap(fake_vtable(bad)).err().expect("must be refused");
        assert!(err.contains(needle), "{needle}: {err}");
        refused += 1;
    }
    let mut vt = fake_vtable(Bad::Nothing);
    vt.abi_version = 0;
    assert!(wrap(vt).err().unwrap().contains("abi_version"));
    let mut vt = fake_vtable(Bad::Nothing);
    vt.release = None;
    assert!(wrap(vt).err().unwrap().contains("NULL callback"));
    refused += 2;
    // an adapter that ends at once yields an empty transcript
    let mut empty = wrap(fake_vtable(Bad::Nothing)).unwrap();
    let (items, report) = empty.check(4, 16);
    assert!(items.is_empty());
    assert_eq!(report.blocks, 0);
    drop(empty);
    // two clean drops + every refusal (the only test touching DESTROYED)
    assert_eq!(DESTROYED.load(Ordering::SeqCst) - before, refused + 2);
}
