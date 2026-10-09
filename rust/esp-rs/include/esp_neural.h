/*
 * SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * ESP neural adapter contract 1.0.0 — C ABI (WP-090).
 *
 * A device maker implements ONE entry point in a shared library:
 *
 *     int32_t esp_neural_adapter_create(const char *config, esp_neural_vtable *out);
 *
 * and fills `out` with its callbacks. The host (esp-rs, or any ESP stack) loads the library,
 * validates everything it receives and checks the same contract as the Python and Rust
 * implementations (`esp-conformance run --neural-c <lib> --neural-rust <esp-rs>`).
 *
 * Ownership (all memory stays with the vendor):
 *  - Every pointer filled by `info()` (strings, arrays, descriptor, replay declaration) must stay
 *    valid until `destroy(ctx)` is called.
 *  - The buffers of a block returned by `read()` must stay valid until the host calls
 *    `release(ctx, block)`. The host copies the block and calls `release` exactly once per
 *    successful `read()` (return value ESP_NEURAL_OK), before the next `read()`.
 *  - The host never writes through any vendor pointer and never frees vendor memory.
 *
 * Data rules (identical to the Python/Rust contract):
 *  - timestamps: int64 nanoseconds in the declared clock domain, strictly increasing across
 *    all blocks of a stream;
 *  - values: row-major float64, n_samples x n_channels, n_channels equal to the declaration,
 *    in the declared unit; NaN marks a dropout, +/-Inf is refused;
 *  - channel names must name a signal, never an interpretation ("valence", "intent_x", ...);
 *  - device ids are pseudonymous, never hardware serial numbers;
 *  - invasive (level 4) sources are admitted only as recorded datasets with a replay
 *    declaration (L4-REPLAY); live invasive sources have no v1 profile.
 *
 * All strings are NUL-terminated UTF-8.
 */
#ifndef ESP_NEURAL_H
#define ESP_NEURAL_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ESP_NEURAL_ABI_VERSION 1u
#define ESP_NEURAL_CONTRACT_VERSION "1.0.0"

/* return codes */
#define ESP_NEURAL_OK 0          /* read(): a block was produced */
#define ESP_NEURAL_END 1         /* read(): no more data */
#define ESP_NEURAL_ERROR (-1)    /* any callback: failure */

typedef struct esp_neural_channel {
    const char *name;     /* neutral signal name, e.g. "fz", "ch001" */
    const char *modality; /* "eeg", "emg", "eye", "ecog", "seeg", "lfp", "mua", "spikes",
                             "spike_counts", "broadband", "neural_features", ... */
    const char *unit;     /* normalized unit: "uV", "mV", "V", "count", "Hz", "1", ... */
} esp_neural_channel;

typedef struct esp_neural_electrode {
    const char *name;
    const char *group; /* may be "" */
} esp_neural_electrode;

typedef struct esp_neural_descriptor {
    const char *manufacturer;
    const char *model;
    const char *firmware;
    const char *device_id;            /* pseudonymous */
    uint32_t n_modalities;
    const char *const *modalities;
    uint32_t n_electrodes;
    const esp_neural_electrode *electrodes;
    const char *unit;
    const char *clock_domain;
    double sampling_rate_hz;          /* <= 0: not set (then bin_width_s must be set) */
    double bin_width_s;               /* <= 0: not set */
} esp_neural_descriptor;

typedef struct esp_neural_replay {
    const char *dataset_id;
    const char *version;
    const char *license;              /* SPDX id of an open license */
    const char *consent_basis;
    const char *url;                  /* https */
} esp_neural_replay;

typedef struct esp_neural_info {
    uint32_t abi_version;             /* ESP_NEURAL_ABI_VERSION */
    const char *adapter_id;
    const char *device_id;            /* pseudonymous */
    const char *device_kind;
    double device_sampling_rate_hz;   /* <= 0: not set */
    int32_t synthetic;                /* 0 or 1 */
    uint32_t n_channels;
    const esp_neural_channel *channels;
    double nominal_rate_hz;
    int32_t level;                    /* 3 = non-invasive, 4 = invasive */
    const char *clock_domain;
    const esp_neural_descriptor *descriptor; /* NULL if none (required for level 4) */
    const esp_neural_replay *replay;         /* NULL unless a recorded invasive dataset */
} esp_neural_info;

typedef struct esp_neural_block {
    uint32_t n_samples;
    uint32_t n_channels;
    const int64_t *timestamps_ns;     /* n_samples */
    const double *values;             /* n_samples * n_channels, row-major */
} esp_neural_block;

typedef struct esp_neural_vtable {
    uint32_t abi_version;             /* ESP_NEURAL_ABI_VERSION */
    void *ctx;
    int32_t (*info)(void *ctx, esp_neural_info *out);
    int32_t (*start)(void *ctx);
    int32_t (*read)(void *ctx, uint32_t max_samples, esp_neural_block *out);
    void (*release)(void *ctx, const esp_neural_block *block);
    int32_t (*stop)(void *ctx);
    void (*destroy)(void *ctx);
} esp_neural_vtable;

/* The one symbol a vendor library exports. `config` may be NULL or a vendor-defined string
 * (device path, recording file, ...). Return ESP_NEURAL_OK and fill `out`. */
int32_t esp_neural_adapter_create(const char *config, esp_neural_vtable *out);

#ifdef __cplusplus
}
#endif

#endif /* ESP_NEURAL_H */
