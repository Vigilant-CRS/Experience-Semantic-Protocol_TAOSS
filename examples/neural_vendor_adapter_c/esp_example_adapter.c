/*
 * SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Example ESP neural adapter in C (contract 1.0.0, header rust/esp-rs/include/esp_neural.h).
 *
 * A deterministic synthetic EEG-like source: 4 channels in uV at 256 Hz, a 10 Hz rhythm plus
 * pseudo-random noise. Replace `fill_block` with your device driver.
 *
 * `config` selects the behaviour. "" (or NULL) is the well-behaved adapter; "l4-replay" is a
 * recorded invasive dataset with its declaration; "nan-dropout" marks one sample as missing
 * (allowed). The remaining modes break exactly one contract rule and exist so that the
 * conformance suite can prove it refuses them:
 *   non-monotonic-clock, interpretive-channel, l4-live-undeclared, null-buffer,
 *   length-mismatch, inf-sample, read-error.
 *
 * Build: cc -shared -fPIC -O2 -I ../../rust/esp-rs/include esp_example_adapter.c \
 *          -o libesp_example_adapter.so -lm
 */
#include "esp_neural.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#ifndef M_PI
#define M_PI 3.14159265358979323846
#endif

#define N_CH 4
#define MAX_BLOCK 1024
#define TOTAL_SAMPLES 4096

typedef struct {
    char mode[32];
    uint64_t pos;
    uint64_t rng;
    int running;
    esp_neural_channel channels[N_CH];
    esp_neural_electrode electrodes[N_CH];
    const char *modalities[1];
    esp_neural_descriptor descriptor;
    esp_neural_replay replay;
    int64_t ts[MAX_BLOCK];
    double values[MAX_BLOCK * N_CH];
} ctx_t;

static const char *EEG_NAMES[N_CH] = {"fz", "cz", "pz", "oz"};
static const char *ECOG_NAMES[N_CH] = {"g001", "g002", "g003", "g004"};

static int is(const ctx_t *c, const char *m) { return strcmp(c->mode, m) == 0; }

static double noise(uint64_t *s) { /* splitmix64 -> [0, 1) */
    uint64_t z = (*s += 0x9E3779B97F4A7C15ull);
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    z ^= z >> 31;
    return (double)(z >> 11) / (double)(1ull << 53);
}

static int32_t info(void *p, esp_neural_info *out) {
    ctx_t *c = (ctx_t *)p;
    int ecog = is(c, "l4-replay");
    for (int i = 0; i < N_CH; i++) {
        c->channels[i].name = ecog ? ECOG_NAMES[i] : EEG_NAMES[i];
        c->channels[i].modality = ecog ? "ecog" : "eeg";
        c->channels[i].unit = "uV";
        c->electrodes[i].name = c->channels[i].name;
        c->electrodes[i].group = ecog ? "grid-a" : "";
    }
    if (is(c, "interpretive-channel")) c->channels[0].name = "valence";
    memset(out, 0, sizeof *out);
    out->abi_version = ESP_NEURAL_ABI_VERSION;
    out->adapter_id = "esp-c-example";
    out->device_id = "c-example-1";
    out->device_kind = ecog ? "ecog-grid" : "eeg-amplifier";
    out->device_sampling_rate_hz = 256.0;
    out->synthetic = 1;
    out->n_channels = N_CH;
    out->channels = c->channels;
    out->nominal_rate_hz = 256.0;
    out->level = (ecog || is(c, "l4-live-undeclared")) ? 4 : 3;
    out->clock_domain = "c-example:mono";
    if (ecog) {
        c->modalities[0] = "ecog";
        c->descriptor = (esp_neural_descriptor){
            .manufacturer = "(synthetic)", .model = "c example grid", .firmware = "n/a",
            .device_id = "c-example-1", .n_modalities = 1, .modalities = c->modalities,
            .n_electrodes = N_CH, .electrodes = c->electrodes, .unit = "uV",
            .clock_domain = "c-example:mono", .sampling_rate_hz = 256.0, .bin_width_s = 0.0};
        c->replay = (esp_neural_replay){
            .dataset_id = "esp:c-example-synthetic", .version = "1.0.0", .license = "CC0-1.0",
            .consent_basis = "synthetic data; no participant",
            .url = "https://example.org/esp/c-example"};
        out->descriptor = &c->descriptor;
        out->replay = &c->replay;
    }
    return ESP_NEURAL_OK;
}

static int32_t start(void *p) {
    ctx_t *c = (ctx_t *)p;
    c->pos = 0;
    c->rng = 42;
    c->running = 1;
    return ESP_NEURAL_OK;
}

static int32_t fill_block(ctx_t *c, uint32_t n) {
    for (uint32_t i = 0; i < n; i++) {
        uint64_t k = c->pos + i;
        double t = (double)k / 256.0;
        c->ts[i] = (int64_t)llround((double)k * 1e9 / 256.0);
        for (int ch = 0; ch < N_CH; ch++)
            c->values[i * N_CH + ch] =
                10.0 * sin(2.0 * M_PI * 10.0 * t + ch) + (noise(&c->rng) - 0.5) * 8.0;
    }
    return 0;
}

static int32_t read_block(void *p, uint32_t max_samples, esp_neural_block *out) {
    ctx_t *c = (ctx_t *)p;
    if (!c->running) return ESP_NEURAL_ERROR;
    if (c->pos >= TOTAL_SAMPLES) return ESP_NEURAL_END;
    uint32_t n = max_samples < MAX_BLOCK ? max_samples : MAX_BLOCK;
    if (c->pos + n > TOTAL_SAMPLES) n = (uint32_t)(TOTAL_SAMPLES - c->pos);
    fill_block(c, n);
    int second = c->pos > 0; /* break modes act on the second block */
    if (second && is(c, "non-monotonic-clock") && n > 5) c->ts[5] = c->ts[4];
    if (second && is(c, "inf-sample")) c->values[0] = INFINITY;
    if (is(c, "nan-dropout") && n > 3) c->values[3 * N_CH + 1] = NAN;
    if (second && is(c, "read-error")) return ESP_NEURAL_ERROR;
    out->n_samples = n;
    out->n_channels = (second && is(c, "length-mismatch")) ? N_CH - 1 : N_CH;
    out->timestamps_ns = c->ts;
    out->values = (second && is(c, "null-buffer")) ? NULL : c->values;
    c->pos += n;
    return ESP_NEURAL_OK;
}

static void release(void *p, const esp_neural_block *b) { (void)p; (void)b; /* static buffers */ }

static int32_t stop(void *p) {
    ((ctx_t *)p)->running = 0;
    return ESP_NEURAL_OK;
}

static void destroy(void *p) { free(p); }

int32_t esp_neural_adapter_create(const char *config, esp_neural_vtable *out) {
    ctx_t *c = (ctx_t *)calloc(1, sizeof(ctx_t));
    if (!c || !out) return ESP_NEURAL_ERROR;
    strncpy(c->mode, config ? config : "", sizeof c->mode - 1);
    out->abi_version = ESP_NEURAL_ABI_VERSION;
    out->ctx = c;
    out->info = info;
    out->start = start;
    out->read = read_block;
    out->release = release;
    out->stop = stop;
    out->destroy = destroy;
    return ESP_NEURAL_OK;
}
