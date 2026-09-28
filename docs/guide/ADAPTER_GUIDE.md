<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Adapter guide

An adapter turns a device or a file into `SampleBlock`s. That is its whole job: **adapters never
produce emotions**. Features, calibration and estimators come later and are separate.

Existing adapters:

- `esp.adapters.physio.brainflow_adapter`: BrainFlow boards, including synthetic and playback.
- `esp.adapters.physio.lsl_adapter`: Lab Streaming Layer.
- `esp.adapters.physio.files`: XDF, EDF/BDF, BrainVision, WFDB and Empatica files.
- `esp.adapters.legacy_movie`: a runtime-only adapter for the proprietary movie ontology, which
  is never vendored.

## Writing an adapter

An adapter must:

1. Emit integer-nanosecond timestamps in one named clock domain.
2. Normalize channel names and units (`normalize_unit`, `normalize_channel`).
3. Mark dropouts as `NaN`. Never interpolate silently.
4. Use a pseudonymous `device_id`, never a hardware serial number.

```python
import numpy as np
from esp.adapters.physio.stream import ChannelSpec, SampleBlock, analyze, regular_timestamps
from esp.features.physio import heart_rate
from esp.observation.model import DeviceMetadata, Modality

fs, seconds = 250.0, 20
t = np.arange(int(fs * seconds)) / fs
ecg = np.zeros_like(t)
ecg[(np.arange(0, seconds, 0.8) * fs).astype(int)] = 1.0  # one R-peak every 0.8 s = 75 bpm
ecg = np.convolve(ecg, np.hanning(9), mode="same")

block = SampleBlock(
    stream="demo-ecg",
    channels=(ChannelSpec("ecg", Modality.ECG, "mV"),),
    timestamps_ns=regular_timestamps(0, t.size, fs),
    values=ecg[:, None],
    device=DeviceMetadata(device_id="demo-device-1", kind="simulator", synthetic=True),
    clock_domain="demo:mono",
    nominal_rate_hz=fs,
)
report = analyze(block)
assert report.gaps == 0 and report.non_monotonic == 0

hr = next(f for f in heart_rate(block.channel("ecg"), fs, 0) if f.name == "hr")
assert abs(hr.value - 75.0) < 1.0 and hr.unit == "bpm"
obs = hr.to_observation(block.device, block.clock_domain)
assert obs.channel == "hr" and obs.value is not None  # a neutral observation, not an emotion
```

## Conformance for other implementations

A new *protocol* implementation (not a sensor adapter) proves itself with the conformance CLI
and the interop matrix. See [CONFORMANCE.md](../CONFORMANCE.md):

```
uv run esp-conformance --json report.json
uv run esp-conformance --peer ./my-impl --json report.json
```
