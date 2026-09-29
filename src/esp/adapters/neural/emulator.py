# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Implant stream emulator (M18, WP-088).

:class:`ImplantStreamEmulator` wraps **any** :class:`NeuralAdapter`, for
example a recording replayed from NWB, the WP-045 simulator or a vendor driver.
It re-emits the source's blocks as if they came from a live device, in real
time (with an injectable clock) or accelerated. It injects seeded, declared
perturbations that real implants produce:

- ``jitter``: Gaussian timestamp jitter;
- ``dropout``: single samples lost (NaN rows);
- ``channel_death``: one channel becomes NaN from a time on;
- ``clock_drift``: the device clock runs fast or slow (ppm);
- ``reconnect``: a gap, then a new clock offset; the stream resumes;
- ``day_drift``: slow gain and offset change per channel;
- ``gain_step``: an abrupt gain change on all channels;
- ``packet_loss``: whole blocks lost;
- ``electrode_removal``: a channel disappears from the stream. This is
  **never silent**: it is logged as a descriptor change, and :attr:`info`
  changes with it;
- ``burst_noise``: transient broadband noise.

Every perturbation is logged in :attr:`events` with its stream time, so a
consumer can be tested for detection. :func:`detect` is the reference
consumer check. Time-based perturbations (all except ``packet_loss`` and
``electrode_removal``, which act on whole blocks) use counter-based
randomness keyed by the global sample index, so their output does not depend
on how the source chunks its stream.
"""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

import numpy as np
from numpy.typing import NDArray

from esp.adapters.neural.interface import NeuralAdapter, NeuralAdapterInfo
from esp.adapters.physio.stream import SampleBlock, analyze, concat

F64 = NDArray[np.float64]
I64 = NDArray[np.int64]
_HOUR_NS: Final = 3600e9
_M1: Final = np.uint64(0xBF58476D1CE4E5B9)
_M2: Final = np.uint64(0x94D049BB133111EB)
_GOLD: Final = np.uint64(0x9E3779B97F4A7C15)


class Perturbation(StrEnum):
    JITTER = "jitter"
    DROPOUT = "dropout"
    CHANNEL_DEATH = "channel_death"
    CLOCK_DRIFT = "clock_drift"
    RECONNECT = "reconnect"
    DAY_DRIFT = "day_drift"
    GAIN_STEP = "gain_step"
    PACKET_LOSS = "packet_loss"
    ELECTRODE_REMOVAL = "electrode_removal"
    BURST_NOISE = "burst_noise"


P = Perturbation


@dataclass(frozen=True, slots=True)
class EmulatorConfig:
    """Declared perturbations. Times are nanoseconds relative to the first source sample."""

    seed: int = 0
    jitter_ns: float = 0.0
    dropout_rate: float = 0.0
    channel_death: tuple[tuple[str, int], ...] = ()
    clock_drift_ppm: float = 0.0
    reconnects: tuple[int, ...] = ()
    reconnect_gap_ns: int = 250_000_000
    reconnect_offset_ns: int = 7_345_679
    """Clock offset added after each reconnect; deliberately not a multiple of any period."""
    day_drift_gain_per_hour: float = 0.0
    """Relative gain change per hour of stream time (per-channel rate factor 0.5-1.5)."""
    day_drift_offset_per_hour: float = 0.0
    """Offset change per hour, in signal units (per-channel rate factor 0.5-1.5)."""
    gain_steps: tuple[tuple[int, float], ...] = ()
    packet_loss: float = 0.0
    electrode_removal: tuple[tuple[str, int], ...] = ()
    bursts: tuple[tuple[int, int, float], ...] = ()
    """``(start, duration, amplitude)``: added white noise with standard deviation ``amplitude``."""
    realtime: bool = False
    speed: float = 1.0

    def __post_init__(self) -> None:
        if not 0.0 <= self.dropout_rate < 1.0 or not 0.0 <= self.packet_loss < 1.0:
            msg = "dropout_rate and packet_loss must lie in [0, 1)"
            raise ValueError(msg)
        if self.jitter_ns < 0 or self.speed <= 0 or self.reconnect_gap_ns < 0:
            msg = "jitter, gap must be non-negative and speed positive"
            raise ValueError(msg)
        if any(f <= 0 for _, f in self.gain_steps):
            msg = "gain factors must be positive"
            raise ValueError(msg)

    def declared(self) -> frozenset[Perturbation]:
        p = Perturbation
        flags = {
            p.JITTER: self.jitter_ns > 0,
            p.DROPOUT: self.dropout_rate > 0,
            p.CHANNEL_DEATH: bool(self.channel_death),
            p.CLOCK_DRIFT: self.clock_drift_ppm != 0,
            p.RECONNECT: bool(self.reconnects),
            p.DAY_DRIFT: bool(self.day_drift_gain_per_hour or self.day_drift_offset_per_hour),
            p.GAIN_STEP: bool(self.gain_steps),
            p.PACKET_LOSS: self.packet_loss > 0,
            p.ELECTRODE_REMOVAL: bool(self.electrode_removal),
            p.BURST_NOISE: bool(self.bursts),
        }
        return frozenset(k for k, v in flags.items() if v)


@dataclass(frozen=True, slots=True)
class EmulatorEvent:
    kind: Perturbation
    t_ns: int
    """Stream time relative to the first source sample (source clock)."""
    channel: str | None = None
    detail: str = ""


@dataclass(frozen=True, slots=True)
class DescriptorChange:
    t_ns: int
    removed: tuple[str, ...]
    channels_after: tuple[str, ...]


# --- counter-based randomness (independent of chunking) ------------------------------------------


def _mix(x: NDArray[np.uint64]) -> NDArray[np.uint64]:
    z = x.copy()
    z ^= z >> np.uint64(30)
    z *= _M1
    z ^= z >> np.uint64(27)
    z *= _M2
    z ^= z >> np.uint64(31)
    return z


def _uniform(seed: int, tag: int, idx: NDArray[np.uint64]) -> F64:
    key = np.uint64((seed * 1_000_003 + tag) & 0xFFFFFFFFFFFFFFFF)
    with np.errstate(over="ignore"):
        z = _mix(idx * _GOLD + key)
    out: F64 = (z >> np.uint64(11)).astype(np.float64) * 2.0**-53
    return out


def _normal(seed: int, tag: int, idx: NDArray[np.uint64]) -> F64:
    u1 = np.maximum(_uniform(seed, 2 * tag, idx), 2.0**-53)
    u2 = _uniform(seed, 2 * tag + 1, idx)
    out: F64 = np.sqrt(-2.0 * np.log(u1)) * np.cos(2.0 * np.pi * u2)
    return out


_T_JITTER, _T_DROP, _T_BURST, _T_GAIN, _T_OFFS = 1, 2, 3, 4, 5
_MAX_CH: Final = 4096


class ImplantStreamEmulator:
    """A :class:`NeuralAdapter` that replays another adapter with declared perturbations."""

    def __init__(
        self,
        source: NeuralAdapter,
        config: EmulatorConfig | None = None,
        *,
        clock: Callable[[], int] = time.monotonic_ns,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._src = source
        self.config = config or EmulatorConfig()
        self._clock, self._sleep = clock, sleep
        src_info = source.info
        self._orig_names = tuple(c.name for c in src_info.channels)
        self._info = dataclasses.replace(src_info, adapter_id=f"{src_info.adapter_id}+emulator")
        self.events: list[EmulatorEvent] = []
        self.descriptor_changes: list[DescriptorChange] = []
        self._reset_state()

    def _reset_state(self) -> None:
        self._t0: int | None = None
        self._wall0: int | None = None
        self._pos = 0
        self._removed: set[str] = set()
        self._logged: set[tuple[Perturbation, str | int | None]] = set()
        self._block_rng = np.random.default_rng([self.config.seed, 0xB10C])
        rng = np.random.default_rng([self.config.seed, 0xC4])
        n = len(self._orig_names)
        self._gain_rate = rng.uniform(0.5, 1.5, n)
        self._offset_rate = rng.uniform(0.5, 1.5, n)

    # --- NeuralAdapter protocol -------------------------------------------------------------------

    @property
    def info(self) -> NeuralAdapterInfo:
        return self._info

    def start(self) -> None:
        self._src.start()

    def stop(self) -> None:
        self._src.stop()

    def read(self, max_samples: int) -> SampleBlock | None:
        while True:
            block = self._src.read(max_samples)
            if block is None:
                return None
            out = self._transform(block)
            if out is not None:
                self._pace(out)
                return out

    # --- internals --------------------------------------------------------------------------------

    def _log(self, kind: Perturbation, t: int, key: str | int | None = None, **kw: str) -> None:
        if (kind, key) in self._logged:
            return
        self._logged.add((kind, key))
        self.events.append(EmulatorEvent(kind, int(t), **kw))

    def _transform(self, block: SampleBlock) -> SampleBlock | None:
        if tuple(c.name for c in block.channels) != self._orig_names:
            msg = "source changed its channels; the emulator needs a fixed source layout"
            raise ValueError(msg)
        if self._t0 is None:
            self._t0 = int(block.timestamps_ns[0])
            continuous = {P.JITTER, P.DROPOUT, P.CLOCK_DRIFT, P.DAY_DRIFT}
            for kind in sorted(self.config.declared() & continuous):
                self._log(kind, 0, detail="enabled")
        n = block.n_samples
        idx = np.arange(self._pos, self._pos + n, dtype=np.uint64)
        self._pos += n
        t_rel = block.timestamps_ns.astype(np.int64) - self._t0
        values = self._perturb_values(np.array(block.values, dtype=np.float64), t_rel, idx)
        ts, keep = self._perturb_time(t_rel, idx)
        if self._lose_packet(t_rel, n):
            return None
        self._remove_electrodes(t_rel)
        if not keep.any():
            return None
        col = {name: i for i, name in enumerate(self._orig_names)}
        cols = [col[c.name] for c in self._info.channels]
        return SampleBlock(
            stream=block.stream,
            channels=self._info.channels,
            timestamps_ns=np.ascontiguousarray(ts[keep]),
            values=np.ascontiguousarray(values[keep][:, cols]),
            device=block.device,
            clock_domain=block.clock_domain,
            nominal_rate_hz=block.nominal_rate_hz,
        )

    def _perturb_values(self, values: F64, t_rel: I64, idx: NDArray[np.uint64]) -> F64:
        """Gain (day drift, steps), burst noise, channel death, dropout: all time/index based."""
        cfg = self.config
        n_ch = values.shape[1]
        hours = (t_rel / _HOUR_NS)[:, None]
        if cfg.day_drift_gain_per_hour:
            values *= 1.0 + cfg.day_drift_gain_per_hour * hours * self._gain_rate[None, :]
        if cfg.day_drift_offset_per_hour:
            values += cfg.day_drift_offset_per_hour * hours * self._offset_rate[None, :]
        for at, factor in cfg.gain_steps:
            hit = t_rel >= at
            if hit.any():
                values[hit] *= factor
                self._log(P.GAIN_STEP, max(at, int(t_rel[hit][0])), at, detail=f"x{factor}")
        cell = idx[:, None] * np.uint64(_MAX_CH) + np.arange(n_ch, dtype=np.uint64)[None, :]
        for start, dur, amp in cfg.bursts:
            hit = (t_rel >= start) & (t_rel < start + dur)
            if hit.any():
                values[hit] += amp * _normal(cfg.seed, _T_BURST, cell[hit].ravel()).reshape(
                    -1, n_ch
                )
                self._log(P.BURST_NOISE, int(t_rel[hit][0]), start, detail=f"sd {amp}")
        col = {name: i for i, name in enumerate(self._orig_names)}
        for name, at in cfg.channel_death:
            hit = t_rel >= at
            if hit.any() and name in col:
                values[hit, col[name]] = np.nan
                self._log(P.CHANNEL_DEATH, int(t_rel[hit][0]), name, channel=name)
        if cfg.dropout_rate:
            values[_uniform(cfg.seed, _T_DROP, idx) < cfg.dropout_rate] = np.nan
        return values

    def _perturb_time(self, t_rel: I64, idx: NDArray[np.uint64]) -> tuple[I64, NDArray[np.bool_]]:
        """Clock drift, reconnects (gap + new offset), jitter. Returns timestamps and kept rows."""
        cfg = self.config
        assert self._t0 is not None  # noqa: S101 - set by the first block
        ts = self._t0 + np.round(t_rel * (1.0 + cfg.clock_drift_ppm * 1e-6)).astype(np.int64)
        keep = np.ones(t_rel.size, dtype=bool)
        offset = np.zeros(t_rel.size, dtype=np.int64)
        for r in sorted(cfg.reconnects):
            gap = (t_rel >= r) & (t_rel < r + cfg.reconnect_gap_ns)
            after = t_rel >= r + cfg.reconnect_gap_ns
            keep &= ~gap
            offset[after] += cfg.reconnect_offset_ns
            if gap.any() or after.any():
                self._log(P.RECONNECT, r, r, detail=f"gap {cfg.reconnect_gap_ns} ns")
        ts = ts + offset
        if cfg.jitter_ns:
            ts = ts + np.round(cfg.jitter_ns * _normal(cfg.seed, _T_JITTER, idx)).astype(np.int64)
        return ts, keep

    def _lose_packet(self, t_rel: I64, n: int) -> bool:
        cfg = self.config
        if cfg.packet_loss and self._block_rng.random() < cfg.packet_loss:
            self._log(P.PACKET_LOSS, int(t_rel[0]), int(t_rel[0]), detail=f"{n} samples")
            return True
        return False

    def _remove_electrodes(self, t_rel: I64) -> None:
        """Block-granular removal; always a logged descriptor change and a new :attr:`info`."""
        newly = [
            name
            for name, at in self.config.electrode_removal
            if name not in self._removed and name in self._orig_names and int(t_rel[-1]) >= at
        ]
        if not newly:
            return
        self._removed.update(newly)
        kept = tuple(c for c in self._info.channels if c.name not in self._removed)
        desc = self._info.descriptor
        if desc is not None:
            desc = dataclasses.replace(
                desc, electrodes=tuple(e for e in desc.electrodes if e.name not in self._removed)
            )
        self._info = dataclasses.replace(self._info, channels=kept, descriptor=desc)
        self.descriptor_changes.append(
            DescriptorChange(int(t_rel[0]), tuple(newly), tuple(c.name for c in kept))
        )
        for name in newly:
            self._log(P.ELECTRODE_REMOVAL, int(t_rel[0]), name, channel=name)

    def _pace(self, block: SampleBlock) -> None:
        if not self.config.realtime or self._t0 is None:
            return
        now = self._clock()
        if self._wall0 is None:
            self._wall0 = now
        due = self._wall0 + (int(block.timestamps_ns[-1]) - self._t0) / self.config.speed
        wait = (due - now) / 1e9
        if wait > 0:
            self._sleep(wait)


# --- the reference consumer check -----------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DetectionReport:
    visible: frozenset[Perturbation]
    evidence: dict[str, float] = field(default_factory=dict)


def _step_vs_linear(y: F64) -> tuple[float, float, float, float]:
    """(total linear change, SSE linear, best one-break step size, SSE step)."""
    x = np.arange(y.size, dtype=np.float64)
    a, b = np.polyfit(x, y, 1)
    sse_lin = float(np.sum((y - (a * x + b)) ** 2))
    best_sse, best_step = float("inf"), 0.0
    for k in range(3, y.size - 2):
        lo, hi = y[:k], y[k:]
        sse = float(np.sum((lo - lo.mean()) ** 2) + np.sum((hi - hi.mean()) ** 2))
        if sse < best_sse:
            best_sse, best_step = sse, float(hi.mean() - lo.mean())
    return float(a * (y.size - 1)), sse_lin, best_step, best_sse


def _common_stream(
    blocks: Sequence[SampleBlock], rate: float, seen: set[Perturbation], ev: dict[str, float]
) -> tuple[SampleBlock, list[str]]:
    """Concatenate the channels present in every block; a changed channel set is a removal."""
    names = [tuple(c.name for c in b.channels) for b in blocks]
    common = [c for c in names[0] if all(c in n for n in names)]
    if any(n != names[0] for n in names):
        seen.add(P.ELECTRODE_REMOVAL)
        ev["channels_lost"] = float(len(names[0]) - len(common))
    parts = [
        SampleBlock(
            stream=b.stream,
            channels=tuple(c for c in b.channels if c.name in common),
            timestamps_ns=b.timestamps_ns,
            values=b.values[:, [i for i, c in enumerate(b.channels) if c.name in common]],
            device=b.device,
            clock_domain=b.clock_domain,
            nominal_rate_hz=rate,
        )
        for b in blocks
    ]
    return concat(parts), common


def _detect_timing(ts: I64, period: float, seen: set[Perturbation], ev: dict[str, float]) -> None:
    """Gaps (loss keeps the sample phase, a reconnect does not), jitter, clock drift."""
    d = np.diff(ts).astype(np.float64)
    for step in d[(d > 1.5 * period) | (d <= 0)]:
        k = step / period
        seen.add(P.RECONNECT if step <= 0 or abs(k - round(k)) > 0.1 else P.PACKET_LOSS)
    normal = (d > 0.5 * period) & (d < 1.5 * period)
    if normal.sum() > 10:
        dn = d[normal]
        spread = 1.4826 * float(np.median(np.abs(dn - np.median(dn))))
        ev["jitter_ns"] = spread
        if spread > 0.01 * period:
            seen.add(P.JITTER)
    seg = np.concatenate([[0], np.cumsum(~normal)])
    sxx = sxy = 0.0
    for s in np.unique(seg):
        m = seg == s
        if m.sum() >= 3:
            i = np.flatnonzero(m).astype(np.float64)
            t = ts[m].astype(np.float64)
            i -= i.mean()
            t -= t.mean()
            sxx += float(i @ i)
            sxy += float(i @ t)
    if sxx > 0:
        ev["clock_ppm"] = (sxy / sxx / period - 1.0) * 1e6
        if abs(ev["clock_ppm"]) > 20.0:
            seen.add(P.CLOCK_DRIFT)


def _detect_values(rows: F64, win: int, seen: set[Perturbation], ev: dict[str, float]) -> None:
    """Per-window scale and mean relative to the first window (median over channels)."""
    n_w = rows.shape[0] // win
    x = rows[: n_w * win].reshape(n_w, win, rows.shape[1])
    with np.errstate(all="ignore"):
        sd = np.nanstd(x, axis=1)
        mu = np.nanmean(x, axis=1)
    base_sd = np.where(sd[0] > 0, sd[0], 1.0)
    r = np.nanmedian(np.log(np.maximum(sd, 1e-12) / base_sd), axis=1)
    m = np.nanmedian((mu - mu[0]) / base_sd, axis=1)
    burst = r - np.median(r) > np.log(3.0)
    if burst.any() and burst.mean() <= 0.3:
        seen.add(P.BURST_NOISE)
        ev["burst_windows"] = float(burst.sum())
    for name, y, t_step, t_drift in (
        ("scale", r[~burst], np.log(1.4), np.log(1.2)),
        ("offset", m[~burst], 0.75, 0.5),
    ):
        if y.size < 8:
            continue
        lin, sse_lin, step, sse_step = _step_vs_linear(y)
        ev[f"{name}_linear"], ev[f"{name}_step"] = lin, step
        if abs(step) > t_step and sse_step < 0.5 * sse_lin:
            seen.add(P.GAIN_STEP)
        elif abs(lin) > t_drift and sse_lin <= sse_step:
            seen.add(P.DAY_DRIFT)


def detect(
    blocks: Sequence[SampleBlock], nominal_rate_hz: float, *, window_s: float = 1.0
) -> DetectionReport:
    """Which perturbations are visible in an emitted stream (no access to the event log)."""
    seen: set[Perturbation] = set()
    ev: dict[str, float] = {}
    stream, common = _common_stream(blocks, nominal_rate_hz, seen, ev)
    rep = analyze(stream)
    ev |= {"gaps": float(rep.gaps), "non_monotonic": float(rep.non_monotonic)}
    _detect_timing(stream.timestamps_ns.astype(np.int64), 1e9 / nominal_rate_hz, seen, ev)
    all_nan = np.isnan(stream.values).all(axis=1)
    rows = stream.values[~all_nan]
    if all_nan.any():
        seen.add(P.DROPOUT)
        ev["dropout_rows"] = float(all_nan.sum())
    win = max(8, round(window_s * nominal_rate_hz))
    alive = []
    for c in range(rows.shape[1]):
        finite = np.flatnonzero(np.isfinite(rows[:, c]))
        if finite.size and 0 < finite[-1] < rows.shape[0] - win:
            seen.add(P.CHANNEL_DEATH)
            ev[f"dead:{common[c]}"] = float(finite[-1])
        elif finite.size:
            alive.append(c)
    if alive and rows.shape[0] >= 12 * win:
        _detect_values(rows[:, alive], win, seen, ev)
    return DetectionReport(frozenset(seen), ev)
