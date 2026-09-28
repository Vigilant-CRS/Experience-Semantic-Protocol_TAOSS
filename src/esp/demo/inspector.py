# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Sender/receiver inspector (WP-082): demo logs -> one self-contained HTML page.

Per packet it shows the cleartext header bits, the payload size, the
plaintext TLV *codes* after decryption (never values), whether any EMO wire
object is present, and the receiver's transparency view (present, masked,
bindings, provenance). The page carries the AGPL section 13 source link and
the NOTICE attribution.
"""

from __future__ import annotations

import html
import json
from pathlib import Path
from typing import Any, Final

SOURCE_URL: Final = "https://github.com/Vigilant-CRS/Experience-Semantic-Protocol_TAOSS"
EMO_CODES: Final = frozenset({"0x62", "0x92", "0x93", "0x50"})
CODE_NAMES: Final = {
    "0x23": "REVOCATION_INTENT",
    "0x50": "ANCHOR_COORDS",
    "0x60": "LATENT KNO",
    "0x61": "LATENT INT",
    "0x62": "LATENT EMO",
    "0x63": "LATENT CTX",
    "0x64": "LATENT SEN",
    "0x65": "LATENT TEM",
    "0x81": "SESSION_CLOSE",
    "0x86": "SOS",
    "0x90": "SEMANTIC_BINDING",
    "0x92": "AFFECT_DESCRIPTOR",
    "0x93": "EMOTION_EPISODE",
    "0x94": "INTENTION_STATE",
    "0x95": "FRAME_METADATA",
}

_CSS: Final = """
:root { --bg:#fbfbfa; --fg:#1d1d1b; --muted:#6b6b66; --line:#deded8; --card:#ffffff;
  --ok:#1f7a4d; --bad:#b3261e; --emo:#8a4fbf; --chip:#efefe9; }
@media (prefers-color-scheme: dark) { :root:not([data-theme="light"]) {
  --bg:#161615; --fg:#ecece6; --muted:#a3a39b; --line:#34342f; --card:#1f1f1d;
  --ok:#5cc28e; --bad:#ef7b72; --emo:#c29bea; --chip:#2a2a27; } }
:root[data-theme="dark"] { --bg:#161615; --fg:#ecece6; --muted:#a3a39b; --line:#34342f;
  --card:#1f1f1d; --ok:#5cc28e; --bad:#ef7b72; --emo:#c29bea; --chip:#2a2a27; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--fg);
  font:15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width:980px; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:22px; margin:0 0 4px; } h2 { font-size:17px; margin:28px 0 8px; }
p.lede, footer { color:var(--muted); }
.card { background:var(--card); border:1px solid var(--line); border-radius:10px;
  padding:12px 14px; margin:10px 0; overflow-wrap:anywhere; }
.row { display:flex; flex-wrap:wrap; gap:6px 14px; align-items:baseline; }
.chip { background:var(--chip); border-radius:6px; padding:1px 7px; font-size:13px;
  font-family:ui-monospace, SFMono-Regular, Menlo, monospace; }
.chip.emo { color:var(--emo); font-weight:600; }
.ok { color:var(--ok); font-weight:600; } .bad { color:var(--bad); font-weight:600; }
.label { color:var(--muted); font-size:13px; }
"""


def _chips(items: list[str], emo: frozenset[str] = frozenset()) -> str:
    if not items:
        return '<span class="label">none</span>'
    return " ".join(
        f'<span class="chip{" emo" if i in emo else ""}">{html.escape(i)}</span>' for i in items
    )


def _packet_card(p: dict[str, Any]) -> str:
    codes = list(p.get("plaintext_tlv_codes", []))
    named = [f"{c} {CODE_NAMES.get(c, '')}".strip() for c in codes]
    emo_named = frozenset(n for n, c in zip(named, codes, strict=True) if c in EMO_CODES)
    has_emo = bool(EMO_CODES & set(codes))
    status = (
        '<span class="ok">accepted</span>' if p["accepted"] else '<span class="bad">rejected</span>'
    )
    wire = p.get("wire_header", {})
    parts = [
        f'<div class="row"><strong>{html.escape(p["channel"])}</strong> {status}'
        f'<span class="label">seq {wire.get("segment_seq", "?")} · '
        f"{wire.get('payload_len', '?')} B payload</span></div>",
        f'<div class="row"><span class="label">cleartext header types</span>'
        f"{_chips(wire.get('types', []))}"
        '<span class="label">EMO_MASKED</span>'
        f'<span class="chip">{wire.get("emo_masked")}</span></div>',
        '<div class="row"><span class="label">decrypted TLV codes</span>'
        f"{_chips(named, emo_named)}</div>",
        '<div class="row"><span class="label">EMO in plaintext</span>'
        + ('<span class="chip emo">yes</span>' if has_emo else '<span class="ok">no</span>')
        + "</div>",
    ]
    if p.get("violations"):
        parts.append(
            f'<div class="row"><span class="label">violations</span>{_chips(p["violations"])}</div>'
        )
    frame = p.get("frame")
    if frame:
        bindings = [f"{b['source']} {b['relation']} {b['target']}" for b in frame["bindings"]]
        parts += [
            f'<div class="row"><span class="label">present</span>{_chips(frame["present_types"])}'
            f'<span class="label">masked</span>{_chips(frame["masked_types"])}</div>',
            f'<div class="row"><span class="label">bindings</span>{_chips(bindings)}</div>',
            f'<div class="row"><span class="label">provenance</span>'
            f'<span class="chip">{html.escape(str(frame["provenance"]["encoder_id"]))}</span>'
            f'<span class="label">consent</span>'
            f'<span class="chip">{html.escape(str(frame["consent_capability_id"]))}</span></div>',
        ]
    return '<div class="card">' + "".join(parts) + "</div>"


def render(events: list[dict[str, Any]], capture: list[dict[str, Any]]) -> str:
    steps = {
        (c["session"], c["header"]["segment_seq"], c["channel"]): c["step"]
        for c in capture
        if c["event"] == "captured"
    }
    body: list[str] = []
    for e in events:
        kind = e["event"]
        if kind == "session_start":
            body.append(f"<h2>Session {e['session']}</h2>")
        elif kind == "session_refused":
            body.append(
                f'<div class="card"><span class="bad">session refused</span> '
                f"{html.escape(e['reason'])}</div>"
            )
        elif kind == "packet":
            key = (e["session"], e.get("wire_header", {}).get("segment_seq"), e["channel"])
            step = steps.get(key)
            if step:
                body.append(f'<p class="label">sender step: {html.escape(step)}</p>')
            body.append(_packet_card(e))
    for c in capture:
        if c["event"] == "send_refused":
            body.append(
                '<div class="card"><span class="bad">sender refused</span> '
                f"session {c['session']}: {html.escape(c['reason'])}</div>"
            )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"<title>ESP Wire Inspector</title><style>{_CSS}</style></head><body><main>"
        "<h1>ESP wire inspector</h1>"
        '<p class="lede">Typed consent without natural language as the transport: what the '
        "network sees (cleartext header), what the receiver decrypted (TLV codes only), and what "
        "the application received.</p>"
        + "".join(body)
        + "<footer><p>Experience Semantic Protocol reference implementation, "
        "© Vigilant e.K. and contributors, AGPL-3.0-or-later. "
        f'Corresponding source (AGPL §13): <a href="{SOURCE_URL}">{SOURCE_URL}</a>. '
        "See NOTICE for required attribution.</p></footer></main></body></html>\n"
    )


def write_report(events_path: Path, capture_path: Path, out: Path) -> None:
    def load(p: Path) -> list[dict[str, Any]]:
        return [json.loads(line) for line in p.read_text(encoding="utf-8").splitlines() if line]

    out.write_text(render(load(events_path), load(capture_path)), encoding="utf-8")
