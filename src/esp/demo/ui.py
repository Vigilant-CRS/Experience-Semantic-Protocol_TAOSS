# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Interactive sender/receiver inspector (WP-082).

``esp-demo ui --port 8080`` serves one local page (bound to 127.0.0.1 only):

- enter a structured state (Likert sliders, action readiness, context,
  knowledge reference);
- set consent switches per type (sender capability), per binding, and the
  receiver's accepted types;
- every click runs a *real* exchange: fresh Noise handshake, capabilities,
  sealed packet, quarantined receive, audited decoders.

The response shows the cleartext header, the ciphertext size, the plaintext
TLV codes after decryption, proof that EMO is absent when it is not
consented, the receiver's view and the decoder transparency panel. The page
shows the AGPL section 13 source link and the NOTICE attribution.
"""

from __future__ import annotations

import html
import json
import secrets
import tempfile
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Final

from esp.codec.header import HEADER_LEN, Header
from esp.codec.tlv import ParsedPayload
from esp.consent.capability import AudienceMode, ReceiverCapability, Rights, SenderCapability
from esp.core.errors import EspError
from esp.core.taoss_types import TaossType, types_to_bitmap
from esp.crypto.noise_ik import StaticKeyPair
from esp.crypto.primitives import SigningKey
from esp.demo.cli import (
    DECLARATION,
    STATE,
    decode_view,
    demo_decoders,
    descriptor,
    frame_view,
    header_view,
    wire,
)
from esp.demo.compose import DemoState, compose_frame
from esp.demo.inspector import CODE_NAMES, EMO_CODES, SOURCE_URL
from esp.frame.model import DisclosurePolicy
from esp.semantics.bindings import BindingPolicy, RelationClass
from esp.session.endpoint import ReceiverEndpoint, SenderEndpoint

T = TaossType
UI_TYPES: Final = (T.KNO, T.INT, T.EMO, T.CTX)
EMOTIONS: Final = (
    "joy",
    "trust",
    "fear",
    "surprise",
    "sadness",
    "anger",
    "disgust",
    "anticipation",
)
MAX_BODY: Final = 16 * 1024
HOUR_NS: Final = 3600 * 10**9


def _types(names: object) -> frozenset[TaossType]:
    if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
        msg = "type lists must be lists of names"
        raise ValueError(msg)
    allowed = {t.name: t for t in UI_TYPES}
    unknown = set(names) - set(allowed)
    if unknown:
        msg = f"unknown types: {sorted(unknown)}"
        raise ValueError(msg)
    return frozenset(allowed[n] for n in names)


def _rating(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 1 <= value <= 5:
        msg = f"{name} must be an integer 1..5"
        raise ValueError(msg)
    return value


def _short(value: object, name: str) -> str:
    if not isinstance(value, str) or not 0 < len(value) <= 64:
        msg = f"{name} must be a 1..64 character string"
        raise ValueError(msg)
    return value


def parse_request(
    data: dict[str, Any],
) -> tuple[DemoState, frozenset[TaossType], frozenset[TaossType], bool]:
    """Validate untrusted UI input into (state, sender types, receiver types, share binding)."""
    emotions = data.get("emotions", {})
    if not isinstance(emotions, dict) or set(emotions) - set(EMOTIONS):
        msg = "emotions must map basic-8 labels to ratings"
        raise ValueError(msg)
    state = DemoState(
        emotions={k: _rating(v, k) for k, v in emotions.items()},
        valence=_rating(data.get("valence", 3), "valence"),
        arousal=_rating(data.get("arousal", 3), "arousal"),
        readiness={"avoid": _rating(data.get("avoid", 3), "avoid")},
        context=(_short(data.get("context", "work"), "context"),),
        knowledge=(_short(data.get("knowledge", "topic"), "knowledge"),),
    )
    return (
        state,
        _types(data.get("sender_types", [])),
        _types(data.get("receiver_types", [])),
        bool(data.get("share_binding", False)),
    )


def run_exchange(data: dict[str, Any]) -> dict[str, Any]:
    """One full ESP exchange in-process with the chosen consent. Never raises for bad consent."""
    try:
        state, sender_types, receiver_types, share_binding = parse_request(data)
    except ValueError as exc:
        return {"ok": False, "stage": "input", "error": str(exc)}
    master, identity = SigningKey.generate(), SigningKey.generate()
    r_static = StaticKeyPair.generate()
    now = time.time_ns()
    inspected: dict[str, Any] = {}

    def inspector(h: Header, parsed: ParsedPayload) -> None:
        inspected["header"] = header_view(h)
        inspected["plaintext_tlv_codes"] = [f"0x{t.code:02x}" for t in parsed.known]

    def receiver_cap(noise_h: bytes) -> ReceiverCapability:
        return ReceiverCapability(
            accept_types=types_to_bitmap(receiver_types),
            max_norm=(10.0,) * len(receiver_types),
            valence_bounds=(-1.0, 1.0) if T.EMO in receiver_types else None,
            rate_limit_hz=100,
            valid_from_ns=now - HOUR_NS,
            valid_until_ns=now + HOUR_NS,
            nonce=secrets.token_bytes(16),
            pk_receiver=identity.public_bytes,
            noise_h=noise_h,
        )

    with tempfile.TemporaryDirectory() as state_dir:
        try:
            sender = SenderEndpoint(
                master=master,
                static=StaticKeyPair.generate(),
                responder_static=r_static.public_bytes,
                receiver_identity=identity.public_bytes,
                descriptor=descriptor(),
                capability=SenderCapability(
                    capability_id=uuid.uuid4(),
                    types_allowed=types_to_bitmap(sender_types),
                    rights=Rights(0),
                    max_segments=10,
                    dp_epsilon_ceiling=0.0,
                    valid_until_ns=now + HOUR_NS,
                    audience_mode=AudienceMode.RECIPIENT_PUBKEY,
                    audience_value=identity.public_bytes,
                    issuer_pk=master.public_bytes,
                    nonce=secrets.token_bytes(16),
                ),
                state_dir=Path(state_dir),
                wire=wire(),
                declaration=DECLARATION,
            )
            receiver = ReceiverEndpoint(
                identity=identity,
                static=r_static,
                descriptor=descriptor(),
                capability=receiver_cap if receiver_types else None,
                trusted_issuers=frozenset({master.public_bytes}),
                wire=wire(),
                declaration=DECLARATION,
                inspector=inspector,
            )
            hs2, t1 = receiver.on_handshake1(sender.start())
            sender.on_handshake2(hs2)
            receiver.on_transport2(sender.on_transport1(t1))
        except EspError as exc:
            return {"ok": False, "stage": "establishment", "error": str(exc)}
        frame = compose_frame(state, timeline_id=sender.timeline_id, sequence=1, now_ns=now)
        bindings = (
            BindingPolicy(allowed_relations=(RelationClass.ELICITED_BY,))
            if share_binding
            else BindingPolicy()
        )
        policy = DisclosurePolicy(allowed_types=UI_TYPES, bindings=bindings)
        try:
            packet = sender.send_frame(frame, policy, now_ns=now)
        except EspError as exc:
            return {"ok": False, "stage": "send", "error": str(exc)}
        result = receiver.receive(packet, now_ns=now)
    codes = inspected.get("plaintext_tlv_codes", [])
    return {
        "ok": result.accepted,
        "stage": "receive",
        "wire": {
            "header": header_view(Header.decode(packet[:HEADER_LEN])),
            "packet_bytes": len(packet),
            "ciphertext_hex_prefix": packet[HEADER_LEN : HEADER_LEN + 32].hex(),
        },
        "decrypted_tlv": [f"{c} {CODE_NAMES.get(c, '')}".strip() for c in codes],
        "emo_in_plaintext": bool(EMO_CODES & set(codes)),
        "violations": list(result.violations),
        "frame": frame_view(result.frame) if result.frame is not None else None,
        "decoded": decode_view(result.frame, demo_decoders()) if result.frame is not None else None,
    }


_PAGE: Final = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ESP Consent Inspector</title><style>
:root{--bg:#fbfbfa;--fg:#1d1d1b;--muted:#6b6b66;--line:#deded8;--card:#fff;--accent:#2f5d8a;
--ok:#1f7a4d;--bad:#b3261e;--emo:#8a4fbf}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#161615;--fg:#ecece6;
--muted:#a3a39b;--line:#34342f;--card:#1f1f1d;--accent:#8db4dc;--ok:#5cc28e;--bad:#ef7b72;--emo:#c29bea}}
:root[data-theme="dark"]{--bg:#161615;--fg:#ecece6;--muted:#a3a39b;--line:#34342f;--card:#1f1f1d;
--accent:#8db4dc;--ok:#5cc28e;--bad:#ef7b72;--emo:#c29bea}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif}
main{max-width:1040px;margin:0 auto;padding:24px 16px 48px}
.grid{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1.4fr);gap:16px}
@media (max-width:760px){.grid{grid-template-columns:minmax(0,1fr)}}
.card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px;
overflow-wrap:anywhere}
h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:0 0 8px}
label{display:flex;justify-content:space-between;gap:8px;margin:4px 0}
.muted{color:var(--muted);font-size:13px}fieldset{border:1px solid var(--line);border-radius:8px;
margin:10px 0;padding:8px 10px}button{background:var(--accent);color:#fff;border:0;
border-radius:8px;padding:9px 16px;font-size:15px;cursor:pointer;width:100%}
pre{white-space:pre-wrap;font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;margin:0}
.ok{color:var(--ok);font-weight:600}.bad{color:var(--bad);font-weight:600}.emo{color:var(--emo)}
input[type=text]{width:9em}
</style></head><body><main>
<h1>ESP consent inspector</h1>
<p class="muted">A structured state is shared under typed consent. No natural language is used as
the transport representation. Each run performs a real handshake and a real sealed packet.</p>
<div class="grid"><form class="card" id="f"><h2>Sender state</h2>
__SLIDERS__
<label>context <input type="text" name="context" value="work"></label>
<label>knowledge ref <input type="text" name="knowledge" value="possible_dismissal"></label>
<fieldset><legend>Sender consent (capability)</legend>__SENDER__
<label>share EMO&rarr;KNO binding <input type="checkbox" name="share_binding" checked></label>
</fieldset>
<fieldset><legend>Receiver accepts</legend>__RECEIVER__</fieldset>
<button type="submit">Send one frame</button></form>
<div class="card"><h2>Result</h2><div id="status" class="muted">Not run yet.</div>
<pre id="out"></pre></div></div>
<footer class="muted"><p>Experience Semantic Protocol reference implementation,
&copy; Vigilant e.K. and contributors, AGPL-3.0-or-later.
Corresponding source (AGPL &sect;13): <a href="__SOURCE__">__SOURCE__</a>.
See NOTICE for required attribution.</p></footer></main>
<script>
const f=document.getElementById('f');
f.addEventListener('submit',async e=>{e.preventDefault();const d=new FormData(f);
const emotions={};for(const k of __EMOTIONS__){const v=+d.get('emo_'+k);if(v>1)emotions[k]=v}
const body={emotions,valence:+d.get('valence'),arousal:+d.get('arousal'),avoid:+d.get('avoid'),
context:d.get('context'),knowledge:d.get('knowledge'),share_binding:d.get('share_binding')==='on',
sender_types:d.getAll('s'),receiver_types:d.getAll('r')};
const status=document.getElementById('status');status.textContent='running…';
try{const r=await fetch('/run',{method:'POST',headers:{'Content-Type':'application/json'},
body:JSON.stringify(body)});const j=await r.json();
status.className=j.ok?'ok':'bad';
status.textContent=j.ok?('accepted — EMO in decrypted payload: '+(j.emo_in_plaintext?'yes':'no'))
:('refused at '+j.stage+': '+(j.error||(j.violations||[]).join('; ')));
document.getElementById('out').textContent=JSON.stringify(j,null,2);}
catch(err){status.className='bad';status.textContent='request failed: '+err}});
</script></body></html>"""


def page() -> str:
    def slider(name: str, value: int) -> str:
        n = html.escape(name)
        return f'<label>{n} <input type="range" name="{n}" min="1" max="5" value="{value}"></label>'

    sliders = "".join(
        [slider("valence", 2), slider("arousal", 4), slider("avoid", 5)]
        + [slider(f"emo_{e}", STATE.emotions.get(e, 1)) for e in EMOTIONS]
    )

    def boxes(prefix: str, checked: set[TaossType]) -> str:
        return "".join(
            f'<label>{t.name} <input type="checkbox" name="{prefix}" value="{t.name}"'
            f"{' checked' if t in checked else ''}></label>"
            for t in UI_TYPES
        )

    return (
        _PAGE.replace("__SLIDERS__", sliders)
        .replace("__SENDER__", boxes("s", {T.KNO, T.INT, T.CTX}))
        .replace("__RECEIVER__", boxes("r", set(UI_TYPES)))
        .replace("__EMOTIONS__", json.dumps(list(EMOTIONS)))
        .replace("__SOURCE__", SOURCE_URL)
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "esp-demo-ui"

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'",
        )
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path != "/":
            self._send(404, b"not found", "text/plain")
            return
        self._send(200, page().encode(), "text/html; charset=utf-8")

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0") or 0)
        if self.path != "/run" or not 0 < length <= MAX_BODY:
            self._send(400, b'{"ok":false,"error":"bad request"}', "application/json")
            return
        try:
            data = json.loads(self.rfile.read(length))
            if not isinstance(data, dict):
                raise TypeError
        except (ValueError, TypeError):
            self._send(400, b'{"ok":false,"error":"invalid JSON"}', "application/json")
            return
        self._send(200, json.dumps(run_exchange(data)).encode(), "application/json")

    def log_message(self, format: str, *args: object) -> None:
        return  # quiet: no request logs with user state


def make_server(port: int) -> ThreadingHTTPServer:
    return ThreadingHTTPServer(("127.0.0.1", port), Handler)
