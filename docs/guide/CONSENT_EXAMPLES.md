<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# Consent examples

Consent in ESP is **typed**: a capability names the TAOSS types it covers. A type that one side
did not consent to is **absent from the wire**. It is not encrypted-but-present, and it is not
zero-filled.

## The receiver declines EMO

```python
from esp.demo.ui import run_exchange

base = {"emotions": {"fear": 4}, "valence": 1, "share_binding": True}
full = ["KNO", "INT", "EMO", "CTX"]
r = run_exchange(base | {"sender_types": full, "receiver_types": ["KNO", "INT", "CTX"]})
assert r["ok"] and not r["emo_in_plaintext"]
assert not any("EMO" in code for code in r["decrypted_tlv"])
assert r["wire"]["header"]["types"] == ["KNO", "INT", "CTX"]
```

Emotional content is withheld even though the sender allowed it. The receiver's capability
did not accept it, and the intersection decides.

## The sender withholds EMO

```python
r = run_exchange(base | {"sender_types": ["KNO", "INT", "CTX"], "receiver_types": full})
assert r["ok"] and not r["emo_in_plaintext"]
```

## No receiver capability means deny by default

```python
r = run_exchange(base | {"sender_types": full, "receiver_types": []})
assert not r["ok"] and r["stage"] == "establishment"
```

## Bindings need their own consent

An EMO→KNO binding ("this fear is about possible dismissal") links two types. It is sent only
when the disclosure policy explicitly allows the relation.

```python
with_binding = run_exchange(base | {"sender_types": full, "receiver_types": full})
without = run_exchange(base | {"sender_types": full, "receiver_types": full, "share_binding": False})
assert any("SEMANTIC_BINDING" in c for c in with_binding["decrypted_tlv"])
assert not any("SEMANTIC_BINDING" in c for c in without["decrypted_tlv"])
```

## Revocation

A `RevocationIntent` (TLV 0x23) is signed by the lineage master and sent on CONTROL. It can
cover a capability, a type or the whole session, and it is effective from a given sequence
number. The receiver then refuses later frames in that scope. The live demo
(`make demo`, milestone M5) shows the sequence: consent, then revoke, then a refused resend.
See `tests/integration/test_endpoint.py` for the complete API.

The interactive version runs with `uv run esp-demo ui` at <http://127.0.0.1:8080/>.
