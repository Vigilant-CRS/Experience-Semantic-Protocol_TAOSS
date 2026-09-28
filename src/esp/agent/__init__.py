# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""ESP-Agent profile: governance for latent machine communication (WP-067; V13 section 18).

- :mod:`esp.agent.descriptor`: the opaque-latent descriptor (TLV 0x98) with every
  V13 section 18.1 mandatory field, and the agent event (TLV 0x99) for causal audit;
- :mod:`esp.agent.companion`: the companion tensor stream, whose digest is bound to
  the ESP transcript and the recipient capability;
- :mod:`esp.agent.adapter`: ``g_agent`` (goal→INT, task context→CTX, facts→KNO).
  Its output may be called TAOSS only after a passed leakage audit;
- :mod:`esp.agent.audit`: a hash-chained event log and the causal audit;
- :mod:`esp.agent.demo`: two scripted agents exchanging INT/CTX/KNO over real ESP
  endpoints under capabilities.

Wrapping opaque bytes in ESP does **not** grant them TAOSS consent guarantees
(V13 section 18.1). Reports say so explicitly (:func:`esp.agent.companion.describe`).
"""
