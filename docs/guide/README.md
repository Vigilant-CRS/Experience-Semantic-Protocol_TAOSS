<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ESP guides

Read them in this order:

1. [Vision](VISION.md): the Adriatic Moment, the North Star and the horizon. Start here.
2. [Scope](WHAT_ESP_IS_NOT.md): what ESP delivers today and where the frontier is.
3. [Psychology model](PSYCHOLOGY_MODEL.md): observation, feature, interpretation;
   `affect_scope`.
4. [Architecture](ARCHITECTURE.md): layers, trust boundaries, module map.
5. [Protocol walkthrough](PROTOCOL_WALKTHROUGH.md): one frame from sender to receiver.
6. [Consent examples](CONSENT_EXAMPLES.md): typed consent, bindings, revocation.
7. [Security examples](SECURITY_EXAMPLES.md): tamper evidence and malformed input.
8. [Adapter guide](ADAPTER_GUIDE.md): connecting sensors and files.
9. [Conformance](../CONFORMANCE.md): testing another implementation.
10. [Docking](DOCKING.md): how device makers, other implementations, agent frameworks and
    researchers connect to ESP.

Every ```` ```python ```` block in these guides is executed by `tests/unit/test_docs_examples.py`.
The examples therefore cannot silently go stale.
