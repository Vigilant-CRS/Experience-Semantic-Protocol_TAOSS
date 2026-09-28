<!--
SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
SPDX-License-Identifier: CC-BY-SA-4.0
-->

# ESP guides

Read them in this order:

1. [What ESP is not](WHAT_ESP_IS_NOT.md): start here.
2. [Psychology model](PSYCHOLOGY_MODEL.md): observation, feature, interpretation;
   `affect_scope`.
3. [Architecture](ARCHITECTURE.md): layers, trust boundaries, module map.
4. [Protocol walkthrough](PROTOCOL_WALKTHROUGH.md): one frame from sender to receiver.
5. [Consent examples](CONSENT_EXAMPLES.md): typed consent, bindings, revocation.
6. [Security examples](SECURITY_EXAMPLES.md): tamper evidence and malformed input.
7. [Adapter guide](ADAPTER_GUIDE.md): connecting sensors and files.
8. [Conformance](../CONFORMANCE.md): testing another implementation.

Every ```` ```python ```` block in these guides is executed by `tests/unit/test_docs_examples.py`.
The examples therefore cannot silently go stale.
