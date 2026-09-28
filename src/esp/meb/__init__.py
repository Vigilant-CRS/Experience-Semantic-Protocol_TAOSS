# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Machine Experience Bridge (WP-066; V13 section 17).

- :mod:`esp.meb.profiles`: ``T_mach``, the domain profiles and the
  machine-to-human (M2H) asymmetric defaults;
- :mod:`esp.meb.adapter`: the machine adapter interface ``g_mach(S, U, M)`` and
  machine-authored frames (EMO is never authored, always explicitly masked);
- :mod:`esp.meb.handover`: a deterministic vehicle-to-driver handover simulator;
- :mod:`esp.meb.alignment`: block-preserving cross-domain alignment with cycle
  loss, the eta-compatibility metric and declared cross-type adapters under a
  mandatory leakage audit (EXPERIMENTAL).
"""
