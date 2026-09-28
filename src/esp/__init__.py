# SPDX-FileCopyrightText: 2026 Vigilant e.K. and contributors
# SPDX-License-Identifier: AGPL-3.0-or-later
"""Experience Semantic Protocol (ESP) V13 / TAOSS reference implementation.

ESP transports typed, provenance-carrying, consent-bound semantic
representations. It does not read minds, transfer consciousness, or
reliably detect emotions (see docs/MASTER_IMPLEMENTATION_PLAN.md, section 4).
"""

from typing import Final

__version__: Final = "0.0.1"

#: Normative source this implementation targets.
SPEC_VERSION: Final = "V13"

#: Wire format major/minor version (V13 Appendix A).
WIRE_VERSION: Final = (1, 0)

__all__ = ["SPEC_VERSION", "WIRE_VERSION", "__version__"]
