#!/usr/bin/env python3
"""DEPRECATED: moved to kestrel.core.crack in v0.4. Will be removed in v0.5."""

import warnings as _warnings

_warnings.warn(
    "scripts/crack_status.py is deprecated. Use 'python -m kestrel.core.crack' "
    "or 'from kestrel.core.crack import ...'. Will be removed in v0.5.",
    DeprecationWarning,
    stacklevel=2,
)

from kestrel.core.crack import *  # noqa: F401, F403, E402
from kestrel.core.crack import main as _main  # noqa: E402

if __name__ == "__main__":
    _main()
