#!/usr/bin/env python3
"""DEPRECATED: moved to kestrel.core.stuck in v0.4. Will be removed in v0.5."""

import warnings as _warnings

_warnings.warn(
    "scripts/stuck_detector.py is deprecated. Use 'python -m kestrel.core.stuck' "
    "or 'from kestrel.core.stuck import ...'. Will be removed in v0.5.",
    DeprecationWarning,
    stacklevel=2,
)

from kestrel.core.stuck import *  # noqa: F401, F403, E402
from kestrel.core.stuck import main as _main  # noqa: E402

if __name__ == "__main__":
    _main()
