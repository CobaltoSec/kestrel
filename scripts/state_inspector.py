#!/usr/bin/env python3
"""DEPRECATED: moved to kestrel.core.state_inspector in v0.4. Will be removed in v0.5."""

import warnings as _warnings

_warnings.warn(
    "scripts/state_inspector.py is deprecated. Use 'python -m kestrel.core.state_inspector' "
    "or 'from kestrel.core.state_inspector import ...'. Will be removed in v0.5.",
    DeprecationWarning,
    stacklevel=2,
)

from kestrel.core.state_inspector import *  # noqa: F401, F403, E402
from kestrel.core.state_inspector import main as _main  # noqa: E402

if __name__ == "__main__":
    _main()
