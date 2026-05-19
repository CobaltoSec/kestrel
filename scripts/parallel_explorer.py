#!/usr/bin/env python3
"""DEPRECATED: moved to kestrel.core.parallel in v0.4. Will be removed in v0.5."""

import warnings as _warnings

_warnings.warn(
    "scripts/parallel_explorer.py is deprecated. Use 'python -m kestrel.core.parallel' "
    "or 'from kestrel.core.parallel import ...'. Will be removed in v0.5.",
    DeprecationWarning,
    stacklevel=2,
)

from kestrel.core.parallel import *  # noqa: F401, F403, E402
from kestrel.core.parallel import main as _main  # noqa: E402

if __name__ == "__main__":
    _main()
