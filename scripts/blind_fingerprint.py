#!/usr/bin/env python3
"""DEPRECATED: moved to kestrel.core.fingerprint in v0.4. Will be removed in v0.5.

This shim preserves CLI and import compatibility:
    python scripts/blind_fingerprint.py --help     # still works
    from scripts.blind_fingerprint import score_rules  # still works (via re-export)
"""

import warnings as _warnings

_warnings.warn(
    "scripts/blind_fingerprint.py is deprecated. Use 'python -m kestrel.core.fingerprint' "
    "or 'from kestrel.core.fingerprint import ...'. Will be removed in v0.5.",
    DeprecationWarning,
    stacklevel=2,
)

from kestrel.core.fingerprint import *  # noqa: F401, F403, E402
from kestrel.core.fingerprint import main as _main  # noqa: E402

if __name__ == "__main__":
    _main()
