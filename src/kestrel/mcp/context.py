"""Server context — singleton state available to tool/prompt/resource handlers.

Initialized once in ``kestrel.mcp.server.main()`` and accessed via
``get_context()`` from any handler in ``kestrel.mcp.tools.*``.

Lazy-initialized in tests via ``ServerContext.from_env()`` or via direct
construction.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kestrel.state.store import StateStore
from kestrel.transport.base import SessionRegistry


@dataclass
class ServerContext:
    """Singleton state passed implicitly via module-global ``_context``."""

    state_dir: Path
    session_root: Path
    state_store: StateStore
    sessions: SessionRegistry = field(default_factory=SessionRegistry)
    config: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_paths(
        cls,
        state_dir: Path | str | None = None,
        session_root: Path | str | None = None,
    ) -> "ServerContext":
        sd = Path(state_dir or _default_state_dir())
        sr = Path(session_root or _default_session_root())
        sd.mkdir(parents=True, exist_ok=True)
        sr.mkdir(parents=True, exist_ok=True)
        store = StateStore(sd / "last-cycle.json")
        return cls(state_dir=sd, session_root=sr, state_store=store)


_context: ServerContext | None = None


def set_context(ctx: ServerContext) -> None:
    global _context
    _context = ctx


def get_context() -> ServerContext:
    """Return the active ServerContext. Raises if not initialized."""
    if _context is None:
        raise RuntimeError(
            "kestrel ServerContext not initialized. "
            "Call kestrel.mcp.context.set_context(ServerContext.from_paths(...)) first."
        )
    return _context


def reset_context() -> None:
    """Tests only — clear singleton."""
    global _context
    _context = None


def _default_state_dir() -> Path:
    """Resolve state dir: env > home convention."""
    env = os.environ.get("KESTREL_STATE_DIR")
    if env:
        return Path(env)
    # Mirror the existing fleet location if in CobaltoSec repo, else fall back to home
    fleet = Path("C:/Proyectos/CobaltoSec/fleet/agents/htb/state")
    if fleet.parent.exists():
        return fleet
    return Path.home() / ".kestrel" / "state"


def _default_session_root() -> Path:
    env = os.environ.get("KESTREL_SESSION_ROOT")
    if env:
        return Path(env)
    sessions = Path("C:/Proyectos/CobaltoSec/sectors/red-team/htb-sessions")
    if sessions.parent.exists():
        return sessions
    return Path.home() / ".kestrel" / "sessions"


__all__ = ["ServerContext", "get_context", "reset_context", "set_context"]
