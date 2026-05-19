"""Kestrel MCP server entrypoint — STUB (filled in Fase 5).

Starts an MCP stdio server with tools/resources/prompts registered via kestrel.mcp.registry.
"""

from __future__ import annotations

import sys


def main(
    state_dir: str | None = None,
    session_root: str | None = None,
    log_level: str = "INFO",
) -> None:
    """Start the MCP server. Filled in Fase 5."""
    print(
        "kestrel-mcp v0.4.0-dev — stub (Fase 5 will implement actual MCP server).",
        file=sys.stderr,
    )
    print(f"  state_dir: {state_dir}", file=sys.stderr)
    print(f"  session_root: {session_root}", file=sys.stderr)
    print(f"  log_level: {log_level}", file=sys.stderr)
    sys.exit(0)


if __name__ == "__main__":
    main()
