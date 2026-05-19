"""kestrel CLI — typer entrypoint.

Subcommands (filled in by Fase 9):
    mcp        — start MCP server (alias of kestrel-mcp)
    agent      — public agent runner (STUB v0.5)
    status     — session dashboard
    config     — manage ~/.kestrel/config.toml
    state      — read state
    debug      — diagnostics (tools-list, ssh-exec, msfrpc-ping)
    fingerprint — legacy CLI for blind_fingerprint
"""

from __future__ import annotations

import typer

from kestrel import __version__

app = typer.Typer(
    name="kestrel",
    help="HackTheBox engagement orchestrator — MCP server for AI-driven VM owning.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Print Kestrel version."""
    typer.echo(f"kestrel {__version__}")


@app.command()
def mcp(
    state_dir: str = typer.Option(
        None,
        "--state-dir",
        help="State directory (defaults to ~/.kestrel/state or config).",
    ),
    session_root: str = typer.Option(
        None,
        "--session-root",
        help="Session artifacts root (defaults to ~/.kestrel/sessions).",
    ),
    log_level: str = typer.Option("INFO", "--log-level"),
) -> None:
    """Start the Kestrel MCP server (stdio transport)."""
    from kestrel.mcp.server import main as mcp_main

    mcp_main(state_dir=state_dir, session_root=session_root, log_level=log_level)


@app.command()
def agent() -> None:
    """Public agent runner — DEFERRED to v0.5."""
    typer.echo("Public agent runner not yet implemented. See v0.5 roadmap in CHANGELOG.md.")
    raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
