"""kestrel CLI — typer entrypoint.

Subcommands:
    mcp        — start MCP server (alias of kestrel-mcp)
    version    — print version
    status     — session dashboard (proxy to heartbeat_status)
    state      — show state (top-level or per-machine)
    config     — init / show ~/.kestrel/config.toml
    debug      — tools-list, ssh-exec, msfrpc-ping
    fingerprint — legacy CLI for blind_fingerprint
    agent      — STUB v0.5
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import typer

from kestrel import __version__

app = typer.Typer(
    name="kestrel",
    help="HackTheBox engagement orchestrator — MCP server for AI-driven VM owning.",
    no_args_is_help=True,
)

config_app = typer.Typer(no_args_is_help=True, help="Manage ~/.kestrel/config.toml")
debug_app = typer.Typer(no_args_is_help=True, help="Diagnostics: tools-list, ssh-exec, msfrpc-ping")
state_app = typer.Typer(no_args_is_help=True, help="Inspect state (last-cycle.json + per-machine)")

app.add_typer(config_app, name="config")
app.add_typer(debug_app, name="debug")
app.add_typer(state_app, name="state")


DEFAULT_CONFIG_PATH = Path.home() / ".kestrel" / "config.toml"

DEFAULT_CONFIG_BODY = """# Kestrel config (~/.kestrel/config.toml)
# Environment variables override these values.

[paths]
state_dir = "C:/Proyectos/CobaltoSec/fleet/agents/htb/state"
session_root = "C:/Proyectos/CobaltoSec/sectors/red-team/htb-sessions"
kb_path = ""                # set to dir containing kb/query/smart.py

[kali]
host = "kali-pentest"
user = "kali"
key_path = "~/.ssh/kali-pentest"
htb_vpn_cmd = "bash ~/htb-vpn.sh"

[msfrpc]
host = "127.0.0.1"
port = 55553
user = "msf"
ssl = true
# password loaded from ~/.kestrel/msfrpc.secret (mode 0600)
"""


# ── top-level ────────────────────────────────────────────────────────────────


@app.command()
def version() -> None:
    """Print Kestrel version."""
    typer.echo(f"kestrel {__version__}")


@app.command()
def mcp(
    state_dir: str = typer.Option(None, "--state-dir"),
    session_root: str = typer.Option(None, "--session-root"),
    log_level: str = typer.Option("INFO", "--log-level"),
) -> None:
    """Start the Kestrel MCP server (stdio transport)."""
    from kestrel.mcp.server import main as mcp_main

    mcp_main(state_dir=state_dir, session_root=session_root, log_level=log_level)


@app.command()
def agent(
    machine: str = typer.Argument(..., help="Machine slug, e.g. 'kobold'"),
    mode: str = typer.Option("blind", "--mode", "-m", help="Engagement mode: blind | guided"),
    provider: str = typer.Option("anthropic", "--provider", help="LLM provider (only 'anthropic' supported)"),
    model: str = typer.Option("claude-sonnet-5", "--model", help="Anthropic model ID"),
    budget_tokens: int = typer.Option(200_000, "--budget-tokens", help="Max tokens before abort"),
    max_iter: int = typer.Option(60, "--max-iter", help="Max ReAct iterations"),
    state_dir: str = typer.Option(None, "--state-dir"),
    session_root: str = typer.Option(None, "--session-root"),
    verbose: bool = typer.Option(True, "--verbose/--quiet"),
) -> None:
    """Run the autonomous ReAct agent against a HTB machine."""
    import os
    from pathlib import Path
    from kestrel.agent.loop import ReActAgent

    if provider != "anthropic":
        typer.echo(f"Provider '{provider}' not yet supported. Only 'anthropic' is available.")
        raise typer.Exit(code=1)

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        typer.echo("Error: ANTHROPIC_API_KEY not set in environment.")
        raise typer.Exit(code=1)

    typer.echo(
        f"[kestrel-agent] Starting {mode} engagement: machine={machine} "
        f"model={model} budget={budget_tokens:,} tokens max_iter={max_iter}"
    )

    ag = ReActAgent(
        machine=machine,
        mode=mode,
        provider=provider,
        model=model,
        budget_tokens=budget_tokens,
        max_iterations=max_iter,
        state_dir=Path(state_dir) if state_dir else None,
        session_root=Path(session_root) if session_root else None,
        api_key=api_key,
        verbose=verbose,
    )
    metrics = ag.run()

    typer.echo("\n[kestrel-agent] Run complete:")
    import json
    typer.echo(json.dumps(metrics.to_dict(), indent=2, default=str))


@app.command()
def status(
    machine: str = typer.Option(None, "--machine", "-m", help="Machine slug; defaults to current_session."),
) -> None:
    """Show the heartbeat dashboard for the current (or specified) machine."""
    import asyncio

    from kestrel.mcp import context as mcp_context
    from kestrel.mcp.tools.heartbeat import heartbeat_status

    ctx = mcp_context.ServerContext.from_paths()
    mcp_context.set_context(ctx)
    if machine is None:
        state = ctx.state_store.read()
        if not state.data.current_session:
            typer.echo("No current_session. Pass --machine <slug>.")
            raise typer.Exit(code=1)
        for slug, m in state.data.machines.items():
            if m.session_slug == state.data.current_session:
                machine = slug
                break
    if machine is None:
        typer.echo("Could not resolve a machine.")
        raise typer.Exit(code=1)
    result = asyncio.run(heartbeat_status(machine=machine))
    typer.echo(json.dumps(result, indent=2, ensure_ascii=False, default=str))


@app.command()
def fingerprint(
    nmap: str = typer.Option(None, "--nmap"),
    target: str = typer.Option(None, "--target"),
    os: str = typer.Option("", "--os"),
    difficulty: str = typer.Option("Medium", "--difficulty"),
    ports_json: str = typer.Option(None, "--ports-json"),
    output: str = typer.Option(None, "--output"),
    no_kb: bool = typer.Option(False, "--no-kb"),
) -> None:
    """Legacy blind_fingerprint CLI — delegates to kestrel.core.fingerprint.main."""
    from kestrel.core import fingerprint as fp

    argv = ["fingerprint"]
    if nmap:
        argv += ["--nmap", nmap]
    if target:
        argv += ["--target", target]
    if os:
        argv += ["--os", os]
    if difficulty:
        argv += ["--difficulty", difficulty]
    if ports_json:
        argv += ["--ports-json", ports_json]
    if output:
        argv += ["--output", output]
    if no_kb:
        argv += ["--no-kb"]
    old_argv = sys.argv
    sys.argv = argv
    try:
        fp.main()
    finally:
        sys.argv = old_argv


# ── config subcommands ─────────────────────────────────────────────────────


@config_app.command("init")
def config_init(
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite if exists"),
    path: str = typer.Option(None, "--path", help="Override default config path"),
) -> None:
    """Write a default ~/.kestrel/config.toml (preserves existing unless --force)."""
    cfg_path = Path(path or DEFAULT_CONFIG_PATH)
    if cfg_path.exists() and not force:
        typer.echo(f"Config exists at {cfg_path}. Use --force to overwrite.")
        raise typer.Exit(code=1)
    cfg_path.parent.mkdir(parents=True, exist_ok=True)
    cfg_path.write_text(DEFAULT_CONFIG_BODY, encoding="utf-8")
    typer.echo(f"Wrote {cfg_path}")


@config_app.command("show")
def config_show(
    path: str = typer.Option(None, "--path"),
) -> None:
    """Print current ~/.kestrel/config.toml contents."""
    cfg_path = Path(path or DEFAULT_CONFIG_PATH)
    if not cfg_path.exists():
        typer.echo(f"Config not found at {cfg_path}. Run `kestrel config init`.")
        raise typer.Exit(code=1)
    typer.echo(cfg_path.read_text(encoding="utf-8"))


# ── state subcommands ──────────────────────────────────────────────────────


@state_app.command("show")
def state_show(
    machine: str = typer.Option(None, "--machine", "-m"),
) -> None:
    """Print the full state JSON or a single machine's slice."""
    from kestrel.mcp import context as mcp_context

    ctx = mcp_context.ServerContext.from_paths()
    state = ctx.state_store.read()
    if machine:
        m = state.data.machines.get(machine)
        if m is None:
            typer.echo(f"Machine '{machine}' not found.")
            raise typer.Exit(code=1)
        typer.echo(json.dumps(m.model_dump(mode="json", exclude_none=True), indent=2))
    else:
        typer.echo(json.dumps(state.model_dump(mode="json", exclude_none=True), indent=2))


# ── debug subcommands ──────────────────────────────────────────────────────


@debug_app.command("tools-list")
def debug_tools_list(
    category: str = typer.Option(None, "--category"),
) -> None:
    """List all registered MCP tools (with optional category filter)."""
    from kestrel.mcp import context as mcp_context
    from kestrel.mcp import registry
    from kestrel.mcp.server import _load_handler_modules

    ctx = mcp_context.ServerContext.from_paths()
    mcp_context.set_context(ctx)
    _load_handler_modules()

    tools = registry.all_tools()
    if category:
        tools = [t for t in tools if t.category == category]
    typer.echo(f"{len(tools)} tools:")
    for t in sorted(tools, key=lambda x: (x.category, x.name)):
        typer.echo(f"  [{t.category}] {t.name} — {t.description.splitlines()[0][:80]}")


@debug_app.command("ssh-exec")
def debug_ssh_exec(
    host: str = typer.Option(..., "--host"),
    user: str = typer.Option(None, "--user"),
    key: str = typer.Option(None, "--key"),
    cmd: str = typer.Option(..., "--cmd"),
) -> None:
    """One-shot SSH exec via paramiko — smoke test for transport layer."""
    from kestrel.transport.ssh import SSHSession

    sess = SSHSession(
        host=host,
        user=user or os.environ.get("KESTREL_KALI_USER", "kali"),
        key_path=key or os.environ.get("KESTREL_KALI_KEY", "~/.ssh/kali-pentest"),
    )
    sess.open()
    try:
        res = sess.exec(cmd, timeout=30.0)
        typer.echo(f"rc={res.rc} duration={res.duration_s}s")
        typer.echo("--- stdout ---")
        typer.echo(res.stdout)
        if res.stderr:
            typer.echo("--- stderr ---")
            typer.echo(res.stderr)
    finally:
        sess.close()


@debug_app.command("msfrpc-ping")
def debug_msfrpc_ping() -> None:
    """Health check for msfrpcd RPC reachability."""
    try:
        from kestrel.transport.msf import MSFRPCSession

        sess = MSFRPCSession.from_config()
        ok = sess.ping()
        typer.echo("msfrpc: UP" if ok else "msfrpc: DOWN")
        raise typer.Exit(code=0 if ok else 1)
    except typer.Exit:
        raise
    except Exception as exc:
        typer.echo(f"msfrpc: ERROR — {exc}")
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
