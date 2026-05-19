"""Kestrel MCP server — stdio transport, async, SDK official.

Bridges the kestrel.mcp.registry decorators to the MCP SDK Server. Loads
all tool/prompt/resource modules at startup so their decorators register
into the global registry, then binds them to a Server instance.

Entry points:
    python -m kestrel.mcp.server [args]
    kestrel-mcp [args]              (console_script)
    kestrel mcp [args]              (typer subcommand wraps main())

Logs go to %LOCALAPPDATA%\\kestrel\\mcp.log (Windows) or ~/.local/share/kestrel/mcp.log (POSIX).
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import mcp.server.stdio
import mcp.types as types
from mcp.server import Server
from mcp.server.lowlevel import NotificationOptions
from mcp.server.models import InitializationOptions

from kestrel import __version__
from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry

logger = logging.getLogger("kestrel.mcp")


# ── Logging setup ────────────────────────────────────────────────────────────


def _log_path() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData" / "Local")))
        return base / "kestrel" / "mcp.log"
    return Path.home() / ".local" / "share" / "kestrel" / "mcp.log"


def setup_logging(log_level: str = "INFO") -> None:
    level = getattr(logging, log_level.upper(), logging.INFO)
    path = _log_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s :: %(message)s")
    )
    root = logging.getLogger()
    root.setLevel(level)
    # Avoid duplicate handlers on hot-reload
    if not any(isinstance(h, logging.FileHandler) and h.baseFilename == str(path) for h in root.handlers):
        root.addHandler(handler)


# ── Tool/prompt/resource module loader ───────────────────────────────────────


def _load_handler_modules() -> None:
    """Import every module under kestrel.mcp.tools / prompts / resources so their decorators fire."""
    import importlib
    import pkgutil

    for parent in ["kestrel.mcp.tools", "kestrel.mcp.prompts", "kestrel.mcp.resources"]:
        try:
            pkg = importlib.import_module(parent)
        except ImportError:
            continue
        for _finder, mod_name, _is_pkg in pkgutil.iter_modules(pkg.__path__):
            try:
                importlib.import_module(f"{parent}.{mod_name}")
                logger.debug("Loaded handler module: %s.%s", parent, mod_name)
            except Exception:
                logger.exception("Failed to load handler module %s.%s", parent, mod_name)


# ── Server construction ──────────────────────────────────────────────────────


def build_server() -> Server:
    """Build a fresh Server with all registered tools/prompts/resources bound."""
    server: Server = Server("kestrel")

    # ── list_tools ───────────────────────────────────────────────────────────
    @server.list_tools()
    async def _list_tools() -> list[types.Tool]:
        out: list[types.Tool] = []
        for spec in registry.all_tools():
            out.append(
                types.Tool(
                    name=spec.name,
                    description=spec.description,
                    inputSchema=spec.input_schema,
                )
            )
        return out

    # ── call_tool ────────────────────────────────────────────────────────────
    @server.call_tool()
    async def _call_tool(name: str, arguments: dict[str, Any] | None) -> list[types.TextContent]:
        spec = registry.get_tool(name)
        if spec is None:
            logger.warning("Unknown tool requested: %s", name)
            return [types.TextContent(type="text", text=json.dumps({"error": f"unknown tool: {name}"}))]
        args = arguments or {}
        try:
            result = await spec.handler(**args)
        except TypeError as e:
            logger.exception("Bad tool args for %s", name)
            return [types.TextContent(type="text", text=json.dumps({"error": f"bad args: {e}"}))]
        except Exception as e:
            logger.exception("Tool %s raised", name)
            return [
                types.TextContent(
                    type="text",
                    text=json.dumps({"error": "tool_exception", "tool": name, "message": str(e)}),
                )
            ]
        text = result if isinstance(result, str) else json.dumps(result, ensure_ascii=False, default=str)
        return [types.TextContent(type="text", text=text)]

    # ── list_prompts ─────────────────────────────────────────────────────────
    @server.list_prompts()
    async def _list_prompts() -> list[types.Prompt]:
        out: list[types.Prompt] = []
        for spec in registry.all_prompts():
            args = [
                types.PromptArgument(
                    name=a.get("name", ""),
                    description=a.get("description", ""),
                    required=a.get("required", False),
                )
                for a in spec.arguments
            ]
            out.append(types.Prompt(name=spec.name, description=spec.description, arguments=args))
        return out

    # ── get_prompt ───────────────────────────────────────────────────────────
    @server.get_prompt()
    async def _get_prompt(name: str, arguments: dict[str, str] | None) -> types.GetPromptResult:
        spec = registry.get_prompt(name)
        if spec is None:
            return types.GetPromptResult(
                description=f"Unknown prompt: {name}",
                messages=[
                    types.PromptMessage(
                        role="user",
                        content=types.TextContent(type="text", text=f"Prompt {name} not found."),
                    )
                ],
            )
        try:
            text = await spec.handler(**(arguments or {}))
        except Exception as e:
            logger.exception("Prompt %s raised", name)
            text = f"Prompt {name} failed: {e}"
        return types.GetPromptResult(
            description=spec.description,
            messages=[
                types.PromptMessage(role="user", content=types.TextContent(type="text", text=text))
            ],
        )

    # ── list_resources ───────────────────────────────────────────────────────
    @server.list_resources()
    async def _list_resources() -> list[types.Resource]:
        out: list[types.Resource] = []
        for spec in registry.all_resources():
            out.append(
                types.Resource(
                    uri=spec.uri,
                    name=spec.name,
                    description=spec.description,
                    mimeType=spec.mime_type,
                )
            )
        return out

    # ── read_resource ────────────────────────────────────────────────────────
    @server.read_resource()
    async def _read_resource(uri) -> str:
        # The SDK passes uri as pydantic AnyUrl object — normalize to string.
        uri_str = str(uri)
        spec = registry.get_resource(uri_str)
        if spec is None:
            # Try template match for kestrel://session/{machine}/... patterns
            for r in registry.all_resources():
                if _uri_template_matches(r.uri, uri_str):
                    spec = r
                    break
        if spec is None:
            return json.dumps({"error": f"unknown resource: {uri_str}"})
        try:
            return await spec.handler(uri_str)
        except Exception as e:
            logger.exception("Resource %s read failed", uri_str)
            return json.dumps({"error": "resource_exception", "uri": uri_str, "message": str(e)})

    return server


def _uri_template_matches(template: str, uri: str) -> bool:
    """Simple kestrel://session/{machine}/intel-style match."""
    if "{" not in template:
        return template == uri
    # Convert template to simple wildcard match
    pattern_parts = template.replace("{", "<").replace("}", ">").split("/")
    uri_parts = uri.split("/")
    if len(pattern_parts) != len(uri_parts):
        return False
    for p, u in zip(pattern_parts, uri_parts):
        if p.startswith("<") and p.endswith(">"):
            continue
        if p != u:
            return False
    return True


# ── Dummy handlers (verified in Fase 5 handshake; will be replaced in Fase 6/7/8) ────


@registry.tool(
    name="kestrel_ping",
    description="Health check — echoes a message with a timestamp. Used for MCP handshake validation.",
    category="meta",
)
async def _ping(message: str = "ping") -> dict[str, Any]:
    return {
        "pong": message,
        "ts": datetime.now(timezone.utc).isoformat(),
        "kestrel_version": __version__,
    }


@registry.tool(
    name="kestrel_version",
    description="Return Kestrel version + loaded tool/prompt/resource counts.",
    category="meta",
)
async def _version() -> dict[str, Any]:
    return {
        "version": __version__,
        "tools": len(registry.all_tools()),
        "prompts": len(registry.all_prompts()),
        "resources": len(registry.all_resources()),
    }


@registry.resource(
    uri="kestrel://config",
    name="config",
    description="Active server configuration (state dir, session root, version).",
)
async def _config_resource(uri: str) -> str:
    ctx = mcp_context.get_context()
    return json.dumps(
        {
            "version": __version__,
            "state_dir": str(ctx.state_dir),
            "session_root": str(ctx.session_root),
            "config": ctx.config,
            "tool_count": len(registry.all_tools()),
            "prompt_count": len(registry.all_prompts()),
            "resource_count": len(registry.all_resources()),
        },
        indent=2,
    )


@registry.prompt(
    name="kestrel_kickoff",
    description="Initial system prompt — Kestrel orchestrator role + phase guidelines.",
)
async def _kickoff() -> str:
    ctx = mcp_context.get_context()
    state = ctx.state_store.read()
    machines = state.data.machines
    if machines:
        machine_lines = "\n".join(
            f"  - {slug}: phase={state.data.current_phase} retired={m.machine_retired} mode={m.htb_mode}"
            for slug, m in machines.items()
        )
    else:
        machine_lines = "  (no machines tracked yet — start with htb_list_machines)"

    return f"""Sos Kestrel, orquestador HTB de CobaltoSec. Versión {__version__}.

Trabajás con phases p0-p5 (Setup, Recon, Vector decision, Exploit, Privesc, Close).
HITL solo en gates críticos (~3-4 por máquina): elección de máquina, vector exploit,
submit flag, debrief. Narración continua con 📡 (descubrir) 🔍 (analizar) 💡 (decidir)
➡ (avanzar). Anti-spoiler en intel (solo dirección, no comandos copy-paste).

Estado actual:
{machine_lines}

Comenzá con `phase_enter('p0_setup')` para arrancar una sesión nueva, o
`state_read` + `phase_current` para retomar la activa.
"""


# ── Entry point ──────────────────────────────────────────────────────────────


async def _async_main(state_dir: str | None, session_root: str | None) -> None:
    ctx = mcp_context.ServerContext.from_paths(state_dir=state_dir, session_root=session_root)
    mcp_context.set_context(ctx)
    _load_handler_modules()  # imports populate registry
    logger.info(
        "Kestrel MCP starting — version=%s tools=%d prompts=%d resources=%d state=%s",
        __version__,
        len(registry.all_tools()),
        len(registry.all_prompts()),
        len(registry.all_resources()),
        ctx.state_dir,
    )
    server = build_server()
    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="kestrel",
                server_version=__version__,
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def main(
    state_dir: str | None = None,
    session_root: str | None = None,
    log_level: str = "INFO",
) -> None:
    """Entrypoint for ``kestrel-mcp`` and ``kestrel mcp`` subcommand."""
    setup_logging(log_level)
    logger.info("kestrel-mcp invoked: state_dir=%s session_root=%s", state_dir, session_root)
    asyncio.run(_async_main(state_dir=state_dir, session_root=session_root))


if __name__ == "__main__":
    main()
