"""MCP tools — generic session management (SSH / WinRM / MSF handles)."""

from __future__ import annotations

import asyncio
from typing import Any

from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry
from kestrel.transport.base import Session
from kestrel.transport.msf import MSFRPCSession
from kestrel.transport.ssh import SSHSession


@registry.tool(
    name="session_open",
    description=(
        "Open a transport session (ssh|winrm|msf) and register it. Returns handle_id for subsequent session_exec calls. "
        "params shape depends on transport: ssh={host,user,key_path|password,port?}, msf={} (uses RPC config), winrm={host,user,password|cert}."
    ),
    category="session",
    input_schema={
        "type": "object",
        "properties": {
            "transport": {"type": "string", "enum": ["ssh", "winrm", "msf"]},
            "params": {"type": "object"},
        },
        "required": ["transport", "params"],
    },
)
async def session_open(transport: str, params: dict[str, Any]) -> dict[str, Any]:
    ctx = mcp_context.get_context()
    transport_l = transport.lower()
    sess: Session
    if transport_l == "ssh":
        sess = SSHSession(
            host=params["host"],
            user=params["user"],
            port=int(params.get("port", 22)),
            key_path=params.get("key_path"),
            password=params.get("password"),
        )
    elif transport_l == "msf":
        sess = MSFRPCSession.from_config()
    elif transport_l == "winrm":
        try:
            from kestrel.transport.winrm import WinRMSession  # type: ignore
        except Exception as exc:
            return {"error": "winrm_unavailable", "message": str(exc)}
        sess = WinRMSession(
            host=params["host"],
            user=params["user"],
            password=params.get("password"),
        )
    else:
        return {"error": "invalid_transport", "valid": ["ssh", "winrm", "msf"], "got": transport}

    try:
        await asyncio.to_thread(sess.open)
    except Exception as exc:
        return {"error": "open_failed", "transport": transport_l, "message": str(exc)}

    ctx.sessions.add(sess)
    return {"handle_id": sess.handle_id, "transport": transport_l}


@registry.tool(
    name="session_exec",
    description="Execute `cmd` on the session identified by `handle_id`. Returns stdout/stderr/rc/duration.",
    category="session",
)
async def session_exec(handle_id: str, cmd: str, timeout: float = 120.0) -> dict[str, Any]:
    timeout = float(timeout)  # coerce — MCP JSON may deliver numeric args as strings
    ctx = mcp_context.get_context()
    sess = ctx.sessions.get(handle_id)
    if sess is None:
        return {"error": "unknown_handle", "handle_id": handle_id}
    try:
        res = await asyncio.to_thread(sess.exec, cmd, timeout)
    except Exception as exc:
        return {"error": "exec_failed", "handle_id": handle_id, "message": str(exc)}
    return {
        "handle_id": handle_id,
        "rc": res.rc,
        "stdout": res.stdout,
        "stderr": res.stderr,
        "duration_s": res.duration_s,
    }


@registry.tool(
    name="session_close",
    description="Close session `handle_id` and remove from the registry.",
    category="session",
)
async def session_close(handle_id: str) -> dict[str, Any]:
    ctx = mcp_context.get_context()
    sess = ctx.sessions.remove(handle_id)
    if sess is None:
        return {"error": "unknown_handle", "handle_id": handle_id}
    try:
        await asyncio.to_thread(sess.close)
    except Exception as exc:
        return {"handle_id": handle_id, "close_error": str(exc)}
    return {"handle_id": handle_id, "closed": True}


@registry.tool(
    name="session_upload",
    description=(
        "Upload a string (script content) to a remote path via SFTP on the given SSH session. "
        "Returns {uploaded: true, remote_path}. Use this instead of heredocs for complex scripts — "
        "write content here, then session_exec to run it."
    ),
    category="session",
)
async def session_upload(handle_id: str, content: str, remote_path: str) -> dict[str, Any]:
    ctx = mcp_context.get_context()
    sess = ctx.sessions.get(handle_id)
    if sess is None:
        return {"error": "unknown_handle", "handle_id": handle_id}
    if not hasattr(sess, "upload_string"):
        return {"error": "upload_not_supported", "transport": type(sess).__name__}
    try:
        await asyncio.to_thread(sess.upload_string, content, remote_path)
    except Exception as exc:
        return {"error": "upload_failed", "handle_id": handle_id, "message": str(exc)}
    return {"uploaded": True, "remote_path": remote_path, "bytes": len(content.encode())}


@registry.tool(
    name="session_list",
    description="List all active session handles with their type. Returns [{handle_id, type}].",
    category="session",
)
async def session_list() -> dict[str, Any]:
    ctx = mcp_context.get_context()
    handles = ctx.sessions.list_handles()
    return {"count": len(handles), "handles": handles}
