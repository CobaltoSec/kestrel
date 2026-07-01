"""MCP tools — HTB API v4 wrappers.

Thin async wrappers around the existing ``HTBClient`` in
``sectors/red-team/htb/api.py``. Each tool wraps the sync client method with
``asyncio.to_thread`` and returns JSON-serializable dicts.

HTB token is auto-loaded from ``~/.htb/token`` by the client. Missing token →
each tool returns ``{"error": "htb_token_missing", ...}``.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry


# Path to the HTBClient lives outside the htb-framework-public repo (in CobaltoSec).
# We import lazily so tests can patch without requiring the real module on sys.path.
_HTB_API_PARENT = Path("C:/Proyectos/CobaltoSec/sectors/red-team/htb")


def _load_htb_module() -> Any:
    """Lazy-load sectors/red-team/htb/api.py since it's outside this package."""
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        "_kestrel_htb_api", _HTB_API_PARENT / "api.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load HTB api.py from {_HTB_API_PARENT}")
    mod = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_kestrel_htb_api", mod)
    spec.loader.exec_module(mod)
    return mod


_client_cache: Any | None = None


def _get_client() -> Any:
    """Return a cached HTBClient instance. Tests patch this to inject mocks."""
    global _client_cache
    if _client_cache is None:
        mod = _load_htb_module()
        _client_cache = mod.HTBClient()
    return _client_cache


def _reset_client_for_tests() -> None:
    global _client_cache
    _client_cache = None


# ── Error wrapper ────────────────────────────────────────────────────────────


def _wrap_htb_error(exc: Exception) -> dict[str, Any]:
    msg = str(exc)
    if "token not found" in msg.lower():
        return {"error": "htb_token_missing", "message": msg}
    return {"error": "htb_api_error", "message": msg}


# ── Tools ────────────────────────────────────────────────────────────────────


@registry.tool(
    name="htb_list_machines",
    description=(
        "List HTB machines, optionally filtered. status='retired' (default) or 'active'. "
        "Returns list of {id, name, os, difficultyText, ip, ...}."
    ),
    category="htb",
)
async def htb_list_machines(
    status: str = "retired",
    difficulty: str | None = None,
    os: str | None = None,
) -> dict[str, Any]:
    try:
        client = _get_client()
        retired = status.lower() == "retired"
        machines = await asyncio.to_thread(
            client.list_machines, retired, difficulty, os
        )
        return {"count": len(machines), "machines": machines}
    except Exception as exc:
        return _wrap_htb_error(exc)


@registry.tool(
    name="htb_machine_info",
    description="Get full machine info by slug (name) or ID. Returns dict with id, name, os, difficulty, ip, points, tags.",
    category="htb",
)
async def htb_machine_info(slug: str) -> dict[str, Any]:
    try:
        client = _get_client()
        info = await asyncio.to_thread(client.get_machine, slug)
        return {"slug": slug, "info": info}
    except Exception as exc:
        return _wrap_htb_error(exc)


@registry.tool(
    name="htb_spawn",
    description=(
        "Spawn an HTB machine on the free VPN. Resolves slug→id automatically. "
        "Persists machine_id, machine_os, machine_difficulty, target_ip into state."
    ),
    category="htb",
)
async def htb_spawn(slug: str) -> dict[str, Any]:
    try:
        client = _get_client()
        info = await asyncio.to_thread(client.get_machine, slug)
        mid = info.get("id")
        if not mid:
            return {"error": "machine_not_found", "slug": slug}
        result = await asyncio.to_thread(client.spawn_machine, mid)
        # Persist core metadata to state
        ctx = mcp_context.get_context()
        ctx.state_store.update_machine(
            slug,
            {
                "machine_id": mid,
                "machine_os": info.get("os"),
                "machine_difficulty": info.get("difficultyText"),
                "machine_retired": bool(info.get("retired", False)),
                "target_ip": info.get("ip"),
            },
        )
        # V08: generate + persist session_slug, update current_session
        from kestrel.mcp.tools.state import _resolve_session_dir  # local to avoid circular
        session_dir = _resolve_session_dir(slug)
        ctx.state_store.set_current_session(session_dir.name)
        return {
            "slug": slug,
            "machine_id": mid,
            "target_ip": info.get("ip"),
            "session_slug": session_dir.name,
            "message": result.get("message", "spawned"),
        }
    except Exception as exc:
        return _wrap_htb_error(exc)


def _check_debrief(slug: str) -> dict[str, Any]:
    """IMP-11: verify feedback.md exists with all 5 required sections."""
    try:
        ctx = mcp_context.get_context()
        from kestrel.mcp.tools.state import _resolve_session_dir
        session_dir = _resolve_session_dir(slug)
        feedback_path = session_dir / "feedback.md"
        if not feedback_path.exists():
            return {"ok": False, "missing": ["feedback.md does not exist"], "path": None}
        content = feedback_path.read_text(encoding="utf-8", errors="ignore")
        required = ["## 1.", "## 2.", "## 3.", "## 4.", "## 5."]
        missing = [s for s in required if s not in content]
        return {"ok": len(missing) == 0, "missing": missing, "path": str(feedback_path)}
    except Exception:
        return {"ok": False, "missing": ["could not resolve session_dir for slug"], "path": None}


@registry.tool(
    name="htb_release",
    description="Release (terminate) an HTB machine. Resolves slug→id automatically. Requires feedback.md with 5 sections (IMP-11 debrief gate).",
    category="htb",
)
async def htb_release(slug: str, force: bool = False) -> dict[str, Any]:
    # IMP-11: debrief hard stop
    if not force:
        debrief = _check_debrief(slug)
        if not debrief["ok"]:
            return {
                "error": "debrief_required",
                "_hitl": True,
                "question": (
                    f"feedback.md incompleto para '{slug}'. "
                    f"Secciones faltantes: {debrief['missing']}. "
                    "Completá el debrief antes de liberar la máquina."
                ),
                "options": ["completar feedback.md primero", "forzar release con force=true"],
                "missing_sections": debrief["missing"],
                "feedback_path": debrief["path"],
            }
    try:
        client = _get_client()
        info = await asyncio.to_thread(client.get_machine, slug)
        mid = info.get("id")
        if not mid:
            return {"error": "machine_not_found", "slug": slug}
        result = await asyncio.to_thread(client.release_machine, mid)
        return {"slug": slug, "machine_id": mid, "message": result.get("message", "released")}
    except Exception as exc:
        return _wrap_htb_error(exc)


@registry.tool(
    name="htb_submit_flag",
    description=(
        "Submit a user or root flag for an HTB machine. flag_type is 'user' or 'root' (informational). "
        "difficulty 10-100 (self-reported)."
    ),
    category="htb",
)
async def htb_submit_flag(
    slug: str, flag: str, flag_type: str = "user", difficulty: int = 50
) -> dict[str, Any]:
    try:
        client = _get_client()
        info = await asyncio.to_thread(client.get_machine, slug)
        mid = info.get("id")
        if not mid:
            return {"error": "machine_not_found", "slug": slug}
        result = await asyncio.to_thread(client.submit_flag, mid, flag, difficulty)
        # Persist ownership update
        ctx = mcp_context.get_context()
        patch: dict[str, Any] = {}
        if flag_type == "user":
            patch["user_owned"] = True
        elif flag_type == "root":
            patch["root_owned"] = True
        if patch:
            ctx.state_store.update_machine(slug, patch)
        return {
            "slug": slug,
            "machine_id": mid,
            "flag_type": flag_type,
            "result": result,
        }
    except Exception as exc:
        return _wrap_htb_error(exc)


@registry.tool(
    name="htb_profile_update",
    description=(
        "Fetch the current HTB profile (rank, points, owns) and persist to <state_dir>/profile.json. "
        "Returns the fetched profile dict."
    ),
    category="htb",
)
async def htb_profile_update() -> dict[str, Any]:
    try:
        client = _get_client()
        profile = await asyncio.to_thread(client.get_profile)
        ctx = mcp_context.get_context()
        profile_path = ctx.state_dir / "profile.json"
        ctx.state_dir.mkdir(parents=True, exist_ok=True)
        profile_path.write_text(
            json.dumps(profile, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        return {"profile_path": str(profile_path), "profile": profile}
    except Exception as exc:
        return _wrap_htb_error(exc)
