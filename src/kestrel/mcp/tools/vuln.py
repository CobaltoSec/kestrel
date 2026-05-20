"""MCP tools — vulnerability identification (nuclei + ExploitDB + MSF search).

- ``vuln_nuclei_targeted``: nuclei against `target` with specific templates (CVE-IDs, tags).
- ``vuln_nuclei_broad``: nuclei wide scan filtered by severity.
- ``vuln_check_exploit_db``: search local exploit-db CSV mirror.
- ``vuln_msf_search``: MSF module search via RPC (graceful if RPC down).
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
from pathlib import Path
from typing import Any

from kestrel.mcp import registry
from kestrel.mcp.tools.state import _resolve_session_dir
from kestrel.transport import kali_proxy


async def _run_kali(cmd: str, timeout: float = 600.0) -> dict[str, Any]:
    res = await asyncio.to_thread(kali_proxy.via_kali, cmd, timeout)
    return {
        "cmd": cmd,
        "rc": res.rc,
        "stdout": res.stdout,
        "stderr": res.stderr.strip(),
        "duration_s": res.duration_s,
    }


def _save_artifact(machine: str | None, subdir: str, filename: str, content: str) -> str | None:
    if machine is None:
        return None
    try:
        session_dir = _resolve_session_dir(machine)
    except ValueError:
        return None
    out_dir = session_dir / "vuln" / subdir
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / filename
    path.write_text(content, encoding="utf-8")
    return str(path)


def _parse_nuclei_jsonl(stdout: str) -> list[dict[str, Any]]:
    """Each line is JSON; collect into list, ignore parse errors."""
    out: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


# ── nuclei tools ─────────────────────────────────────────────────────────────


@registry.tool(
    name="vuln_nuclei_targeted",
    description=(
        "Run nuclei with specific templates against `target`. `templates` is a list of "
        "template IDs, tags, or paths (e.g. ['CVE-2007-2447', 'samba']). Returns parsed findings."
    ),
    category="vuln",
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "templates": {"type": "array", "items": {"type": "string"}},
            "severity": {"type": "string"},
            "machine": {"type": "string"},
        },
        "required": ["target", "templates"],
    },
)
async def vuln_nuclei_targeted(
    target: str,
    templates: list[str],
    severity: str | None = None,
    machine: str | None = None,
) -> dict[str, Any]:
    tmpl_args = " ".join(f"-id {shlex.quote(t)}" for t in templates)
    sev = f"-severity {shlex.quote(severity)}" if severity else ""
    cmd = f"nuclei -u {shlex.quote(target)} {tmpl_args} {sev} -jsonl -silent -timeout 8"
    raw = await _run_kali(cmd, timeout=600.0)
    findings = _parse_nuclei_jsonl(raw["stdout"])
    artifact = _save_artifact(machine, "nuclei", f"{target.replace('/', '_')}-targeted.jsonl", raw["stdout"])
    return {
        "target": target,
        "templates": templates,
        "rc": raw["rc"],
        "finding_count": len(findings),
        "findings": findings,
        "artifact": artifact,
    }


@registry.tool(
    name="vuln_nuclei_broad",
    description=(
        "Wide nuclei scan filtered by severity (critical/high/medium/low). Slower — use after "
        "vuln_nuclei_targeted when ad-hoc CVE lookup turned up nothing."
    ),
    category="vuln",
)
async def vuln_nuclei_broad(
    target: str,
    severity: str = "critical,high",
    machine: str | None = None,
) -> dict[str, Any]:
    cmd = f"nuclei -u {shlex.quote(target)} -severity {shlex.quote(severity)} -jsonl -silent -timeout 8"
    raw = await _run_kali(cmd, timeout=900.0)
    findings = _parse_nuclei_jsonl(raw["stdout"])
    artifact = _save_artifact(machine, "nuclei", f"{target.replace('/', '_')}-broad.jsonl", raw["stdout"])
    return {
        "target": target,
        "severity": severity,
        "rc": raw["rc"],
        "finding_count": len(findings),
        "findings": findings,
        "artifact": artifact,
    }


# ── ExploitDB ────────────────────────────────────────────────────────────────


@registry.tool(
    name="vuln_check_exploit_db",
    description=(
        "Search the local ExploitDB CSV mirror for `query` (case-insensitive). "
        "Defaults to ~/.kestrel/exploitdb.csv (override via env KESTREL_EXPLOITDB_CSV)."
    ),
    category="vuln",
)
async def vuln_check_exploit_db(query: str, limit: int = 10) -> dict[str, Any]:
    csv_path = Path(
        os.environ.get("KESTREL_EXPLOITDB_CSV", str(Path.home() / ".kestrel" / "exploitdb.csv"))
    )
    if not csv_path.exists():
        return {"available": False, "query": query, "results": [], "reason": "csv_not_found"}

    def _do() -> list[dict[str, Any]]:
        needle = query.lower()
        matches: list[dict[str, Any]] = []
        for line in csv_path.read_text(encoding="utf-8", errors="replace").splitlines()[:200000]:
            if needle in line.lower():
                parts = line.split(",")
                if len(parts) >= 3:
                    matches.append({
                        "id": parts[0].strip(),
                        "title": parts[2].strip('"'),
                    })
                if len(matches) >= limit:
                    break
        return matches

    matches = await asyncio.to_thread(_do)
    return {"available": True, "query": query, "results": matches, "count": len(matches)}


# ── MSF search ───────────────────────────────────────────────────────────────


_msf_session_cache: Any | None = None


def _get_msf_session() -> Any | None:
    """Return the cached MSFRPCSession instance (lazy). None if config/secret missing."""
    global _msf_session_cache
    if _msf_session_cache is not None:
        return _msf_session_cache
    try:
        from kestrel.transport.msf import MSFRPCSession
        sess = MSFRPCSession.from_config()
        _msf_session_cache = sess
        return sess
    except Exception:
        return None


def _reset_msf_session_for_tests() -> None:
    global _msf_session_cache
    _msf_session_cache = None


@registry.tool(
    name="vuln_msf_search",
    description=(
        "Search Metasploit modules matching `query` via RPC. Returns list of modules with rank/type. "
        "Returns available=False with reason if msfrpcd is unreachable."
    ),
    category="vuln",
)
async def vuln_msf_search(query: str) -> dict[str, Any]:
    sess = _get_msf_session()
    if sess is None:
        return {"available": False, "query": query, "modules": [], "reason": "rpc_unavailable"}
    try:
        modules = await asyncio.to_thread(sess.search_modules, query)
    except Exception as exc:
        return {"available": False, "query": query, "modules": [], "reason": f"error: {exc}"}
    # Normalize keys: pymetasploit3 returns dicts with various shapes
    out: list[dict[str, Any]] = []
    for m in modules[:50]:
        out.append({
            "fullname": m.get("fullname") or m.get("name"),
            "type": m.get("type"),
            "rank": m.get("rank"),
            "name": m.get("name"),
        })
    return {"available": True, "query": query, "modules": out, "count": len(out)}
