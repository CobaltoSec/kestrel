"""MCP tools — credential operations (defaults, spray, hash recommend/crack/status, audit)."""

from __future__ import annotations

import asyncio
import os
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kestrel.core import crack, wordlist
from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry
from kestrel.transport import kali_proxy


SERVICE_DEFAULTS: dict[str, list[tuple[str, str]]] = {
    "ssh": [("root", "root"), ("root", "toor"), ("admin", "admin"), ("kali", "kali")],
    "mysql": [("root", ""), ("root", "root"), ("mysql", "mysql"), ("admin", "admin")],
    "ftp": [("anonymous", ""), ("ftp", "ftp"), ("admin", "admin")],
    "rdp": [("administrator", "administrator"), ("admin", "admin")],
    "tomcat": [("tomcat", "tomcat"), ("admin", "admin"), ("manager", "manager")],
    "jenkins": [("admin", "admin"), ("jenkins", "jenkins")],
    "mongodb": [("admin", "admin"), ("root", "root")],
    "postgres": [("postgres", "postgres"), ("admin", "admin")],
}


async def _run_kali(cmd: str, timeout: float = 120.0) -> dict[str, Any]:
    res = await asyncio.to_thread(kali_proxy.via_kali, cmd, timeout)
    return {"cmd": cmd, "rc": res.rc, "stdout": res.stdout, "stderr": res.stderr.strip(), "duration_s": res.duration_s}


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── creds_default_check ──────────────────────────────────────────────────────


@registry.tool(
    name="creds_default_check",
    description=(
        "Try a built-in dict of default credentials for the given service (ssh/mysql/ftp/rdp/tomcat/etc.). "
        "Uses nxc (NetExec). Returns success on first hit."
    ),
    category="creds",
)
async def creds_default_check(service: str, target: str, port: int | None = None) -> dict[str, Any]:
    svc = service.lower()
    if svc not in SERVICE_DEFAULTS:
        return {"error": "service_not_supported", "service": svc, "supported": list(SERVICE_DEFAULTS.keys())}
    nxc_proto_map = {"ssh": "ssh", "mysql": "mssql", "rdp": "rdp", "ftp": "ftp", "winrm": "winrm"}
    proto = nxc_proto_map.get(svc)
    if not proto:
        return {"error": "nxc_protocol_unsupported", "service": svc}
    results: list[dict[str, Any]] = []
    for user, password in SERVICE_DEFAULTS[svc]:
        port_arg = f"--port {port}" if port else ""
        cmd = f"nxc {proto} {shlex.quote(target)} {port_arg} -u {shlex.quote(user)} -p {shlex.quote(password)}"
        res = await _run_kali(cmd, timeout=15.0)
        # NetExec marks success with [+]
        success = "[+]" in res["stdout"]
        results.append({"user": user, "password": password, "success": success})
        if success:
            return {"service": svc, "target": target, "found": {"user": user, "password": password}, "tries": results}
    return {"service": svc, "target": target, "found": None, "tries": results}


# ── creds_password_spray ─────────────────────────────────────────────────────


@registry.tool(
    name="creds_password_spray",
    description=(
        "Password spray a single password across a user list against `target`. Service auto-detected from protocol arg "
        "(smb/winrm/ssh/mssql). Use small lists — 1 password per call to avoid AD lockout."
    ),
    category="creds",
)
async def creds_password_spray(
    target: str, users: list[str], password: str, protocol: str = "smb"
) -> dict[str, Any]:
    users_payload = "\n".join(users)
    # write a temp file on Kali via heredoc
    cmd = (
        f"set -e; tmpf=$(mktemp); printf '%s' {shlex.quote(users_payload)} > $tmpf; "
        f"nxc {shlex.quote(protocol)} {shlex.quote(target)} -u $tmpf -p {shlex.quote(password)} --continue-on-success; "
        f"rm -f $tmpf"
    )
    res = await _run_kali(cmd, timeout=120.0)
    successes: list[str] = []
    for line in res["stdout"].splitlines():
        if "[+]" in line:
            successes.append(line.strip())
    return {"target": target, "protocol": protocol, "password": password, "success_count": len(successes), "successes": successes, "rc": res["rc"]}


# ── creds_hash_recommend ─────────────────────────────────────────────────────


@registry.tool(
    name="creds_hash_recommend",
    description=(
        "Recommend a ranked wordlist strategy for a hash given context (machine_name, vhosts, framework). "
        "Wraps kestrel.core.wordlist.build_plan."
    ),
    category="creds",
    input_schema={
        "type": "object",
        "properties": {
            "hash_type": {"type": "string"},
            "machine_name": {"type": "string"},
            "vhosts": {"type": "array", "items": {"type": "string"}},
            "framework": {"type": "string"},
            "target_ip": {"type": "string"},
        },
        "required": ["hash_type", "machine_name"],
    },
)
async def creds_hash_recommend(
    hash_type: str,
    machine_name: str,
    vhosts: list[str] | None = None,
    framework: str | None = None,
    target_ip: str | None = None,
) -> dict[str, Any]:
    plan = wordlist.build_plan(machine_name, vhosts or [], framework, hash_type, target_ip)
    return {"hash_type": hash_type, "machine": machine_name, "plan": plan}


# ── creds_hash_crack ─────────────────────────────────────────────────────────


@registry.tool(
    name="creds_hash_crack",
    description=(
        "Crack a single hash via hashcat on Kali. Returns rc + cracked password if found. "
        "For bcrypt/argon2/scrypt prefer async pipeline (use crack-helper.sh from skill flow)."
    ),
    category="creds",
)
async def creds_hash_crack(
    hash_value: str,
    hash_type: str,
    wordlist_path: str,
    rules: str = "none",
    timeout: int = 300,
) -> dict[str, Any]:
    # hash_type translates to hashcat -m mode. We accept either int strings or names.
    rules_arg = f"-r {shlex.quote(rules)}" if rules and rules != "none" else ""
    # Write the hash to a temp file on Kali to avoid shell escape issues
    cmd = (
        f"set -e; hf=$(mktemp); printf '%s' {shlex.quote(hash_value)} > $hf; "
        f"hashcat -m {shlex.quote(hash_type)} $hf {shlex.quote(wordlist_path)} {rules_arg} --quiet --potfile-disable; "
        f"rc=$?; hashcat -m {shlex.quote(hash_type)} $hf {shlex.quote(wordlist_path)} {rules_arg} --show; "
        f"rm -f $hf; exit $rc"
    )
    res = await _run_kali(cmd, timeout=float(timeout))
    cracked = None
    for line in res["stdout"].splitlines():
        if ":" in line and line.startswith(hash_value.split("$")[0][:8]):
            parts = line.split(":", 1)
            if len(parts) == 2:
                cracked = parts[1].strip()
                break
    return {
        "hash_type": hash_type,
        "cracked": cracked,
        "rc": res["rc"],
        "duration_s": res["duration_s"],
    }


# ── creds_hash_status ────────────────────────────────────────────────────────


@registry.tool(
    name="creds_hash_status",
    description=(
        "Check the status of an async hash crack job (created by crack-helper.sh --async). "
        "Returns pending_upload / running / complete / no_match / timeout / error."
    ),
    category="creds",
)
async def creds_hash_status(job_id: str, jobs_dir: str | None = None) -> dict[str, Any]:
    jd = Path(jobs_dir or os.environ.get("KESTREL_CRACK_JOBS_DIR", str(Path.home() / ".kestrel" / "crack-jobs")))
    state = crack.load_state(jd, job_id)
    result = crack.load_result(jd, job_id)
    return crack.compute_status(state, result)


# ── creds_save_tried ─────────────────────────────────────────────────────────


@registry.tool(
    name="creds_save_tried",
    description=(
        "Append a tried credential / endpoint / hash to state.machines[machine] cross-session arrays. "
        "kind must be 'credential', 'endpoint', or 'hash'. Auto-stamps ts if missing."
    ),
    category="creds",
    input_schema={
        "type": "object",
        "properties": {
            "machine": {"type": "string"},
            "kind": {"type": "string", "enum": ["credential", "endpoint", "hash"]},
            "payload": {"type": "object"},
        },
        "required": ["machine", "kind", "payload"],
    },
)
async def creds_save_tried(machine: str, kind: str, payload: dict[str, Any]) -> dict[str, Any]:
    field_map = {"credential": "tried_credentials", "endpoint": "tried_endpoints", "hash": "tried_hashes"}
    field = field_map.get(kind)
    if field is None:
        return {"error": "invalid_kind", "got": kind, "valid": list(field_map.keys())}
    ctx = mcp_context.get_context()
    m = ctx.state_store.get_machine(machine)
    existing = []
    if m is not None:
        existing = [c.model_dump(mode="json") for c in getattr(m, field, [])]
    if "ts" not in payload:
        payload["ts"] = _now_iso()
    existing.append(payload)
    ctx.state_store.update_machine(machine, {field: existing})
    return {"machine": machine, "kind": kind, "count": len(existing)}
