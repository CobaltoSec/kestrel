"""MCP tools — intel layer (classify blind, KB query, CVE lookup, synthesis persist).

Core entrypoints for the LLM client to ground its attack reasoning:
- ``intel_classify_blind``: scoring rules over ports/services/banners → attack plan.
- ``intel_kb_query``: pgvector KB query with graceful fallback.
- ``intel_cve_lookup``: 4-stage pipeline (KB → NVD → ExploitDB local → MSF search).
- ``intel_save_synthesis``: persist intel.md per machine session.
- ``intel_next_step``: phase + findings + stuck-signals → prioritised steps with commands.
- ``lolbin_suggest``: binary inventory → GTFOBins/LOLBAS techniques (concurrent KB).

All external dependencies (KB, NVD, ExploitDB, MSF RPC) fail gracefully — every
tool returns a meaningful dict even when a backend is down.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any

import httpx

from kestrel.core.fingerprint import build_attack_plan, query_kb, score_rules
from kestrel.core.stuck import (
    detect_cred_exhausted,
    detect_hash_stuck,
    detect_rabbit_hole,
    detect_shell_lost,
    read_file_safe,
    read_jsonl,
)
from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry
from kestrel.mcp.tools.state import _resolve_session_dir


KB_QUERY_TIMEOUT_S = 5.0
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_JACCARD_THRESHOLD = 0.6


# ── intel_classify_blind ─────────────────────────────────────────────────────


@registry.tool(
    name="intel_classify_blind",
    description=(
        "Classify a target from ports/services/banners into ranked attack categories + attack plan. "
        "Uses kestrel.core.fingerprint. KB query auto-runs if KESTREL_KB_PATH is set."
    ),
    category="intel",
    input_schema={
        "type": "object",
        "properties": {
            "target": {"type": "string"},
            "ports": {"type": "array", "items": {"type": "string"}},
            "services": {"type": "array", "items": {"type": "string"}},
            "banners": {"type": "array", "items": {"type": "string"}},
            "os_hint": {"type": "string", "default": ""},
            "framework": {"type": "string"},
            "ad_joined": {"type": "boolean", "default": False},
        },
        "required": ["target"],
    },
)
async def intel_classify_blind(
    target: str,
    ports: list[str] | None = None,
    services: list[str] | None = None,
    banners: list[str] | None = None,
    os_hint: str = "",
    framework: str | None = None,
    ad_joined: bool = False,
) -> dict[str, Any]:
    ports = ports or []
    services = services or []
    banners = banners or []
    categories = score_rules(ports, services, banners, os_hint, framework)
    attack_plan = build_attack_plan(categories, os_hint or "unknown", framework, ad_joined)
    kb_chunks: list[dict[str, Any]] = []
    try:
        kb_chunks = await asyncio.wait_for(
            asyncio.to_thread(query_kb, categories),
            timeout=KB_QUERY_TIMEOUT_S,
        )
    except asyncio.TimeoutError:
        kb_chunks = []
    except Exception:
        kb_chunks = []
    return {
        "target": target,
        "categories": categories,
        "attack_plan": attack_plan,
        "kb_chunks": kb_chunks,
        "os_hint": os_hint,
        "framework": framework,
        "kb_active": len(kb_chunks) > 0,
        "kb_note": None if kb_chunks else "KB no activa para este target — pasos son templates genéricos",
    }


# ── intel_kb_query ───────────────────────────────────────────────────────────


def _try_import_kb_smart() -> Any | None:
    """Try to import kb.query.smart from KESTREL_KB_PATH. Returns the module or None."""
    kb_path = os.environ.get("KESTREL_KB_PATH", "")
    if not kb_path:
        return None
    try:
        if kb_path not in sys.path:
            sys.path.insert(0, kb_path)
        from kb.query import smart  # type: ignore
        return smart
    except Exception:
        return None


@registry.tool(
    name="intel_kb_query",
    description=(
        "Query the pgvector KB with `query` (free text). Returns top_k chunks with score + source. "
        "Falls back to empty list if KB unavailable. timeout 5s hard cap."
    ),
    category="intel",
)
async def intel_kb_query(query: str, top_k: int = 5) -> dict[str, Any]:
    smart_mod = _try_import_kb_smart()
    if smart_mod is None:
        return {"available": False, "query": query, "chunks": [], "reason": "kb_unavailable"}

    async def _run() -> list[dict[str, Any]]:
        def _do() -> list[dict[str, Any]]:
            results, _ = smart_mod.smart_search(query, top_k=top_k)
            return [
                {
                    "text": r.get("content", "")[:600],
                    "source": r.get("metadata", {}).get("source", ""),
                    "score": round(float(r.get("score", 0.0)), 3),
                }
                for r in results
            ]

        return await asyncio.to_thread(_do)

    try:
        chunks = await asyncio.wait_for(_run(), timeout=KB_QUERY_TIMEOUT_S)
    except asyncio.TimeoutError:
        return {"available": False, "query": query, "chunks": [], "reason": "timeout"}
    except Exception as exc:
        return {"available": False, "query": query, "chunks": [], "reason": f"error: {exc}"}
    return {"available": True, "query": query, "chunks": chunks}


# ── intel_cve_lookup ─────────────────────────────────────────────────────────


async def _nvd_lookup(product: str, version: str) -> list[dict[str, Any]]:
    """Query NVD CPE-based search. No API key needed (rate-limited heavily without)."""
    cpe = f"cpe:2.3:a:*:{product.lower()}:{version}:*:*:*:*:*:*:*"
    params = {"cpeName": cpe, "resultsPerPage": 10}
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            r = await client.get(NVD_API, params=params)
            r.raise_for_status()
            data = r.json()
    except Exception:
        return []
    out: list[dict[str, Any]] = []
    for v in data.get("vulnerabilities", [])[:10]:
        cve = v.get("cve", {})
        out.append({
            "cve_id": cve.get("id"),
            "description": (cve.get("descriptions") or [{}])[0].get("value", "")[:300],
            "published": cve.get("published"),
        })
    return out


def _exploitdb_local_lookup(product: str, version: str) -> list[dict[str, Any]]:
    """Best-effort grep over an exploitdb CSV mirror at ~/.kestrel/exploitdb.csv. Falls back to []."""
    csv_path = Path(os.environ.get("KESTREL_EXPLOITDB_CSV", str(Path.home() / ".kestrel" / "exploitdb.csv")))
    if not csv_path.exists():
        return []
    needle = f"{product.lower()} {version.lower()}".strip()
    matches: list[dict[str, Any]] = []
    try:
        for line in csv_path.read_text(encoding="utf-8", errors="replace").splitlines()[:50000]:
            if needle and needle in line.lower():
                parts = line.split(",")
                if len(parts) >= 3:
                    matches.append({"id": parts[0].strip(), "title": parts[2].strip('"')})
                if len(matches) >= 10:
                    break
    except Exception:
        return []
    return matches


@registry.tool(
    name="intel_cve_lookup",
    description=(
        "Ranked CVE pipeline for product+version: 1) KB synthesis chunks 2) NVD API "
        "3) ExploitDB local CSV 4) MSF search RPC. Each backend independent — failures don't block."
    ),
    category="intel",
)
async def intel_cve_lookup(product: str, version: str) -> dict[str, Any]:
    # QW: KB query and NVD run concurrently — saves ~3-8s vs sequential awaits.
    kb_result, nvd = await asyncio.gather(
        intel_kb_query(f"{product} {version} CVE exploit", top_k=3),
        _nvd_lookup(product, version),
    )
    kb_chunks = kb_result.get("chunks", [])

    edb = _exploitdb_local_lookup(product, version)

    # MSF search via RPC deferred — LLM can call vuln_msf_search explicitly.
    msf_results: list[dict[str, Any]] = []

    return {
        "product": product,
        "version": version,
        "stages": {
            "kb": kb_chunks,
            "nvd": nvd,
            "exploitdb_local": edb,
            "msf": msf_results,
        },
        "ranked_cves": _rank_cves(kb_chunks, nvd, edb),
    }


def _rank_cves(
    kb_chunks: list[dict[str, Any]],
    nvd: list[dict[str, Any]],
    edb: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Simple ranking: NVD CVE-IDs cross-referenced with edb titles get boosted."""
    edb_titles = " ".join(e.get("title", "").lower() for e in edb)
    out: list[dict[str, Any]] = []
    for cve in nvd:
        cve_id = cve.get("cve_id", "")
        has_edb = cve_id.lower() in edb_titles
        out.append({
            "cve_id": cve_id,
            "description": cve.get("description", ""),
            "has_exploitdb": has_edb,
            "priority": 2 if has_edb else 1,
        })
    out.sort(key=lambda x: x["priority"], reverse=True)
    return out


# ── intel_save_synthesis ─────────────────────────────────────────────────────


@registry.tool(
    name="intel_save_synthesis",
    description=(
        "Persist an intel.md synthesis to <session_dir>/intel.md and update state.machines[machine] "
        "with intel_path + intel_confidence + intel_sources."
    ),
    category="intel",
    input_schema={
        "type": "object",
        "properties": {
            "machine": {"type": "string"},
            "content_md": {"type": "string"},
            "sources": {"type": "array", "items": {"type": "string"}},
            "confidence": {"type": "string", "enum": ["high", "medium", "low", "none"]},
        },
        "required": ["machine", "content_md", "confidence"],
    },
)
async def intel_save_synthesis(
    machine: str,
    content_md: str,
    confidence: str,
    sources: list[str] | None = None,
) -> dict[str, Any]:
    if confidence not in ("high", "medium", "low", "none"):
        return {"error": "invalid_confidence", "got": confidence}
    sources = sources or []
    ctx = mcp_context.get_context()
    session_dir = _resolve_session_dir(machine)
    session_dir.mkdir(parents=True, exist_ok=True)
    intel_path = session_dir / "intel.md"
    intel_path.write_text(content_md, encoding="utf-8")
    ctx.state_store.update_machine(
        machine,
        {
            "intel_path": str(intel_path),
            "intel_confidence": confidence,
            "intel_sources": sources,
        },
    )
    return {
        "machine": machine,
        "intel_path": str(intel_path),
        "confidence": confidence,
        "sources_count": len(sources),
    }


# ── intel_next_step — helpers ────────────────────────────────────────────────


_PHASE_KB_PREFIX: dict[str, str] = {
    "p2_enum": "enumeration service discovery",
    "p3_foothold": "initial access foothold exploit",
    "p3a_pre_foothold": "initial access exploit CVE RCE web vulnerability",
    "p3b_post_foothold": "post foothold shell upgrade loot enumeration",
    "p4_privesc": "privilege escalation post-exploitation",
}

# IMPROVEMENT-3: richer phase-aware fallback templates (KB-independent).
_PHASE_FALLBACK_STEPS: dict[str, list[dict[str, Any]]] = {
    "p2_enum": [
        {
            "priority": 1,
            "action": "full_tcp_scan",
            "command": "nmap -sV -sC -p- --open -T4 {target}",
            "rationale": "Full port sweep — services often run on non-standard ports.",
            "source": "builtin",
        },
        {
            "priority": 2,
            "action": "web_fingerprint",
            "command": "whatweb http://{target} && curl -sI http://{target}",
            "rationale": "Identify web stack version for CVE correlation.",
            "source": "builtin",
        },
        {
            "priority": 3,
            "action": "smb_enum",
            "command": "smbclient -L //{target} -N && nmap --script smb-enum-shares,smb-enum-users -p 445 {target}",
            "rationale": "SMB null session often reveals shares and usernames on HTB boxes.",
            "source": "builtin",
        },
        {
            "priority": 4,
            "action": "web_dir_fuzz",
            "command": "gobuster dir -u http://{target} -w /usr/share/seclists/Discovery/Web-Content/common.txt -x php,txt,bak",
            "rationale": "Directory brute-force exposes admin panels and backup files.",
            "source": "builtin",
        },
        {
            "priority": 5,
            "action": "db_port_scan",
            "command": "nmap -sV -p 3306,5432,27017,1433,6379,5984 {target}",
            "rationale": "Database services often exposed without auth on lab boxes.",
            "source": "builtin",
        },
        {
            "priority": 6,
            "action": "docker_api_check",
            "command": "curl -s http://{target}:2375/info 2>/dev/null | python3 -m json.tool || echo no docker api",
            "rationale": "Docker API on 2375 (no TLS) = instant RCE via container exec.",
            "source": "builtin",
        },
        {
            "priority": 7,
            "action": "ics_ot_scan",
            "command": "nmap -sV -p 4840,102,502,20000,44818,47808 {target}",
            "rationale": "OPC-UA (4840), S7 (102), Modbus (502) — ICS/OT attack surface.",
            "source": "builtin",
        },
        {
            "priority": 8,
            "action": "nifi_check",
            "command": "curl -s http://{target}:8080/nifi/ | grep -i 'nifi\\|version'",
            "rationale": "Apache NiFi unauthenticated = Groovy ExecuteScript RCE.",
            "source": "builtin",
        },
    ],
    "p3a_pre_foothold": [
        {
            "priority": 1,
            "action": "test_rce_endpoint",
            "command": "curl -sv http://{target}/vulnerable-endpoint -d 'param=test'",
            "rationale": "Probe RCE endpoint — verify response and headers before exploitation.",
            "source": "builtin",
        },
        {
            "priority": 2,
            "action": "searchsploit_service",
            "command": "searchsploit {service} {version}",
            "rationale": "List CVEs applicable to the confirmed service version.",
            "source": "builtin",
        },
        {
            "priority": 3,
            "action": "run_poc",
            "command": "python3 exploit.py {target}",
            "rationale": "Execute PoC if version is confirmed vulnerable.",
            "source": "builtin",
        },
        {
            "priority": 4,
            "action": "sqli_auto",
            "command": "sqlmap -u 'http://{target}/endpoint?param=1' --level=2 --risk=2",
            "rationale": "Automated SQLi scan against confirmed injectable parameter.",
            "source": "builtin",
        },
        {
            "priority": 5,
            "action": "brute_web_login",
            "command": "hydra -l admin -P /usr/share/wordlists/rockyou.txt {target} http-post-form '/login:user=^USER^&pass=^PASS^:invalid'",
            "rationale": "Credential brute-force against web login form.",
            "source": "builtin",
        },
    ],
    "p3b_post_foothold": [
        {
            "priority": 1,
            "action": "pty_upgrade",
            "command": "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'",
            "rationale": "Upgrade dumb shell to full PTY for interactive use.",
            "source": "builtin",
        },
        {
            "priority": 2,
            "action": "fix_terminal",
            "command": "export TERM=xterm && stty rows 38 cols 116",
            "rationale": "Fix terminal dimensions after PTY upgrade.",
            "source": "builtin",
        },
        {
            "priority": 3,
            "action": "basic_loot",
            "command": "cat ~/.ssh/id_rsa ~/.bash_history /etc/passwd /etc/shadow 2>/dev/null",
            "rationale": "Collect credentials and history immediately after shell access.",
            "source": "builtin",
        },
        {
            "priority": 4,
            "action": "suid_search",
            "command": "find / -perm -4000 -type f 2>/dev/null",
            "rationale": "SUID binaries are the most common privesc path on HTB.",
            "source": "builtin",
        },
        {
            "priority": 5,
            "action": "sudo_check",
            "command": "sudo -l",
            "rationale": "List sudo privileges for the current user.",
            "source": "builtin",
        },
    ],
    "p3_foothold": [
        {
            "priority": 1,
            "action": "pty_upgrade",
            "command": "python3 -c 'import pty; pty.spawn(\"/bin/bash\")'",
            "rationale": "Upgrade dumb shell to PTY for interactive use.",
            "source": "builtin",
        },
        {
            "priority": 2,
            "action": "home_enum",
            "command": "ls -la /home/ && cat /etc/passwd | grep -v nologin",
            "rationale": "Enumerate user home dirs and valid shell accounts.",
            "source": "builtin",
        },
        {
            "priority": 3,
            "action": "rce_verify",
            "command": "id && hostname && ip a && whoami",
            "rationale": "Confirm RCE identity and network position before lateral move.",
            "source": "builtin",
        },
        {
            "priority": 4,
            "action": "stable_pty_alt",
            "command": "script /dev/null -c bash",
            "rationale": "Alternative PTY upgrade when python3 unavailable.",
            "source": "builtin",
        },
        {
            "priority": 5,
            "action": "ssh_key_hunt",
            "command": "find /home /root -name 'id_rsa' -o -name '*.bak' -o -name '*.key' 2>/dev/null | head -20",
            "rationale": "SSH private keys or backup creds in home dirs pivot to next user.",
            "source": "builtin",
        },
        {
            "priority": 6,
            "action": "config_creds_hunt",
            "command": "find / -name '*.conf' -o -name '*.cfg' -o -name '*.ini' 2>/dev/null | xargs grep -l 'password\\|passwd\\|secret' 2>/dev/null | head -10",
            "rationale": "Hardcoded creds in config files are common in lab environments.",
            "source": "builtin",
        },
        {
            "priority": 7,
            "action": "web_rce_verify",
            "command": "curl -s 'http://{target}/rce?cmd=id'  # adapt param to confirmed vector",
            "rationale": "Test web RCE parameter with safe command before spawning shell.",
            "source": "builtin",
        },
    ],
    "p4_privesc": [
        {
            "priority": 1,
            "action": "suid_search",
            "command": "find / -perm -4000 -type f 2>/dev/null",
            "rationale": "SUID binaries are the most common privesc path on HTB.",
            "source": "builtin",
        },
        {
            "priority": 2,
            "action": "sudo_check",
            "command": "sudo -l 2>/dev/null",
            "rationale": "Passwordless sudo entries are frequent lab misconfigurations.",
            "source": "builtin",
        },
        {
            "priority": 3,
            "action": "capabilities_check",
            "command": "getcap -r / 2>/dev/null",
            "rationale": "Linux capabilities (cap_setuid, cap_net_raw) bypass standard root check.",
            "source": "builtin",
        },
        {
            "priority": 4,
            "action": "cron_writable",
            "command": "ls -la /etc/cron* /var/spool/cron/ 2>/dev/null; find /etc/cron* -writable 2>/dev/null",
            "rationale": "Writable cron jobs run as root — classic path injection target.",
            "source": "builtin",
        },
        {
            "priority": 5,
            "action": "path_hijack",
            "command": "echo $PATH; find / -writable -type d 2>/dev/null | grep -v proc | head -20",
            "rationale": "Writable dirs in $PATH allow hijacking commands called by root scripts.",
            "source": "builtin",
        },
        {
            "priority": 6,
            "action": "service_config_write",
            "command": "find /etc/systemd /etc/init.d /etc/rc.d -writable 2>/dev/null",
            "rationale": "Writable service configs → inject command, trigger on restart.",
            "source": "builtin",
        },
        {
            "priority": 7,
            "action": "group_check",
            "command": "id | grep -E 'docker|lxd|disk|adm|sudo|wheel'",
            "rationale": "Group membership in docker/lxd/disk → trivial root escalation.",
            "source": "builtin",
        },
        {
            "priority": 8,
            "action": "passwd_shadow_perms",
            "command": "ls -la /etc/passwd /etc/shadow 2>/dev/null; stat /etc/passwd",
            "rationale": "Writable /etc/passwd → add root-equivalent user without password.",
            "source": "builtin",
        },
    ],
}

# IMPROVEMENT-1: stuck-signal → injected step mapping.
_STUCK_SIGNAL_STEPS: dict[str, dict[str, Any]] = {
    "shell_lost": {
        "action": "reset_listener",
        "command": "nc -lvnp 4444  # re-run exploit to reconnect",
        "rationale": "Stuck: shell_lost — foothold is dead. Re-exploit same vector or pivot to stable shell.",
        "source": "stuck",
    },
    "hash_stuck": {
        "action": "escalate_gpu",
        "command": "bash scripts/crack-helper.sh --async  # or upload hash to Colab/Kaggle",
        "rationale": "Stuck: hash_stuck — CPU cracking exhausted. Offload to GPU while pivoting other vectors.",
        "source": "stuck",
    },
    "cred_exhausted": {
        "action": "pivot_vector",
        "command": "# All creds exhausted — run stuck_check to see alternatives[]",
        "rationale": "Stuck: cred_exhausted — all spray paths failed. Switch to alternative attack vector.",
        "source": "stuck",
    },
    # IMP-06
    "rabbit_hole": {
        "action": "pivot_away",
        "command": "# Rabbit hole — revisar tried[] y cambiar vector. Consultar attack_plan.alternative_chains.",
        "rationale": "Stuck: rabbit_hole — misma acción repetida sin nuevos findings. Pivot obligatorio.",
        "source": "stuck",
    },
}

# Extended prefix set for _extract_command_hint — covers GTFOBins/LOLBAS output.
_SHELL_CMD_PREFIXES = (
    "nmap", "curl", "wget", "python", "python3", "find", "sudo",
    "ssh", "nc", "netcat", "ncat", "msfconsole", "msfvenom", "searchsploit",
    "crackmapexec", "cme", "nxc", "evil-winrm", "impacket", "gobuster",
    "ffuf", "feroxbuster", "wfuzz", "hydra", "john", "hashcat", "sqlmap",
    "vim", "vi", "perl", "ruby", "php", "lua", "awk", "gawk", "sed",
    "tar", "zip", "gzip", "less", "more", "man", "env", "install",
    "cp", "mv", "chmod", "chown", "cat",
    "openssl", "base64", "xxd", "od",
    "gcc", "make", "go", "rustc",
    "docker", "kubectl", "helm",
    "responder", "bloodhound", "certipy", "impacket-",
    "git", "svn", "pip", "apt", "yum", "dnf",
    "getcap", "setcap", "script",
)


def _build_next_step_query(phase: str, findings: list[str], os_hint: str) -> str:
    """Combine phase prefix + findings + os into a single KB query string."""
    prefix = _PHASE_KB_PREFIX.get(phase, phase.replace("_", " "))
    findings_blob = " ".join(findings[:6])  # cap to avoid overly long queries
    parts = [prefix, findings_blob]
    if os_hint:
        parts.append(os_hint)
    return " ".join(p for p in parts if p).strip()


# IMPROVEMENT-2: Jaccard-based fuzzy dedup.

def _jaccard_similarity(a: set[str], b: set[str]) -> float:
    """Jaccard similarity between two token sets. Returns 1.0 for two empty sets."""
    union = a | b
    if not union:
        return 1.0
    return len(a & b) / len(union)


def _strip_cmd_annotation(cmd: str) -> str:
    """Strip descriptive annotation from a command hint.

    Handles 'sudo -l 2>/dev/null — check permissions' → 'sudo -l 2>/dev/null'.
    Separators tried in order (most-specific first): em-dash with spaces, en-dash with
    spaces, bare em-dash, bare en-dash, hash comment.
    """
    for sep in (" — ", " – ", "—", "–", " # "):
        if sep in cmd:
            return cmd[:cmd.index(sep)].strip()
    return cmd.strip()


def _chunk_matches_tried(chunk_text: str, tried: list[str]) -> bool:
    """Return True if any tried command is Jaccard-similar (≥0.6) to the chunk's command hint.

    Strips inline annotations before comparison so that 'sudo -l 2>/dev/null — description'
    and 'sudo -l' correctly measure as the same command rather than being diluted by the
    annotation tokens inflating the union.
    """
    raw_hint = _extract_command_hint(chunk_text)
    compare = _strip_cmd_annotation(raw_hint) if raw_hint else chunk_text[:80]
    compare_tokens = set(compare.lower().split())
    for attempt in tried:
        attempt_tokens = set(attempt.lower().split())
        if not attempt_tokens:
            continue
        if _jaccard_similarity(attempt_tokens, compare_tokens) >= _JACCARD_THRESHOLD:
            return True
    return False


def _extract_command_hint(text: str) -> str:
    """Best-effort: pull the first shell-like line from a KB chunk."""
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith(("$", "#", "`")) or any(
            stripped.startswith(cmd) for cmd in _SHELL_CMD_PREFIXES
        ):
            return stripped.lstrip("$# `").strip()
    # Fallback: first non-empty line truncated to 120 chars
    for line in text.splitlines():
        if line.strip():
            return line.strip()[:120]
    return ""


def _steps_from_chunks(chunks: list[dict[str, Any]], tried: list[str]) -> list[dict[str, Any]]:
    """Convert KB chunks into step dicts, filtering tried paths, highest score first."""
    steps: list[dict[str, Any]] = []
    for i, chunk in enumerate(chunks):
        if _chunk_matches_tried(chunk.get("text", ""), tried):
            continue
        text = chunk.get("text", "")
        steps.append(
            {
                "priority": i + 1,
                "action": f"kb_step_{i + 1}",
                "command": _extract_command_hint(text),
                "rationale": text[:200],
                "source": chunk.get("source", "kb"),
            }
        )
    return steps


def _detect_stuck_signals(session_dir_str: str, machine: str) -> list[str]:
    """Run stuck detectors against session artifacts. Auto-resolves from machine if dir empty."""
    sdir_str = session_dir_str
    if not sdir_str:
        # QW: auto-resolve from machine context so callers don't have to pass session_dir.
        try:
            resolved = _resolve_session_dir(machine)
            if resolved.exists():
                sdir_str = str(resolved)
        except Exception:
            pass
    if not sdir_str:
        return []
    sdir = Path(sdir_str)
    if not sdir.exists():
        return []
    estado = read_file_safe(sdir / "estado.md")
    findings_txt = read_file_safe(sdir / "findings.md")
    jsonl = read_jsonl(sdir / "sessions.jsonl")
    signals: list[str] = []
    if detect_shell_lost(estado, findings_txt):
        signals.append("shell_lost")
    if detect_hash_stuck(estado, jsonl):
        signals.append("hash_stuck")
    if detect_cred_exhausted(estado, jsonl):
        signals.append("cred_exhausted")
    # IMP-06
    if detect_rabbit_hole(estado, jsonl):
        signals.append("rabbit_hole")
    return signals


# ── intel_next_step ──────────────────────────────────────────────────────────


@registry.tool(
    name="intel_next_step",
    description=(
        "Given current phase + tried list + findings, returns prioritised next steps with "
        "exact commands. Queries KB, filters tried paths via Jaccard dedup, auto-detects stuck "
        "signals from session artifacts, and injects recovery steps when stuck. Falls back to "
        "built-in phase templates when KB is unavailable."
    ),
    category="intel",
    input_schema={
        "type": "object",
        "properties": {
            "machine": {"type": "string"},
            "current_phase": {
                "type": "string",
                "enum": ["p2_enum", "p3_foothold", "p3a_pre_foothold", "p3b_post_foothold", "p4_privesc"],
            },
            "tried": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Commands or techniques already attempted without success.",
            },
            "findings": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Services, versions, or artefacts discovered so far.",
            },
            "os_hint": {"type": "string", "default": ""},
            "top_k": {"type": "integer", "default": 5},
            "session_dir": {
                "type": "string",
                "default": "",
                "description": "Path to session dir for stuck detection. Auto-resolved from machine if omitted.",
            },
        },
        "required": ["machine", "current_phase", "tried", "findings"],
    },
)
async def intel_next_step(
    machine: str,
    current_phase: str,
    tried: list[str],
    findings: list[str],
    os_hint: str = "",
    top_k: int = 5,
    session_dir: str = "",
) -> dict[str, Any]:
    # IMP-17: Auto-cargar tried desde state para dedup cross-session
    _auto_tried_count = 0
    try:
        _ctx = mcp_context.get_context()
        _m = _ctx.state_store.get_machine(machine) if machine else None
        _auto_tried: list[str] = []
        if _m:
            _auto_tried += [
                c.password for c in (getattr(_m, "tried_credentials", None) or [])
                if getattr(c, "result", None) == "auth_failed" and getattr(c, "password", None)
            ]
            _auto_tried += [
                e.path for e in (getattr(_m, "tried_endpoints", None) or [])
                if not getattr(e, "interesting", True)
            ]
        tried = list(set(tried or []) | set(_auto_tried))
        _auto_tried_count = len(_auto_tried)
    except Exception:
        _auto_tried_count = 0

    query = _build_next_step_query(current_phase, findings, os_hint)
    kb_result = await intel_kb_query(query, top_k=top_k)
    chunks = kb_result.get("chunks", [])

    steps = _steps_from_chunks(chunks, tried)

    if not steps:
        fallback = _PHASE_FALLBACK_STEPS.get(current_phase, [])
        # Deep-copy dicts so we don't mutate the module-level template on priority rewrite.
        steps = [
            dict(s) for s in fallback
            if not _chunk_matches_tried(s["command"] + " " + s["rationale"], tried)
        ] or [dict(s) for s in fallback]

    # IMPROVEMENT-1: prepend stuck-signal recovery steps.
    stuck_signals = _detect_stuck_signals(session_dir, machine)
    injected: list[dict[str, Any]] = []
    for sig in stuck_signals:
        template = _STUCK_SIGNAL_STEPS.get(sig)
        if template:
            injected.append(dict(template))
    steps = injected + steps

    # Re-number priorities after injection + filtering.
    for idx, step in enumerate(steps):
        step["priority"] = idx + 1

    return {
        "machine": machine,
        "phase": current_phase,
        "query_used": query,
        "kb_available": kb_result.get("available", False),
        "kb_active": len(chunks) > 0,
        "stuck_signals": stuck_signals,
        "steps": steps[:top_k],
        "kb_chunks": chunks,
        "tried_count": len(tried),
        "findings_count": len(findings),
        "auto_tried_merged": _auto_tried_count,
    }


# ── lolbin_suggest ───────────────────────────────────────────────────────────


@registry.tool(
    name="lolbin_suggest",
    description=(
        "Given a list of binaries found on the target, queries LOLBAS/GTFOBins KB entries "
        "and returns exploitable techniques per binary. Queries run concurrently. "
        "Duplicate binary names are deduplicated before querying."
    ),
    category="intel",
    input_schema={
        "type": "object",
        "properties": {
            "binaries": {
                "type": "array",
                "items": {"type": "string"},
                "description": "Binary names found on the target, e.g. ['find', 'python3', 'vim'].",
            },
            "context": {
                "type": "string",
                "default": "",
                "description": "Additional context such as 'SUID', 'sudo nopasswd', 'writable'.",
            },
            "os_hint": {"type": "string", "default": "linux"},
            "top_k_per_binary": {"type": "integer", "default": 2},
        },
        "required": ["binaries"],
    },
)
async def lolbin_suggest(
    binaries: list[str],
    context: str = "",
    os_hint: str = "linux",
    top_k_per_binary: int = 2,
) -> dict[str, Any]:
    if not binaries:
        return {"suggestions": {}, "binaries_with_hits": [], "binaries_queried": []}

    # QW: dedup binaries — avoid redundant KB queries when caller passes duplicates.
    unique_binaries = list(dict.fromkeys(binaries))

    async def _query_one(binary: str) -> tuple[str, list[dict[str, Any]]]:
        query = f"{binary} {context} {os_hint} privilege escalation file read write".strip()
        result = await intel_kb_query(query, top_k=top_k_per_binary)
        techniques: list[dict[str, Any]] = []
        for chunk in result.get("chunks", []):
            text = chunk.get("text", "")
            techniques.append(
                {
                    "technique": text[:120],
                    "command": _extract_command_hint(text),
                    "source": chunk.get("source", "kb"),
                    "score": chunk.get("score", 0.0),
                }
            )
        return binary, techniques

    pairs = await asyncio.gather(*(_query_one(b) for b in unique_binaries))

    suggestions: dict[str, list[dict[str, Any]]] = {}
    binaries_with_hits: list[str] = []
    for binary, techniques in pairs:
        suggestions[binary] = techniques
        if techniques:
            binaries_with_hits.append(binary)

    return {
        "suggestions": suggestions,
        "binaries_with_hits": binaries_with_hits,
        "binaries_queried": unique_binaries,
    }
