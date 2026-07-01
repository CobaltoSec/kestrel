"""MCP tools — reconnaissance primitives (nmap, web/smb/dns/ldap enum).

All tools execute on the Kali VM via SSH. Heavy outputs (nmap XML, smbclient
listings) are saved to ``<session_dir>/recon/`` when a ``machine`` is given,
and the parsed summary is returned in the response.
"""

from __future__ import annotations

import asyncio
import re
import shlex
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry
from kestrel.mcp.tools.state import _resolve_session_dir
from kestrel.transport import kali_proxy


NMAP_PROFILES: dict[str, str] = {
    "quick": "-sS -T4 --top-ports=1000 -oX -",
    "full": "-sS -T4 -p- -sV -sC --max-retries=1 --host-timeout 600s --max-rtt-timeout 300ms --initial-rtt-timeout 50ms -oX -",
    "udp": "-sU -T4 --top-ports=100 --max-rtt-timeout 200ms --initial-rtt-timeout 50ms --max-retries=1 -oX -",
    "nse_smb": "-p139,445 -sS --script=smb-enum-shares,smb-enum-users,smb-vuln-* -oX -",
    "os_detect": "-sS -O --osscan-guess -p22,80,443,445,3389 -oX -",
}

_HEAVY_CMDS = ("nmap", "nuclei", "enum4linux", "feroxbuster", "ffuf", "gobuster", "sqlmap")


async def _run_kali(cmd: str, timeout: float = 600.0) -> dict[str, Any]:
    first_token = cmd.strip().split()[0]
    if any(first_token.endswith(t) for t in _HEAVY_CMDS):
        safe_secs = max(30, int(timeout) - 30)
        cmd = f"timeout {safe_secs}s {cmd}"
    res = await asyncio.to_thread(kali_proxy.via_kali, cmd, timeout)
    result = {
        "cmd": cmd,
        "rc": res.rc,
        "stdout": res.stdout,
        "stderr": res.stderr.strip(),
        "duration_s": res.duration_s,
    }
    if res.infrastructure_error:
        result["infrastructure_error"] = True
        result["hint"] = "Verificar que Kali VM esté up con kali_status()"
    return result


def _save_artifact(machine: str | None, subdir: str, filename: str, content: str) -> str | None:
    """Save raw artifact under <session_dir>/recon/<subdir>/<filename>. Returns full path or None."""
    if machine is None:
        return None
    try:
        session_dir = _resolve_session_dir(machine)
    except ValueError:
        return None
    out_dir = session_dir / "recon" / subdir
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / filename
    path.write_text(content, encoding="utf-8")
    return str(path)


def _parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    """Parse nmap XML output into a structured dict."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as exc:
        return {"parse_error": str(exc), "hosts": []}

    hosts_out: list[dict[str, Any]] = []
    for host in root.findall("host"):
        status_el = host.find("status")
        status = status_el.attrib.get("state") if status_el is not None else "unknown"
        addr_el = host.find("address")
        addr = addr_el.attrib.get("addr") if addr_el is not None else None

        ports_out: list[dict[str, Any]] = []
        ports_el = host.find("ports")
        if ports_el is not None:
            for port in ports_el.findall("port"):
                state_el = port.find("state")
                svc_el = port.find("service")
                port_dict: dict[str, Any] = {
                    "port": int(port.attrib.get("portid", 0)),
                    "protocol": port.attrib.get("protocol"),
                    "state": state_el.attrib.get("state") if state_el is not None else "unknown",
                }
                if svc_el is not None:
                    port_dict["service"] = svc_el.attrib.get("name")
                    if "product" in svc_el.attrib:
                        port_dict["product"] = svc_el.attrib.get("product")
                    if "version" in svc_el.attrib:
                        port_dict["version"] = svc_el.attrib.get("version")
                ports_out.append(port_dict)

        os_matches = []
        os_el = host.find("os")
        if os_el is not None:
            for osmatch in os_el.findall("osmatch"):
                os_matches.append({
                    "name": osmatch.attrib.get("name"),
                    "accuracy": int(osmatch.attrib.get("accuracy", 0)),
                })

        hosts_out.append({
            "address": addr,
            "status": status,
            "ports": ports_out,
            "os_matches": os_matches,
        })
    return {"hosts": hosts_out, "host_count": len(hosts_out)}


# ── IMP-16/18/19 helpers ─────────────────────────────────────────────────────


def _endpoint_url(target: str, port: int) -> str:
    scheme = "https" if port in (443, 8443) else "http"
    return f"{scheme}://{target}:{port}/"


def _check_endpoint_tried(target: str, port: int, machine: str | None) -> bool:
    """IMP-16: return True if target:port already in tried_endpoints as not-interesting."""
    if machine is None:
        return False
    try:
        ctx = mcp_context.get_context()
        m = ctx.state_store.get_machine(machine)
        if m is None:
            return False
        url = _endpoint_url(target, port)
        for ep in (m.tried_endpoints or []):
            if ep.path == url and not ep.interesting:
                return True
    except Exception:
        pass
    return False


def _save_endpoint_tried(machine: str | None, url: str, status: int | None = None, interesting: bool = False) -> None:
    """IMP-19: persist a probed endpoint to state.machines[machine].tried_endpoints."""
    if machine is None:
        return
    try:
        ctx = mcp_context.get_context()
        m = ctx.state_store.get_machine(machine)
        existing = list(m.tried_endpoints) if m and m.tried_endpoints else []
        # avoid duplicates
        for ep in existing:
            if ep.path == url:
                return
        from kestrel.state.schema import TriedEndpoint
        existing.append(TriedEndpoint(
            path=url,
            status=status,
            interesting=interesting,
            ts=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        ))
        ctx.state_store.update_machine(machine, {"tried_endpoints": [e.model_dump(mode="json") for e in existing]})
    except Exception:
        pass


async def _auto_narrate(stream: str, text: str, machine: str | None) -> None:
    """IMP-18: fire-and-forget narration emitted by heavy tools on completion."""
    try:
        from kestrel.mcp.tools.narrate import narrate_emit
        await narrate_emit(stream=stream, text=text, machine=machine)
    except Exception:
        pass


# ── Tools ─────────────────────────────────────────────────────────────────────


@registry.tool(
    name="recon_nmap_scan",
    description=(
        "Run nmap against `target` with the given profile (quick|full|udp|nse_smb). "
        "Returns parsed ports + services. Saves raw XML to <session_dir>/recon/nmap/ if machine given."
    ),
    category="recon",
)
async def recon_nmap_scan(
    target: str,
    profile: str = "quick",
    ports: str | None = None,
    machine: str | None = None,
) -> dict[str, Any]:
    if profile not in NMAP_PROFILES:
        return {"error": "invalid_profile", "valid": list(NMAP_PROFILES.keys()), "got": profile}
    base = NMAP_PROFILES[profile]
    if ports:
        # Override -p in profiles that have it
        base = base.replace("--top-ports=1000", "").replace("--top-ports=100", "").replace("-p139,445", "").replace("-p22,80,443,445,3389", "")
        cmd = f"nmap {base.strip()} -p {shlex.quote(ports)} {shlex.quote(target)}"
    else:
        cmd = f"nmap {base} {shlex.quote(target)}"
    raw = await _run_kali(cmd, timeout=900.0)
    parsed = _parse_nmap_xml(raw["stdout"])
    artifact = _save_artifact(machine, "nmap", f"{target.replace(':', '_').replace('/', '_')}-{profile}.xml", raw["stdout"])
    # IMP-18: auto-narrate nmap completion
    host_count = parsed.get("host_count", 0)
    port_count = sum(len(h.get("ports", [])) for h in parsed.get("hosts", []))
    await _auto_narrate("📡", f"nmap {profile} {target}: {host_count} hosts, {port_count} ports open", machine)
    return {
        "target": target,
        "profile": profile,
        "rc": raw["rc"],
        "duration_s": raw["duration_s"],
        "summary": parsed,
        "artifact": artifact,
    }


@registry.tool(
    name="recon_service_probe",
    description=(
        "Probe a single target:port with nmap version detection + scripts (-sV -sC --version-all). "
        "Use for service-specific deep-dive after recon_nmap_scan."
    ),
    category="recon",
)
async def recon_service_probe(
    target: str,
    port: int,
    service_hint: str | None = None,
    machine: str | None = None,
) -> dict[str, Any]:
    script = "default"
    if service_hint:
        script = f"default,{service_hint}"
    cmd = (
        f"nmap -Pn -p {port} -sV -sC --version-all --script={script} "
        f"-oX - {shlex.quote(target)}"
    )
    raw = await _run_kali(cmd, timeout=300.0)
    parsed = _parse_nmap_xml(raw["stdout"])
    artifact = _save_artifact(
        machine, "service-probe", f"{target}_{port}.xml", raw["stdout"]
    )
    return {
        "target": target,
        "port": port,
        "rc": raw["rc"],
        "summary": parsed,
        "artifact": artifact,
    }


@registry.tool(
    name="recon_web_fingerprint",
    description=(
        "HTTP(S) fingerprint via curl: status code, server, headers, title. "
        "Use on web ports identified by nmap (80, 443, 8080, etc.)."
    ),
    category="recon",
)
async def recon_web_fingerprint(
    target: str,
    port: int = 80,
    machine: str | None = None,
) -> dict[str, Any]:
    # IMP-16: skip if already tried and not interesting
    if _check_endpoint_tried(target, port, machine):
        url = _endpoint_url(target, port)
        return {"skipped": True, "reason": "endpoint_already_tried", "url": url, "machine": machine}

    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{target}:{port}/"
    cmd = (
        f"curl -ksI --max-time 15 {shlex.quote(url)} ; "
        f"echo '---BODY---' ; "
        f"curl -ks --max-time 15 {shlex.quote(url)} | head -c 16000"
    )
    raw = await _run_kali(cmd, timeout=30.0)
    headers, _, body = raw["stdout"].partition("---BODY---")
    fp = {
        "url": url,
        "status_line": None,
        "server": None,
        "powered_by": None,
        "title": None,
    }
    status_code: int | None = None
    for line in headers.splitlines():
        line = line.strip()
        if line.startswith("HTTP/"):
            fp["status_line"] = line
            try:
                status_code = int(line.split()[1])
            except (IndexError, ValueError):
                pass
        elif line.lower().startswith("server:"):
            fp["server"] = line.split(":", 1)[1].strip()
        elif line.lower().startswith("x-powered-by:"):
            fp["powered_by"] = line.split(":", 1)[1].strip()
    body_l = body.lower()
    if "<title>" in body_l:
        s = body_l.index("<title>") + len("<title>")
        e = body_l.find("</title>", s)
        if e > s:
            fp["title"] = body[s:e].strip()

    # __NEXT_DATA__ extraction
    import re as _re_next
    import json as _json_next
    next_data = None
    if "__NEXT_DATA__" in body:
        m_nd = _re_next.search(
            r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(\{.*?\})</script>',
            body, _re_next.DOTALL
        )
        if m_nd:
            try:
                next_data = _json_next.loads(m_nd.group(1))
            except Exception:
                next_data = {"raw": m_nd.group(1)[:1000]}

    artifact = _save_artifact(machine, "web", f"{target}_{port}.txt", raw["stdout"])
    # IMP-19: persist endpoint to state
    _save_endpoint_tried(machine, url, status=status_code, interesting=bool(fp["title"]))

    # IMP-02: static RSC detection — only fires when Next.js is detected
    nextjs_analysis: dict[str, Any] | None = None
    powered_by = (fp.get("powered_by") or "").lower()
    if "_next" in body.lower() or powered_by.startswith("next"):
        nextjs_analysis = await _probe_nextjs(target, port)

    return {**fp, "rc": raw["rc"], "artifact": artifact, "nextjs_analysis": nextjs_analysis, "next_data": next_data}


async def _probe_nextjs(target: str, port: int) -> dict[str, Any]:
    """IMP-02: lightweight Next.js static-vs-dynamic probe + manifest content read."""
    scheme = "https" if port in (443, 8443) else "http"
    base = f"{scheme}://{target}:{port}"
    cmd = (
        f"curl -ks --max-time 10 -o /dev/null -w '%{{http_code}}' "
        f"{shlex.quote(base + '/_next/data/buildManifest.json')} ; "
        f"echo '---MANIFEST---' ; "
        f"curl -ks --max-time 10 {shlex.quote(base + '/_next/static/buildManifest.js')} | head -c 8000 ; "
        f"echo '---PAGES---' ; "
        f"curl -ks --max-time 10 {shlex.quote(base + '/_next/static/chunks/pages-manifest.json')} 2>/dev/null | head -c 4000 ; "
        f"echo '---RSC---' ; "
        f"curl -ks --max-time 10 {shlex.quote(base + '/__next_f')} 2>/dev/null | head -c 300"
    )
    raw = await _run_kali(cmd, timeout=35.0)
    # Parse output sections
    manifest_raw, _, rest = raw["stdout"].partition("---MANIFEST---")
    manifest_status = manifest_raw.strip()
    manifest_body, _, rest2 = rest.partition("---PAGES---")
    _pages_body, _, rsc_raw = rest2.partition("---RSC---")
    manifest_content = manifest_body.strip()[:2000] if manifest_body.strip() else None
    rsc_chunk = rsc_raw.strip()
    # Server Actions presence: RSC payload contains "S":true or "action" references
    has_server_actions = '"S":true' in rsc_chunk or '"action"' in rsc_chunk
    is_static = not has_server_actions
    hint: str | None = None
    if is_static:
        hint = (
            "Next.js puro estático — superficie web agotada. "
            "Pasos obligatorios en orden: "
            "1) creds_themed_wordlist_gen(machine=<slug>, keywords=[<page_keywords>], staff=[<names>]) "
            "2) creds_ssh_bruteforce(target=<ip>, users=[<candidates>], wordlist=<output_path>) "
            "3) Si falla: creds_ssh_bruteforce con /usr/share/wordlists/rockyou.txt. "
            "NO seguir explorando la web — el vector es SSH."
        )
    return {
        "detected": True,
        "is_static": is_static,
        "has_build_manifest": manifest_status == "200",
        "manifest_content": manifest_content,
        "has_server_actions": has_server_actions,
        "operator_hint": hint,
    }


@registry.tool(
    name="recon_smb_enum",
    description="Enumerate SMB shares + users via smbclient + enum4linux-ng on Kali.",
    category="recon",
)
async def recon_smb_enum(
    target: str,
    machine: str | None = None,
) -> dict[str, Any]:
    cmd = (
        f"echo '=== smbclient -L ===' ; "
        f"smbclient -L {shlex.quote(target)} -N 2>&1 ; "
        f"echo '=== enum4linux-ng -A ===' ; "
        f"enum4linux-ng -A {shlex.quote(target)} 2>&1 | head -c 8000"
    )
    raw = await _run_kali(cmd, timeout=180.0)
    shares: list[str] = []
    for line in raw["stdout"].splitlines():
        stripped = line.strip()
        # smbclient share table rows
        if "Disk" in stripped or "IPC" in stripped:
            parts = stripped.split()
            if parts and not parts[0].lower().startswith(("sharename", "---")):
                shares.append(parts[0])
    artifact = _save_artifact(machine, "smb", f"{target}.txt", raw["stdout"])
    # IMP-18: auto-narrate smb enum result
    await _auto_narrate("📡", f"smb enum {target}: shares={shares or 'none'}", machine)
    return {
        "target": target,
        "shares_detected": shares,
        "rc": raw["rc"],
        "artifact": artifact,
    }


@registry.tool(
    name="recon_dns_enum",
    description="DNS enumeration via dig + dnsenum (NS, MX, SOA, axfr attempt) against target.",
    category="recon",
)
async def recon_dns_enum(
    target: str,
    domain: str | None = None,
    machine: str | None = None,
) -> dict[str, Any]:
    q = domain or target
    cmd = (
        f"dig +short ns {shlex.quote(q)} ; "
        f"dig +short mx {shlex.quote(q)} ; "
        f"dig +short txt {shlex.quote(q)} ; "
        f"dig @{shlex.quote(target)} {shlex.quote(q)} axfr 2>&1 | head -200"
    )
    raw = await _run_kali(cmd, timeout=60.0)
    artifact = _save_artifact(machine, "dns", f"{q}.txt", raw["stdout"])
    return {"target": target, "domain": q, "rc": raw["rc"], "stdout": raw["stdout"], "artifact": artifact}


@registry.tool(
    name="recon_ldap_enum",
    description="LDAP anonymous bind + naming context enumeration via ldapsearch.",
    category="recon",
)
async def recon_ldap_enum(
    target: str,
    machine: str | None = None,
) -> dict[str, Any]:
    cmd = (
        f"ldapsearch -x -h {shlex.quote(target)} -s base -b '' "
        f"'(objectclass=*)' 2>&1 | head -c 8000"
    )
    raw = await _run_kali(cmd, timeout=60.0)
    artifact = _save_artifact(machine, "ldap", f"{target}.txt", raw["stdout"])
    naming_contexts: list[str] = []
    for line in raw["stdout"].splitlines():
        if line.startswith("namingContexts:"):
            naming_contexts.append(line.split(":", 1)[1].strip())
    return {
        "target": target,
        "rc": raw["rc"],
        "naming_contexts": naming_contexts,
        "artifact": artifact,
    }


# IMP-05: recon_web_dirfuzz ───────────────────────────────────────────────────

_NEXTJS_PROBE_PATHS = [
    "api/users", "api/user", "api/me", "api/auth", "api/login", "api/admin",
    "admin", "login", "dashboard", "team", "about", "staff",
    "_next/data", "api/v1/users",
]

_DIRFUZZ_LINE_RE = re.compile(
    r"^\s*(\d{3})\s+.*?(https?://\S+)\s*$",
    re.IGNORECASE,
)


def _parse_feroxbuster(stdout: str) -> list[dict[str, Any]]:
    """Parse feroxbuster output lines: STATUS SIZE WORDS LINES METHOD URL."""
    results: list[dict[str, Any]] = []
    for line in stdout.splitlines():
        m = _DIRFUZZ_LINE_RE.match(line)
        if m:
            status = int(m.group(1))
            url = m.group(2)
            # include 2xx and 3xx only (exclude 4xx noise)
            if 200 <= status < 400:
                results.append({"status": status, "url": url})
    return results


@registry.tool(
    name="recon_web_dirfuzz",
    description=(
        "Web directory/file fuzzing via feroxbuster (fallback: gobuster) on Kali. "
        "IMP-05: Discovers hidden paths on web targets. "
        "IMP-16: skips if root URL already tried and not interesting. "
        "IMP-18: auto-narrates result. "
        "IMP-19: saves discovered paths to tried_endpoints."
    ),
    category="recon",
)
async def recon_web_dirfuzz(
    target: str,
    port: int = 80,
    wordlist: str = "/usr/share/seclists/Discovery/Web-Content/common.txt",
    extensions: str = "php,txt,bak,html",
    depth: int = 2,
    machine: str | None = None,
    bypass_header: str | None = None,
    extra_paths: list[str] | None = None,
) -> dict[str, Any]:
    # IMP-16: skip if already tried and not interesting
    if _check_endpoint_tried(target, port, machine):
        url = _endpoint_url(target, port)
        return {"skipped": True, "reason": "endpoint_already_tried", "url": url, "machine": machine}

    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}:{port}/"

    # IMP-06: optional bypass header (e.g. x-middleware-subrequest for Next.js middleware bypass)
    header_arg = f"-H {shlex.quote(bypass_header)}" if bypass_header else ""

    # Probe Next.js before main fuzz
    _probe_cmd = (
        f"curl -ks -o /dev/null -w '%{{http_code}}' --max-time 5 "
        f"{shlex.quote(base_url + '_next/static/')}"
    )
    _probe_res = await _run_kali(_probe_cmd, timeout=10.0)
    nextjs_detected = _probe_res.get("stdout", "").strip() in ("200", "403", "301", "302")

    # Build feroxbuster command; embed Next.js probe as first step in same shell call
    ferox_cmd = (
        f"_NJS=$(curl -ks -o /dev/null -w '%{{http_code}}' --max-time 5 "
        f"{shlex.quote(base_url + '_next/static/')} 2>/dev/null); "
        f"echo \"NEXTJS_PROBE:$_NJS\"; "
        f"command -v feroxbuster >/dev/null 2>&1 && "
        f"feroxbuster --url {shlex.quote(base_url)} "
        f"--wordlist {shlex.quote(wordlist)} "
        f"--extensions {shlex.quote(extensions)} "
        f"--depth {depth} "
        f"--no-state --no-recursion-limit --silent "
        f"--timeout 10 -k {header_arg} 2>/dev/null "
        f"|| command -v gobuster >/dev/null 2>&1 && "
        f"gobuster dir --url {shlex.quote(base_url)} "
        f"--wordlist {shlex.quote(wordlist)} "
        f"--extensions {shlex.quote(extensions)} "
        f"--no-progress -q -k 2>/dev/null "
        f"|| echo 'KESTREL_ERROR: feroxbuster and gobuster not found on Kali'"
    )

    raw = await _run_kali(ferox_cmd, timeout=600.0)

    if "KESTREL_ERROR" in raw["stdout"]:
        return {
            "error": "tool_not_found",
            "hint": "Install feroxbuster or gobuster on Kali: apt install feroxbuster gobuster",
            "target": target,
        }

    # Parse Next.js probe result from embedded output line
    nextjs_detected = False
    for _line in raw["stdout"].splitlines():
        if _line.startswith("NEXTJS_PROBE:"):
            _njs_status = _line.split(":", 1)[1].strip()
            nextjs_detected = _njs_status in ("200", "403", "301", "302")
            break

    discovered = _parse_feroxbuster(raw["stdout"])
    raw_output = raw["stdout"]

    # IMP-06: extra_paths — domain-themed paths fuzzed as a second pass
    if extra_paths:
        paths_content = "\n".join(extra_paths)
        extra_cmd = (
            f"echo {shlex.quote(paths_content)} > /tmp/kestrel_extra_paths.txt && "
            f"command -v feroxbuster >/dev/null 2>&1 && "
            f"feroxbuster --url {shlex.quote(base_url)} "
            f"--wordlist /tmp/kestrel_extra_paths.txt "
            f"--no-state --silent --timeout 10 -k {header_arg} 2>/dev/null"
        )
        extra_raw = await _run_kali(extra_cmd, timeout=120.0)
        discovered += _parse_feroxbuster(extra_raw["stdout"])
        raw_output += "\n--- extra_paths ---\n" + extra_raw["stdout"]

    # Auto-escalate to raft-medium when common.txt yields 0 results
    _MEDIUM_WL = "/usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt"
    if (
        len(discovered) == 0
        and wordlist == "/usr/share/seclists/Discovery/Web-Content/common.txt"
    ):
        medium_cmd = (
            f"command -v feroxbuster >/dev/null 2>&1 && "
            f"feroxbuster --url {shlex.quote(base_url)} "
            f"--wordlist {_MEDIUM_WL} "
            f"--extensions {shlex.quote(extensions)} "
            f"--depth {depth} "
            f"--no-state --no-recursion-limit --silent "
            f"--timeout 10 -k {header_arg} 2>/dev/null"
        )
        medium_raw = await _run_kali(medium_cmd, timeout=600.0)
        discovered += _parse_feroxbuster(medium_raw["stdout"])
        raw_output += "\n--- raft-medium-words escalation ---\n" + medium_raw["stdout"]

    artifact = _save_artifact(
        machine, "dirfuzz",
        f"{target}_{port}.txt",
        raw_output,
    )

    # IMP-19: save interesting paths to tried_endpoints
    for item in discovered:
        _save_endpoint_tried(machine, item["url"], status=item["status"], interesting=True)
    # save root URL as tried (not interesting if we got no results, interesting otherwise)
    _save_endpoint_tried(machine, base_url, status=None, interesting=bool(discovered))

    # IMP-18: auto-narrate result
    await _auto_narrate("📡", f"dirfuzz {base_url}: {len(discovered)} paths discovered", machine)

    return {
        "target": target,
        "port": port,
        "base_url": base_url,
        "rc": raw["rc"],
        "duration_s": raw["duration_s"],
        "discovered": discovered,
        "discovered_count": len(discovered),
        "artifact": artifact,
        "bypass_header_used": bypass_header,
        "extra_paths_count": len(extra_paths) if extra_paths else 0,
        "nextjs_detected": nextjs_detected,
        "nextjs_suggested_paths": _NEXTJS_PROBE_PATHS if nextjs_detected else [],
    }


# IMP-05: recon_web_username_extract ──────────────────────────────────────────

_HTML_TAG_RE = re.compile(r"<[^>]+>")
_PROPER_NAME_RE = re.compile(r"\b([A-Z][a-z]{2,15})\s+([A-Z][a-z]{2,15})\b")

# Common false-positive words that look like proper names
_NAME_STOPWORDS = frozenset({
    "About", "Admin", "Alert", "Allow", "Apply", "Back", "Base", "Blog", "Body",
    "Bold", "Bool", "Boot", "Build", "Call", "Card", "Chat", "Check", "Class",
    "Click", "Code", "Come", "Core", "Dark", "Data", "Date", "Default", "Delete",
    "Demo", "Deploy", "Desc", "Design", "Down", "Each", "Edit", "Email", "Enable",
    "Enter", "Error", "Event", "Exit", "File", "Find", "First", "Fixed", "Flag",
    "Follow", "Footer", "Form", "Free", "From", "Full", "Grid", "Head", "Help",
    "High", "Home", "Html", "Http", "Info", "Init", "Item", "Json", "Just", "Keep",
    "Last", "Layout", "Link", "List", "Live", "Load", "Login", "Logo", "Loop",
    "Mail", "Main", "Make", "Menu", "Meta", "Mode", "More", "Move", "Name", "Next",
    "None", "Note", "Null", "Once", "Only", "Open", "Page", "Pass", "Path", "Plan",
    "Post", "Print", "Props", "Read", "Real", "Role", "Root", "Rule", "Safe",
    "Save", "Send", "Size", "Some", "Sort", "Start", "State", "Step", "Stop",
    "Style", "Sync", "Tags", "Task", "Test", "Text", "Time", "Title", "Type",
    "Unit", "User", "Value", "View", "Wait", "With", "Work",
})


def _strip_html(html: str) -> str:
    return _HTML_TAG_RE.sub(" ", html)


def _generate_username_variants(first: str, last: str) -> list[str]:
    f, l = first.lower(), last.lower()
    return [
        f,
        l,
        f"{f[0]}{l}",           # flastname
        f"{f}{l}",               # firstlastname
        f"{f}.{l}",              # first.last
        f"{f}{l[0]}",            # firstl
        f"{f[0]}.{l}",          # f.last
    ]


@registry.tool(
    name="recon_web_username_extract",
    description=(
        "Extract proper names from web page HTML and generate SSH username candidates. "
        "IMP-05: Use after recon_web_fingerprint when page content includes staff names. "
        "Saves wordlist to <session_dir>/recon/usernames.txt if machine given. "
        "Pure Python — no Kali call needed."
    ),
    category="recon",
    input_schema={
        "type": "object",
        "properties": {
            "html": {
                "type": "string",
                "description": "Raw HTML or text from the web page (recon_web_fingerprint body output).",
            },
            "machine": {"type": "string"},
        },
        "required": ["html"],
    },
)
async def recon_web_username_extract(
    html: str,
    machine: str | None = None,
) -> dict[str, Any]:
    text = _strip_html(html)
    raw_pairs = _PROPER_NAME_RE.findall(text)

    names: list[str] = []
    candidates: list[str] = []
    seen_pairs: set[tuple[str, str]] = set()

    for first, last in raw_pairs:
        if first in _NAME_STOPWORDS or last in _NAME_STOPWORDS:
            continue
        pair = (first.lower(), last.lower())
        if pair in seen_pairs:
            continue
        seen_pairs.add(pair)
        names.append(f"{first} {last}")
        candidates.extend(_generate_username_variants(first, last))

    # Dedup preserving order, cap at 50
    seen: set[str] = set()
    deduped: list[str] = []
    for c in candidates:
        if c not in seen:
            seen.add(c)
            deduped.append(c)
            if len(deduped) >= 50:
                break

    wordlist_path: str | None = None
    if machine and deduped:
        artifact_path = _save_artifact(machine, "recon", "usernames.txt", "\n".join(deduped) + "\n")
        wordlist_path = artifact_path

    await _auto_narrate(
        "🔍",
        f"username extract: {len(names)} names → {len(deduped)} SSH candidates",
        machine,
    )

    return {
        "names": names,
        "username_candidates": deduped,
        "candidate_count": len(deduped),
        "wordlist_path": wordlist_path,
        "ssh_spray_hint": (
            f"nxc ssh {{target}} -u /tmp/users.txt -p /usr/share/wordlists/rockyou.txt --no-bruteforce"
            if deduped else None
        ),
    }
