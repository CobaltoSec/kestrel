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
        f"curl -ks --max-time 15 {shlex.quote(url)} | head -c 4000"
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
    artifact = _save_artifact(machine, "web", f"{target}_{port}.txt", raw["stdout"])
    # IMP-19: persist endpoint to state
    _save_endpoint_tried(machine, url, status=status_code, interesting=bool(fp["title"]))
    return {**fp, "rc": raw["rc"], "artifact": artifact}


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
) -> dict[str, Any]:
    # IMP-16: skip if already tried and not interesting
    if _check_endpoint_tried(target, port, machine):
        url = _endpoint_url(target, port)
        return {"skipped": True, "reason": "endpoint_already_tried", "url": url, "machine": machine}

    scheme = "https" if port in (443, 8443) else "http"
    base_url = f"{scheme}://{target}:{port}/"

    # Build feroxbuster command; fall back to gobuster check
    ferox_cmd = (
        f"command -v feroxbuster >/dev/null 2>&1 && "
        f"feroxbuster --url {shlex.quote(base_url)} "
        f"--wordlist {shlex.quote(wordlist)} "
        f"--extensions {shlex.quote(extensions)} "
        f"--depth {depth} "
        f"--no-state --no-recursion-limit --silent "
        f"--timeout 10 -k 2>/dev/null "
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

    discovered = _parse_feroxbuster(raw["stdout"])
    artifact = _save_artifact(
        machine, "dirfuzz",
        f"{target}_{port}.txt",
        raw["stdout"],
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
    }
