"""MCP tools — reconnaissance primitives (nmap, web/smb/dns/ldap enum).

All tools execute on the Kali VM via SSH. Heavy outputs (nmap XML, smbclient
listings) are saved to ``<session_dir>/recon/`` when a ``machine`` is given,
and the parsed summary is returned in the response.
"""

from __future__ import annotations

import asyncio
import shlex
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from kestrel.mcp import registry
from kestrel.mcp.tools.state import _resolve_session_dir
from kestrel.transport import kali_proxy


NMAP_PROFILES: dict[str, str] = {
    "quick": "-sS -T4 --top-ports=1000 -oX -",
    "full": "-sS -T4 -p- -sV -sC --max-retries=1 -oX -",
    "udp": "-sU -T4 --top-ports=200 -oX -",
    "nse_smb": "-p139,445 -sS --script=smb-enum-shares,smb-enum-users,smb-vuln-* -oX -",
}


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


# ── Tools ────────────────────────────────────────────────────────────────────


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
        base = base.replace("--top-ports=1000", "").replace("--top-ports=200", "").replace("-p139,445", "")
        cmd = f"nmap {base.strip()} -p {shlex.quote(ports)} {shlex.quote(target)}"
    else:
        cmd = f"nmap {base} {shlex.quote(target)}"
    raw = await _run_kali(cmd, timeout=900.0)
    parsed = _parse_nmap_xml(raw["stdout"])
    artifact = _save_artifact(machine, "nmap", f"{target.replace(':', '_').replace('/', '_')}-{profile}.xml", raw["stdout"])
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
    for line in headers.splitlines():
        line = line.strip()
        if line.startswith("HTTP/"):
            fp["status_line"] = line
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
