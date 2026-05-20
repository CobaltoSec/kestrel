"""MCP tools — Kali VM health + target reachability.

These wrap simple Kali-side commands via SSH for connectivity checks before
running heavier recon/exploit tools.
"""

from __future__ import annotations

import asyncio
import shlex
from typing import Any

from kestrel.mcp import registry
from kestrel.transport import kali_proxy


async def _run_kali(cmd: str, timeout: float = 30.0) -> dict[str, Any]:
    res = await asyncio.to_thread(kali_proxy.via_kali, cmd, timeout)
    return {
        "cmd": cmd,
        "rc": res.rc,
        "stdout": res.stdout.strip(),
        "stderr": res.stderr.strip(),
        "duration_s": res.duration_s,
    }


@registry.tool(
    name="kali_status",
    description=(
        "Check Kali VM SSH reachability + return hostname/uname/whoami/uptime. "
        "Use before running any other tool that requires Kali."
    ),
    category="kali",
)
async def kali_status() -> dict[str, Any]:
    cmd = "hostname; whoami; uname -a; uptime"
    return await _run_kali(cmd, timeout=10.0)


@registry.tool(
    name="kali_ping_target",
    description=(
        "Send 3 ICMP echo requests from Kali to target_ip. Returns rc 0 if reachable. "
        "Useful right after vpn_up to confirm HTB target is up."
    ),
    category="kali",
)
async def kali_ping_target(target_ip: str) -> dict[str, Any]:
    cmd = f"ping -c 3 -W 2 {shlex.quote(target_ip)}"
    res = await _run_kali(cmd, timeout=15.0)
    res["reachable"] = res["rc"] == 0
    return res
