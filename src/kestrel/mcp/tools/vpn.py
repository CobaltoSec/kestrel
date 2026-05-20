"""MCP tools — HTB OpenVPN lifecycle via the Kali wrapper script.

Executes ``htb-vpn.sh {up|down|status}`` on the Kali VM via SSH. The wrapper
script path is configurable via env ``KESTREL_HTB_VPN_CMD`` (default:
``bash ~/htb-vpn.sh``).

State persistence: each call updates the active machine's ``vpn_iface_state``
field if a current_session is set.
"""

from __future__ import annotations

import asyncio
import os
import shlex
from typing import Any

from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry
from kestrel.transport import kali_proxy


def _vpn_cmd_base() -> str:
    return os.environ.get("KESTREL_HTB_VPN_CMD", "bash ~/htb-vpn.sh")


async def _run_kali(cmd: str, timeout: float = 60.0) -> dict[str, Any]:
    """Run a command on Kali and return a normalized dict."""
    res = await asyncio.to_thread(kali_proxy.via_kali, cmd, timeout)
    return {
        "cmd": cmd,
        "rc": res.rc,
        "stdout": res.stdout.strip(),
        "stderr": res.stderr.strip(),
        "duration_s": res.duration_s,
    }


def _patch_current_machine_vpn(state_iface: str) -> None:
    """Update vpn_iface_state on the machine pointed to by current_session, if any."""
    ctx = mcp_context.get_context()
    state = ctx.state_store.read()
    sess = state.data.current_session
    if not sess:
        return
    for slug, m in state.data.machines.items():
        if m.session_slug == sess:
            ctx.state_store.update_machine(slug, {"vpn_iface_state": state_iface})
            return


@registry.tool(
    name="vpn_up",
    description=(
        "Bring up the HTB OpenVPN connection on Kali. Optional `server` arg picks a region "
        "(e.g. 'eu-vip-1'). Returns rc + stdout/stderr from htb-vpn.sh."
    ),
    category="vpn",
)
async def vpn_up(server: str | None = None) -> dict[str, Any]:
    base = _vpn_cmd_base()
    cmd = f"{base} up {shlex.quote(server)}" if server else f"{base} up"
    res = await _run_kali(cmd, timeout=90.0)
    if res["rc"] == 0:
        _patch_current_machine_vpn("up")
    return res


@registry.tool(
    name="vpn_down",
    description="Tear down the HTB OpenVPN connection on Kali.",
    category="vpn",
)
async def vpn_down() -> dict[str, Any]:
    cmd = f"{_vpn_cmd_base()} down"
    res = await _run_kali(cmd, timeout=30.0)
    if res["rc"] == 0:
        _patch_current_machine_vpn("down")
    return res


@registry.tool(
    name="vpn_status",
    description="Check HTB OpenVPN status on Kali (interface state, IP, peer).",
    category="vpn",
)
async def vpn_status() -> dict[str, Any]:
    cmd = f"{_vpn_cmd_base()} status"
    return await _run_kali(cmd, timeout=10.0)
