"""MCP tools — Kali VM lifecycle + health + target reachability.

These wrap simple Kali-side commands via SSH for connectivity checks before
running heavier recon/exploit tools, plus vmrun-based VM power management so
the framework can boot/halt Kali without manual intervention.
"""

from __future__ import annotations

import asyncio
import os
import shlex
import subprocess
import time
from typing import Any

from kestrel.mcp import registry
from kestrel.transport import kali_proxy

# ── VM defaults (override via env) ───────────────────────────────────────────
_VMRUN_DEFAULT = r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"
_VMX_DEFAULT = (
    r"C:\VMs\kali-pentest\kali-linux-2026.1-vmware-amd64.vmwarevm"
    r"\kali-linux-2026.1-vmware-amd64.vmx"
)


def _get_vmrun() -> str:
    return os.environ.get("KESTREL_VMRUN_PATH", _VMRUN_DEFAULT)


def _get_vmx() -> str:
    return os.environ.get("KESTREL_VMX_PATH", _VMX_DEFAULT)


def _vmrun_exec(args: list[str]) -> dict[str, Any]:
    """Run vmrun.exe on the Windows host and return rc/stdout/stderr."""
    vmrun = _get_vmrun()
    try:
        r = subprocess.run(
            [vmrun] + args,
            capture_output=True,
            text=True,
            timeout=30,
        )
        return {"rc": r.returncode, "stdout": r.stdout.strip(), "stderr": r.stderr.strip()}
    except FileNotFoundError:
        return {"rc": -1, "stdout": "", "stderr": f"vmrun not found: {vmrun}"}
    except subprocess.TimeoutExpired:
        return {"rc": -1, "stdout": "", "stderr": "vmrun timeout"}


async def _run_kali(cmd: str, timeout: float = 30.0) -> dict[str, Any]:
    res = await asyncio.to_thread(kali_proxy.via_kali, cmd, timeout)
    return {
        "cmd": cmd,
        "rc": res.rc,
        "stdout": res.stdout.strip(),
        "stderr": res.stderr.strip(),
        "duration_s": res.duration_s,
    }


# ── VM lifecycle ─────────────────────────────────────────────────────────────


@registry.tool(
    name="kali_vm_status",
    description=(
        "Check Kali VM power state via vmrun. Returns running:bool and current IP "
        "if the VM is on. Does NOT require SSH. Use before kali_vm_up to avoid double-boot."
    ),
    category="kali",
)
async def kali_vm_status() -> dict[str, Any]:
    vmx = _get_vmx()
    list_r = await asyncio.to_thread(_vmrun_exec, ["list"])
    running = vmx in list_r["stdout"]
    ip: str | None = None
    if running:
        ip_r = await asyncio.to_thread(_vmrun_exec, ["getGuestIPAddress", vmx])
        ip = ip_r["stdout"] if ip_r["rc"] == 0 else None
    return {"running": running, "ip": ip, "vmx": vmx}


@registry.tool(
    name="kali_vm_up",
    description=(
        "Boot the Kali VM via vmrun and wait until SSH is reachable (up to timeout_s). "
        "No-op if already running. Returns started:bool, reachable:bool, waited_s. "
        "Call this at the start of every session before kali_status."
    ),
    category="kali",
)
async def kali_vm_up(wait_ssh: bool = True, timeout_s: int = 120) -> dict[str, Any]:
    vmx = _get_vmx()
    list_r = await asyncio.to_thread(_vmrun_exec, ["list"])
    already = vmx in list_r["stdout"]

    if already:
        start_r: dict[str, Any] = {"rc": 0, "stdout": "already_running", "stderr": ""}
    else:
        start_r = await asyncio.to_thread(_vmrun_exec, ["start", vmx, "nogui"])

    if start_r["rc"] != 0:
        return {"started": False, "reachable": False, "waited_s": 0, **start_r}

    if not wait_ssh:
        return {"started": True, "reachable": None, "waited_s": 0, **start_r}

    # Reset stale session so the next via_kali reconnects fresh
    kali_proxy.close_default_session()

    deadline = time.monotonic() + timeout_s
    reachable = False
    waited_s = 0
    while time.monotonic() < deadline:
        res = await asyncio.to_thread(kali_proxy.via_kali, "echo ok", 5.0)
        if not res.infrastructure_error and res.rc == 0:
            reachable = True
            break
        await asyncio.sleep(5)
        waited_s += 5

    return {"started": True, "reachable": reachable, "waited_s": waited_s, **start_r}


@registry.tool(
    name="kali_vm_down",
    description=(
        "Gracefully shut down the Kali VM via vmrun stop soft. "
        "Closes the SSH session first to avoid dangling connections."
    ),
    category="kali",
)
async def kali_vm_down() -> dict[str, Any]:
    vmx = _get_vmx()
    kali_proxy.close_default_session()
    result = await asyncio.to_thread(_vmrun_exec, ["stop", vmx, "soft"])
    return {"stopped": result["rc"] == 0, **result}


# ── SSH health + reachability ─────────────────────────────────────────────────


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
