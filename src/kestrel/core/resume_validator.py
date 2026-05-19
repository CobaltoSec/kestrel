#!/usr/bin/env python3
"""
Kestrel resume_validator — L4 Memory Layer cross-session health check.

Run on your Kali VM (or via an injected runner in v0.4+) to validate session
state before resuming.

v0.4 split:
    - Functions accept an optional `runner: Callable[[str], tuple[str, int]]`
      that executes a shell command and returns (stdout, exit_code).
    - Default runner: subprocess.run on the local box (identical behavior to
      the legacy script when invoked on Kali).
    - Fase 4 will inject an SSHSession runner so the same code works from a
      Windows control node talking to Kali.

Inputs (environment variables, legacy CLI flow):
  MACHINE_IP      — last known HTB machine IP (e.g. 10.10.10.x)
  LISTENERS_JSON  — JSON array of registered listeners, e.g.:
                    '[{"pid":1234,"port":9001,"type":"nc","cmd":"nc -lvnp 9001"}]'

Output: JSON to stdout
  {
    "vpn_up": true,
    "machine_reachable": false,
    "machine_ip": "10.10.10.x",
    "listeners_alive": [{"port": 9001, "pid": 1234, "type": "nc", "alive": false}],
    "needs_recovery": true,
    "recovery_actions": ["respawn_machine", "restart_listener_9001"]
  }

Usage (legacy):
  MACHINE_IP=10.10.10.x \\
  LISTENERS_JSON='[{"pid":1234,"port":9001,"type":"nc","cmd":"nc -lvnp 9001"}]' \\
  python -m kestrel.core.resume_validator
"""

from __future__ import annotations

import json
import os
import subprocess
from typing import Callable, Optional, Tuple

# Type alias: runner takes a shell command string and returns (stdout, exit_code).
Runner = Callable[[str], Tuple[str, int]]


def _default_runner(cmd: str, timeout: int = 10) -> Tuple[str, int]:
    """Local subprocess runner — identical behavior to the legacy script."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True, timeout=timeout
        )
        return result.stdout or "", result.returncode
    except subprocess.TimeoutExpired:
        return "", 124
    except Exception:
        return "", 1


def check_vpn(runner: Optional[Runner] = None) -> bool:
    """Return True if tun0 is up with a 10.x address.

    When `runner` is None, uses local subprocess (same as legacy).
    """
    if runner is None:
        # Use the structured path to keep parity with original logic
        try:
            result = subprocess.run(
                ["ip", "-j", "addr", "show", "tun0"],
                capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                return False
            data = json.loads(result.stdout)
            for iface in data:
                for addr in iface.get("addr_info", []):
                    if addr.get("local", "").startswith("10."):
                        return True
            return False
        except Exception:
            return False

    # Injected runner path — use shell form so SSH/Windows runners can reuse.
    out, code = runner("ip -j addr show tun0")
    if code != 0:
        return False
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return False
    for iface in data:
        for addr in iface.get("addr_info", []):
            if addr.get("local", "").startswith("10."):
                return True
    return False


def check_machine(ip: str, runner: Optional[Runner] = None) -> bool:
    """Return True if the machine responds to ping."""
    if not ip:
        return False
    if runner is None:
        try:
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "2", ip],
                capture_output=True, timeout=10,
            )
            return result.returncode == 0
        except Exception:
            return False

    _, code = runner(f"ping -c 1 -W 2 {ip}")
    return code == 0


def check_listener(pid: int, port: int, runner: Optional[Runner] = None) -> bool:
    """Return True if listener is alive (by PID first, then by port)."""
    if runner is None:
        if pid:
            try:
                os.kill(pid, 0)
                return True
            except (ProcessLookupError, PermissionError):
                pass
        if port:
            try:
                result = subprocess.run(
                    ["ss", "-tlnp", f"sport = :{port}"],
                    capture_output=True, text=True, timeout=5,
                )
                return f":{port}" in result.stdout
            except Exception:
                pass
        return False

    # Runner path — both checks via shell since os.kill is local-only.
    if pid:
        _, code = runner(f"kill -0 {pid} 2>/dev/null && echo OK")
        if code == 0:
            return True
    if port:
        out, _ = runner(f"ss -tlnp 'sport = :{port}'")
        if f":{port}" in out:
            return True
    return False


def main() -> None:
    machine_ip = os.environ.get("MACHINE_IP", "")
    listeners_raw = os.environ.get("LISTENERS_JSON", "[]")

    try:
        listeners = json.loads(listeners_raw)
        if not isinstance(listeners, list):
            listeners = []
    except json.JSONDecodeError:
        listeners = []

    vpn_up = check_vpn()
    machine_reachable = check_machine(machine_ip) if vpn_up else False

    listeners_alive = []
    for lst in listeners:
        port = int(lst.get("port") or 0)
        pid = int(lst.get("pid") or 0)
        alive = check_listener(pid, port)
        listeners_alive.append({
            "port": port,
            "pid": pid,
            "type": lst.get("type", ""),
            "alive": alive,
        })

    recovery_actions = []
    if not vpn_up:
        recovery_actions.append("revpn")
    if not machine_reachable:
        recovery_actions.append("respawn_machine")
    for lst in listeners_alive:
        if not lst["alive"]:
            recovery_actions.append(f"restart_listener_{lst['port']}")

    output = {
        "vpn_up": vpn_up,
        "machine_reachable": machine_reachable,
        "machine_ip": machine_ip,
        "listeners_alive": listeners_alive,
        "needs_recovery": len(recovery_actions) > 0,
        "recovery_actions": recovery_actions,
    }
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
