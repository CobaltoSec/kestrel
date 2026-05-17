#!/usr/bin/env python3
"""
Kestrel resume_validator — L4 Memory Layer cross-session health check.
Run on your Kali VM to validate session state before resuming.

Inputs (environment variables):
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

Usage:
  MACHINE_IP=10.10.10.x \\
  LISTENERS_JSON='[{"pid":1234,"port":9001,"type":"nc","cmd":"nc -lvnp 9001"}]' \\
  python3 resume_validator.py
"""

import json
import os
import subprocess


def check_vpn() -> bool:
    """Return True if tun0 is up with a 10.x address."""
    try:
        result = subprocess.run(
            ["ip", "-j", "addr", "show", "tun0"],
            capture_output=True, text=True, timeout=5
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


def check_machine(ip: str) -> bool:
    """Return True if the machine responds to ping."""
    if not ip:
        return False
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", "2", ip],
            capture_output=True, timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


def check_listener(pid: int, port: int) -> bool:
    """Return True if listener is alive (by PID first, then by port)."""
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
                capture_output=True, text=True, timeout=5
            )
            return f":{port}" in result.stdout
        except Exception:
            pass
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
