"""MCP tools — flag operations (extract from session, validate format)."""

from __future__ import annotations

import asyncio
import re
import shlex
from typing import Any

from kestrel.mcp import registry
from kestrel.transport import kali_proxy


HTB_FLAG_RE = re.compile(r"^[0-9a-f]{32}$", re.IGNORECASE)


async def _run_kali(cmd: str, timeout: float = 60.0) -> dict[str, Any]:
    res = await asyncio.to_thread(kali_proxy.via_kali, cmd, timeout)
    return {"cmd": cmd, "rc": res.rc, "stdout": res.stdout.strip(), "stderr": res.stderr.strip(), "duration_s": res.duration_s}


@registry.tool(
    name="flag_extract",
    description=(
        "Extract user.txt + root.txt (Linux) or user.txt + admin.txt (Windows) via the given exec template. "
        "Returns dict {user_flag, root_flag, raw_outputs}. Pass exec_cmd_template with `{}` placeholder for the inner cmd."
    ),
    category="flag",
)
async def flag_extract(exec_cmd_template: str, os: str = "linux") -> dict[str, Any]:
    if os.lower().startswith("win"):
        # On Windows machines, flags live in C:\Users\<user>\Desktop\user.txt and C:\Users\Administrator\Desktop\root.txt
        user_cmd = "type C:\\Users\\*\\Desktop\\user.txt 2>nul"
        root_cmd = "type C:\\Users\\Administrator\\Desktop\\root.txt 2>nul"
    else:
        user_cmd = "cat /home/*/user.txt 2>/dev/null"
        root_cmd = "cat /root/root.txt 2>/dev/null"

    def build(inner: str) -> str:
        if "{}" in exec_cmd_template:
            return exec_cmd_template.replace("{}", inner)
        return f"{exec_cmd_template} {shlex.quote(inner)}"

    user_res = await _run_kali(build(user_cmd), timeout=30.0)
    root_res = await _run_kali(build(root_cmd), timeout=30.0)

    def _flag_from(stdout: str) -> str | None:
        for line in stdout.strip().splitlines():
            line = line.strip()
            if HTB_FLAG_RE.match(line):
                return line.lower()
        return None

    return {
        "user_flag": _flag_from(user_res["stdout"]),
        "root_flag": _flag_from(root_res["stdout"]),
        "raw_user_stdout": user_res["stdout"],
        "raw_root_stdout": root_res["stdout"],
    }


@registry.tool(
    name="flag_validate",
    description="Validate an HTB flag format (32 hex characters). Returns {valid: bool, normalized: str|None, reason?}.",
    category="flag",
)
async def flag_validate(flag: str) -> dict[str, Any]:
    cleaned = flag.strip().strip('"').strip("'")
    if HTB_FLAG_RE.match(cleaned):
        return {"valid": True, "normalized": cleaned.lower()}
    return {"valid": False, "normalized": None, "reason": "must be 32 hex chars"}
