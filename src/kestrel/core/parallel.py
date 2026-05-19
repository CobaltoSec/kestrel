#!/usr/bin/env python3
"""
Kestrel parallel_explorer — run N exploration tasks in parallel against Kali.

Designed for the cases where Kestrel needs to cover several vectors at once
instead of serially:
    * WinRM spray + SMB enum + endpoint fuzz concurrently
    * Multiple SQLi vectors against different endpoints
    * Async crack running + endpoint enum on the same host

Each task spec:
    {"id": "winrm-spray", "cmd": "netexec winrm <IP> -u users -p passwords", "timeout": 300}

Tasks run via SSH to Kali, capped at --max-workers (default 4). Stdout/stderr
tails (last 4KB) are captured into a consolidated JSON output. The script never
parses or interprets the output — that's the caller's job.

`--dry-run` substitutes `bash -c "<cmd>"` for the SSH wrapper, so the same
module is testable in CI without a Kali to talk to.

Usage (legacy CLI):
    python -m kestrel.core.parallel \\
        --tasks-json '{"tasks":[...]}' \\
        --kali-ssh ~/.ssh/kali-pentest \\
        --kali-host 192.168.1.10 \\
        --output results.json
"""
import argparse
import concurrent.futures
import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

MAX_TAIL_BYTES = 4096
DEFAULT_MAX_WORKERS = 4


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def tail(text: str | None, n: int = MAX_TAIL_BYTES) -> str:
    if not text:
        return ""
    if len(text) <= n:
        return text
    return "...[truncated " + str(len(text) - n) + " bytes]...\n" + text[-n:]


def build_command(task: dict, kali_ssh: str, kali_host: str, dry_run: bool) -> list[str]:
    cmd = task["cmd"]
    if dry_run:
        # Run locally — for testing without Kali
        return ["bash", "-c", cmd]
    return [
        "ssh",
        "-i", kali_ssh,
        "-o", "StrictHostKeyChecking=no",
        "-o", "BatchMode=yes",
        "-o", "ConnectTimeout=10",
        f"kali@{kali_host}",
        cmd,
    ]


def run_task(task: dict, kali_ssh: str, kali_host: str, dry_run: bool) -> dict:
    task_id = task.get("id") or f"task-{int(time.time() * 1000)}"
    timeout = int(task.get("timeout", 300))
    cmd = build_command(task, kali_ssh, kali_host, dry_run)

    started = time.time()
    started_iso = iso_now()

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        elapsed = time.time() - started
        if proc.returncode == 0:
            status = "success"
        else:
            status = "failed"
        return {
            "id":         task_id,
            "status":     status,
            "exit_code":  proc.returncode,
            "elapsed_s":  round(elapsed, 2),
            "started_at": started_iso,
            "ended_at":   iso_now(),
            "stdout":     tail(proc.stdout),
            "stderr":     tail(proc.stderr),
            "cmd_summary": task["cmd"][:200],
        }
    except subprocess.TimeoutExpired as exc:
        elapsed = time.time() - started
        return {
            "id":         task_id,
            "status":     "timeout",
            "exit_code":  None,
            "elapsed_s":  round(elapsed, 2),
            "started_at": started_iso,
            "ended_at":   iso_now(),
            "stdout":     tail(getattr(exc, "stdout", "") or ""),
            "stderr":     tail(getattr(exc, "stderr", "") or "") + f"\n[Timeout {timeout}s exceeded]",
            "cmd_summary": task["cmd"][:200],
        }
    except FileNotFoundError as exc:
        elapsed = time.time() - started
        return {
            "id":         task_id,
            "status":     "error",
            "exit_code":  None,
            "elapsed_s":  round(elapsed, 2),
            "started_at": started_iso,
            "ended_at":   iso_now(),
            "stdout":     "",
            "stderr":     f"command not found: {exc}",
            "cmd_summary": task["cmd"][:200],
        }


def run_all(tasks: list[dict], kali_ssh: str, kali_host: str,
            max_workers: int, dry_run: bool) -> dict:
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(run_task, t, kali_ssh, kali_host, dry_run): t.get("id", f"task-{i}")
            for i, t in enumerate(tasks)
        }
        for fut in concurrent.futures.as_completed(futures):
            results.append(fut.result())

    # Preserve input order for caller convenience
    order = {t.get("id", f"task-{i}"): i for i, t in enumerate(tasks)}
    results.sort(key=lambda r: order.get(r["id"], 999))

    summary = {
        "total":   len(results),
        "success": sum(1 for r in results if r["status"] == "success"),
        "failed":  sum(1 for r in results if r["status"] == "failed"),
        "timeout": sum(1 for r in results if r["status"] == "timeout"),
        "error":   sum(1 for r in results if r["status"] == "error"),
    }
    return {
        "ran_at":  iso_now(),
        "dry_run": dry_run,
        "summary": summary,
        "tasks":   results,
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--tasks-json", help="Inline JSON: {\"tasks\":[{...},{...}]}")
    grp.add_argument("--tasks-file", type=Path, help="Path to JSON file with tasks")
    ap.add_argument("--kali-ssh",  default="", help="SSH key path (ignored with --dry-run)")
    ap.add_argument("--kali-host", default="", help="Kali host (ignored with --dry-run)")
    ap.add_argument("--max-workers", type=int, default=DEFAULT_MAX_WORKERS)
    ap.add_argument("--dry-run", action="store_true",
                    help="Run commands locally via bash -c instead of SSH")
    ap.add_argument("--output", type=Path, default=None)
    args = ap.parse_args()

    if args.tasks_json:
        spec = json.loads(args.tasks_json)
    else:
        spec = json.loads(args.tasks_file.read_text())

    tasks = spec.get("tasks", [])
    if not isinstance(tasks, list) or not tasks:
        print(json.dumps({"error": "tasks must be a non-empty list"}), file=sys.stderr)
        sys.exit(2)

    if not args.dry_run and (not args.kali_ssh or not args.kali_host):
        print(json.dumps({"error": "--kali-ssh and --kali-host required unless --dry-run"}),
              file=sys.stderr)
        sys.exit(2)

    result = run_all(tasks, args.kali_ssh, args.kali_host,
                     args.max_workers, args.dry_run)
    out_json = json.dumps(result, indent=2)
    print(out_json)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(out_json)

    # Exit 0 if all success, 1 if any failed/timeout, 2 on error
    if result["summary"]["error"] > 0:
        sys.exit(2)
    if result["summary"]["failed"] > 0 or result["summary"]["timeout"] > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
