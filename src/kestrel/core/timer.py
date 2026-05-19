#!/usr/bin/env python3
"""
Kestrel timer — Python replacement for legacy tool-timer.sh.

Provides a context manager that emits ``tool_start`` / ``tool_end`` events to
``<session_dir>/sessions.jsonl`` for telemetry. Replaces the bash wrapper which
could not be invoked from the MCP server cleanly.

Usage::

    from kestrel.core.timer import timer

    with timer(session_dir, "nmap-quick") as state:
        result = subprocess.run(["nmap", "-sV", target], capture_output=True)
        state["exit_code"] = result.returncode
        state["extra"] = {"target": target, "ports_open": 14}

The resulting ``sessions.jsonl`` lines::

    {"ts":"2026-05-19T12:00:00+00:00","phase":"tool-timer","event":"tool_start","detail":"nmap-quick"}
    {"ts":"2026-05-19T12:00:30+00:00","phase":"tool-timer","event":"tool_end","detail":"nmap-quick","duration_s":30.123,"exit_code":0,"target":"10.10.10.3","ports_open":14}

For CLI-style invocation (matching the old ``tool-timer.sh --session-dir X --tool Y -- <cmd...>`` interface)
use :func:`run_with_timer`.
"""

from __future__ import annotations

import json
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterator


def _now_iso() -> str:
    """ISO 8601 timestamp with UTC offset."""
    return datetime.now(timezone.utc).isoformat()


def _append_event(jsonl_path: Path, event: dict[str, Any]) -> None:
    jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    with jsonl_path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, ensure_ascii=False) + "\n")


@contextmanager
def timer(
    session_dir: Path | str,
    tool_name: str,
    phase: str = "tool-timer",
) -> Iterator[dict[str, Any]]:
    """Emit tool_start/tool_end events for the wrapped block.

    Yields a mutable dict the caller can populate with ``exit_code`` and optional
    ``extra`` key. The ``extra`` dict is merged into the ``tool_end`` event.

    Always emits ``tool_end`` even if an exception escapes the ``with`` block;
    the exit_code defaults to 1 if the caller did not set one and an exception
    bubbled up.
    """
    session_path = Path(session_dir)
    jsonl_path = session_path / "sessions.jsonl"
    state: dict[str, Any] = {"exit_code": 0, "extra": {}}
    started_mono = time.monotonic()
    _append_event(
        jsonl_path,
        {"ts": _now_iso(), "phase": phase, "event": "tool_start", "detail": tool_name},
    )
    exc_raised = False
    try:
        yield state
    except BaseException:
        exc_raised = True
        if state.get("exit_code", 0) == 0:
            state["exit_code"] = 1
        raise
    finally:
        duration = round(time.monotonic() - started_mono, 3)
        event: dict[str, Any] = {
            "ts": _now_iso(),
            "phase": phase,
            "event": "tool_end",
            "detail": tool_name,
            "duration_s": duration,
            "exit_code": state.get("exit_code", 0),
        }
        extra = state.get("extra") or {}
        if isinstance(extra, dict) and extra:
            for k, v in extra.items():
                if k not in event:
                    event[k] = v
        if exc_raised:
            event["exception"] = True
        _append_event(jsonl_path, event)


def run_with_timer(
    session_dir: Path | str,
    tool_name: str,
    argv: list[str],
    timeout: float | None = None,
    phase: str = "tool-timer",
) -> int:
    """Execute ``argv`` as a subprocess inside a :func:`timer` block.

    Returns the subprocess return code. The output is **not** captured — stdout
    and stderr pass through to the calling process. Useful as a replacement for
    the bash ``tool-timer.sh`` wrapper in shell pipelines.
    """
    with timer(session_dir, tool_name, phase=phase) as state:
        try:
            result = subprocess.run(argv, timeout=timeout)
            state["exit_code"] = result.returncode
            return result.returncode
        except subprocess.TimeoutExpired:
            state["exit_code"] = 124
            state["extra"] = {"timeout_s": timeout}
            return 124


def main(argv: list[str] | None = None) -> int:
    """CLI entry mirroring the old tool-timer.sh interface.

    Usage:
        python -m kestrel.core.timer --session-dir <dir> --tool <name> -- <cmd> [args...]
    """
    import argparse

    if argv is None:
        argv = sys.argv[1:]

    if "--" not in argv:
        print(
            "kestrel.core.timer: missing '--' separator before subprocess argv",
            file=sys.stderr,
        )
        return 2

    sep = argv.index("--")
    parser_args = argv[:sep]
    cmd_args = argv[sep + 1 :]

    parser = argparse.ArgumentParser(
        prog="kestrel.core.timer",
        description="Emit tool_start/tool_end JSONL events around a subprocess.",
    )
    parser.add_argument("--session-dir", required=True)
    parser.add_argument("--tool", required=True)
    parser.add_argument("--phase", default="tool-timer")
    parser.add_argument("--timeout", type=float, default=None)
    args = parser.parse_args(parser_args)

    if not cmd_args:
        print("kestrel.core.timer: no command provided after '--'", file=sys.stderr)
        return 2

    return run_with_timer(
        session_dir=args.session_dir,
        tool_name=args.tool,
        argv=cmd_args,
        timeout=args.timeout,
        phase=args.phase,
    )


if __name__ == "__main__":
    sys.exit(main())
