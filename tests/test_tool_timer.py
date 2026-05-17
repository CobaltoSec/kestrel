"""Tests for tool-timer.sh — stamps tool_start/tool_end in sessions.jsonl.

NOTE: tool-timer.sh is a bash script targeting Linux/Kali environments.
Tests that invoke it are skipped on Windows (bash path handling incompatible).
The --missing-args tests exercise bash error paths and still run on all platforms.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "tool-timer.sh"
POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="bash script, POSIX only")


def run_timer(session_dir: Path, tool: str, *cmd: str, timeout: int = 10):
    return subprocess.run(
        ["bash", str(SCRIPT),
         "--session-dir", str(session_dir),
         "--tool", tool,
         "--", *cmd],
        capture_output=True, text=True, timeout=timeout,
    )


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@POSIX_ONLY
def test_basic_stamps(tmp_path: Path):
    """Successful command → tool_start + tool_end with duration_s ≥ 1."""
    r = run_timer(tmp_path / "session", "sleep", "sleep", "1")
    assert r.returncode == 0
    events = read_jsonl(tmp_path / "session" / "sessions.jsonl")
    assert len(events) == 2
    start, end = events
    assert start["event"] == "tool_start"
    assert start["detail"] == "sleep"
    assert end["event"] == "tool_end"
    assert end["detail"] == "sleep"
    assert end["duration_s"] >= 1
    assert end["exit_code"] == 0


@POSIX_ONLY
def test_failed_command_exit_code(tmp_path: Path):
    """Non-zero exit → tool_end records exit_code; script mirrors it."""
    r = run_timer(tmp_path / "session", "fail42", "bash", "-c", "exit 42")
    assert r.returncode == 42
    events = read_jsonl(tmp_path / "session" / "sessions.jsonl")
    end = next(e for e in events if e["event"] == "tool_end")
    assert end["exit_code"] == 42
    assert "duration_s" in end


@POSIX_ONLY
def test_stdout_forwarded(tmp_path: Path):
    """Wrapped command stdout is forwarded unchanged."""
    r = run_timer(tmp_path / "session", "echo", "echo", "hello-kestrel")
    assert "hello-kestrel" in r.stdout


@POSIX_ONLY
def test_stderr_forwarded(tmp_path: Path):
    """Wrapped command stderr is forwarded unchanged."""
    r = run_timer(tmp_path / "session", "stderr", "bash", "-c", "echo warn-msg >&2")
    assert "warn-msg" in r.stderr


@POSIX_ONLY
def test_creates_session_dir(tmp_path: Path):
    """Script creates SESSION_DIR if it doesn't exist."""
    nested = tmp_path / "a" / "b" / "c"
    run_timer(nested, "noop", "true")
    assert (nested / "sessions.jsonl").exists()


@POSIX_ONLY
def test_appends_across_invocations(tmp_path: Path):
    """Multiple runs append to the same sessions.jsonl."""
    session = tmp_path / "session"
    run_timer(session, "first",  "true")
    run_timer(session, "second", "true")
    events = read_jsonl(session / "sessions.jsonl")
    assert len(events) == 4  # 2× (start + end)
    details = [e["detail"] for e in events]
    assert details.count("first") == 2
    assert details.count("second") == 2


def test_missing_args_nonzero(tmp_path: Path):
    """Missing --tool or cmd → non-zero exit."""
    r = subprocess.run(
        ["bash", str(SCRIPT), "--tool", "noop"],
        capture_output=True, text=True, timeout=5,
    )
    assert r.returncode != 0


def test_session_dir_flag_required(tmp_path: Path):
    """Missing --session-dir → non-zero exit."""
    r = subprocess.run(
        ["bash", str(SCRIPT), "--tool", "noop", "--", "true"],
        capture_output=True, text=True, timeout=5,
    )
    assert r.returncode != 0
