"""Tests for kestrel.core.timer — Python replacement for tool-timer.sh."""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import pytest

from kestrel.core.timer import _now_iso, run_with_timer, timer


def _read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_iso_format_utc():
    ts = _now_iso()
    assert re.match(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?\+\d{2}:\d{2}$", ts)


def test_timer_smoke_emits_two_events(tmp_path: Path):
    with timer(tmp_path, "smoke") as state:
        state["exit_code"] = 0

    events = _read_jsonl(tmp_path / "sessions.jsonl")
    assert len(events) == 2
    assert events[0]["event"] == "tool_start"
    assert events[0]["detail"] == "smoke"
    assert events[0]["phase"] == "tool-timer"
    assert events[1]["event"] == "tool_end"
    assert events[1]["detail"] == "smoke"
    assert events[1]["exit_code"] == 0
    assert events[1]["duration_s"] >= 0
    assert "ts" in events[0] and "ts" in events[1]


def test_timer_propagates_exit_code(tmp_path: Path):
    with timer(tmp_path, "tool-x") as state:
        state["exit_code"] = 42

    events = _read_jsonl(tmp_path / "sessions.jsonl")
    assert events[-1]["exit_code"] == 42


def test_timer_merges_extras(tmp_path: Path):
    with timer(tmp_path, "nmap") as state:
        state["exit_code"] = 0
        state["extra"] = {"target": "10.10.10.3", "ports_open": 14}

    end = _read_jsonl(tmp_path / "sessions.jsonl")[-1]
    assert end["target"] == "10.10.10.3"
    assert end["ports_open"] == 14
    # core fields must not be overridden
    assert end["event"] == "tool_end"
    assert end["detail"] == "nmap"


def test_timer_exception_still_emits_end_event(tmp_path: Path):
    with pytest.raises(RuntimeError, match="boom"):
        with timer(tmp_path, "tool-boom"):
            raise RuntimeError("boom")

    events = _read_jsonl(tmp_path / "sessions.jsonl")
    assert len(events) == 2
    end = events[-1]
    assert end["event"] == "tool_end"
    assert end["exception"] is True
    # default exit_code on uncaught exception becomes 1 (not 0)
    assert end["exit_code"] == 1


def test_timer_creates_parent_dir(tmp_path: Path):
    nested = tmp_path / "a" / "b" / "c"
    assert not nested.exists()
    with timer(nested, "init") as state:
        state["exit_code"] = 0
    assert (nested / "sessions.jsonl").exists()


def test_timer_duration_is_positive(tmp_path: Path):
    with timer(tmp_path, "slow") as state:
        time.sleep(0.05)
        state["exit_code"] = 0

    end = _read_jsonl(tmp_path / "sessions.jsonl")[-1]
    assert end["duration_s"] >= 0.04


def test_run_with_timer_returns_subprocess_rc(tmp_path: Path):
    # `python -c "exit(0)"` is portable to Windows + POSIX
    import sys

    rc = run_with_timer(tmp_path, "ok-cmd", [sys.executable, "-c", "exit(0)"])
    assert rc == 0
    end = _read_jsonl(tmp_path / "sessions.jsonl")[-1]
    assert end["exit_code"] == 0


def test_run_with_timer_propagates_failure(tmp_path: Path):
    import sys

    rc = run_with_timer(tmp_path, "fail-cmd", [sys.executable, "-c", "exit(7)"])
    assert rc == 7
    end = _read_jsonl(tmp_path / "sessions.jsonl")[-1]
    assert end["exit_code"] == 7


def test_run_with_timer_timeout(tmp_path: Path):
    import sys

    rc = run_with_timer(
        tmp_path,
        "slow-cmd",
        [sys.executable, "-c", "import time; time.sleep(5)"],
        timeout=0.5,
    )
    assert rc == 124
    end = _read_jsonl(tmp_path / "sessions.jsonl")[-1]
    assert end["exit_code"] == 124
    assert end.get("timeout_s") == 0.5
