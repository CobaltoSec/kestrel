"""
Tests for parallel_explorer.py — concurrent task orchestration.

All tests use --dry-run so they run on the CI runner without a Kali to SSH into.
"""
import json
import subprocess
import sys
import time
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / "scripts" / "parallel_explorer.py"

# On Windows the runner can't execute "bash" the same way; skip these tests
# in CI Windows. CI runs on ubuntu-latest so this only kicks in for local dev.
WINDOWS_SKIP = pytest.mark.skipif(
    sys.platform.startswith("win"),
    reason="parallel_explorer dry-run uses bash; Windows path is via Git Bash only",
)


def run(tasks: list[dict], *, max_workers: int = 4) -> tuple[int, dict]:
    spec = json.dumps({"tasks": tasks})
    r = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--tasks-json", spec,
         "--dry-run",
         "--max-workers", str(max_workers)],
        capture_output=True, text=True, timeout=30,
    )
    return r.returncode, json.loads(r.stdout)


@WINDOWS_SKIP
def test_single_success_task():
    code, out = run([{"id": "echo-hello", "cmd": "echo hello", "timeout": 5}])
    assert code == 0, out
    assert out["summary"]["total"] == 1
    assert out["summary"]["success"] == 1
    assert "hello" in out["tasks"][0]["stdout"]


@WINDOWS_SKIP
def test_multiple_tasks_run_in_parallel():
    """3 tasks of ~1s each should finish in <2s when max_workers=4."""
    start = time.time()
    code, out = run(
        [
            {"id": "t1", "cmd": "sleep 1 && echo t1", "timeout": 5},
            {"id": "t2", "cmd": "sleep 1 && echo t2", "timeout": 5},
            {"id": "t3", "cmd": "sleep 1 && echo t3", "timeout": 5},
        ],
        max_workers=4,
    )
    elapsed = time.time() - start
    assert code == 0
    assert out["summary"]["success"] == 3
    assert elapsed < 2.5, f"Expected parallel execution (<2.5s), got {elapsed:.2f}s"


@WINDOWS_SKIP
def test_failed_task_marks_failed_status():
    code, out = run([{"id": "fail", "cmd": "exit 7", "timeout": 5}])
    assert code == 1  # at least one failed
    assert out["tasks"][0]["status"] == "failed"
    assert out["tasks"][0]["exit_code"] == 7


@WINDOWS_SKIP
def test_timeout_task():
    code, out = run([{"id": "stuck", "cmd": "sleep 10", "timeout": 1}])
    assert code == 1
    assert out["tasks"][0]["status"] == "timeout"
    assert "Timeout" in out["tasks"][0]["stderr"]


@WINDOWS_SKIP
def test_mix_of_outcomes():
    code, out = run([
        {"id": "ok",      "cmd": "echo ok",  "timeout": 3},
        {"id": "fail",    "cmd": "exit 1",   "timeout": 3},
        {"id": "timeout", "cmd": "sleep 10", "timeout": 1},
    ])
    assert code == 1
    assert out["summary"]["success"] == 1
    assert out["summary"]["failed"] == 1
    assert out["summary"]["timeout"] == 1


@WINDOWS_SKIP
def test_order_preserved_in_output():
    code, out = run([
        {"id": "alpha", "cmd": "sleep 0.5 && echo a", "timeout": 3},
        {"id": "beta",  "cmd": "echo b",              "timeout": 3},
        {"id": "gamma", "cmd": "sleep 0.2 && echo c", "timeout": 3},
    ])
    assert [t["id"] for t in out["tasks"]] == ["alpha", "beta", "gamma"]


@WINDOWS_SKIP
def test_max_workers_serializes_when_set_to_one():
    """3 tasks of ~0.5s with max_workers=1 should take >=1.5s (serial)."""
    start = time.time()
    code, out = run(
        [
            {"id": "s1", "cmd": "sleep 0.5", "timeout": 5},
            {"id": "s2", "cmd": "sleep 0.5", "timeout": 5},
            {"id": "s3", "cmd": "sleep 0.5", "timeout": 5},
        ],
        max_workers=1,
    )
    elapsed = time.time() - start
    assert code == 0
    assert elapsed >= 1.4, f"Expected serial execution (>=1.4s), got {elapsed:.2f}s"


def test_rejects_empty_tasks_list():
    r = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--tasks-json", '{"tasks":[]}', "--dry-run"],
        capture_output=True, text=True, timeout=5,
    )
    assert r.returncode == 2


def test_requires_ssh_args_without_dry_run():
    r = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--tasks-json", '{"tasks":[{"id":"x","cmd":"echo","timeout":3}]}'],
        capture_output=True, text=True, timeout=5,
    )
    assert r.returncode == 2
    assert "kali-ssh" in r.stderr or "kali-host" in r.stderr


def test_tasks_from_file(tmp_path: Path):
    spec = {"tasks": [{"id": "ok", "cmd": "echo from-file", "timeout": 3}]}
    f = tmp_path / "tasks.json"
    f.write_text(json.dumps(spec))
    if sys.platform.startswith("win"):
        pytest.skip("bash dry-run on Windows only via Git Bash")
    r = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--tasks-file", str(f), "--dry-run"],
        capture_output=True, text=True, timeout=10,
    )
    assert r.returncode == 0
    out = json.loads(r.stdout)
    assert out["summary"]["success"] == 1
