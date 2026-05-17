"""
Tests for crack_status.py — async hash-crack job polling.
"""
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path


SCRIPT = Path(__file__).parent.parent / "scripts" / "crack_status.py"


def make_state(jobs_dir: Path, job_id: str, *, created_offset_h: float = 0.0,
               timeout_hours: int = 4) -> Path:
    created_ts = (datetime.now(timezone.utc) - timedelta(hours=created_offset_h)
                  ).strftime("%Y-%m-%dT%H:%M:%SZ")
    state = {
        "job_id":     job_id,
        "status":     "pending_upload",
        "slug":       "engagement-abcd1234.txt",
        "hash_sig":   "abcd1234",
        "hash_mode":  "3200",
        "hash_label": "bcrypt",
        "wordlist":   "rockyou",
        "target":     "colab",
        "staged_path": "/tmp/staged",
        "expected_result_file": str(jobs_dir / f"{job_id}.result.json"),
        "created_ts": created_ts,
        "timeout_hours": timeout_hours,
    }
    state_file = jobs_dir / f"{job_id}.json"
    state_file.write_text(json.dumps(state, indent=2))
    return state_file


def make_result(jobs_dir: Path, job_id: str, *, status: str,
                password: str | None = None, elapsed_s: int = 300):
    result = {
        "job_id": job_id,
        "status": status,
        "password": password,
        "elapsed_s": elapsed_s,
        "completed_ts": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    (jobs_dir / f"{job_id}.result.json").write_text(json.dumps(result, indent=2))


def run(jobs_dir: Path, job_id: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT),
         "--job-id", job_id,
         "--jobs-dir", str(jobs_dir)],
        capture_output=True, text=True, timeout=10,
    )


def test_pending_upload_within_timeout(tmp_path: Path):
    make_state(tmp_path, "job1", created_offset_h=0.5)
    r = run(tmp_path, "job1")
    assert r.returncode == 2, r.stderr
    out = json.loads(r.stdout)
    assert out["status"] == "pending_upload"
    assert out["job_id"] == "job1"
    assert out["elapsed_hours"] >= 0.4


def test_expired_after_timeout(tmp_path: Path):
    make_state(tmp_path, "job2", created_offset_h=5.0, timeout_hours=4)
    r = run(tmp_path, "job2")
    assert r.returncode == 3
    out = json.loads(r.stdout)
    assert out["status"] == "expired"


def test_complete_with_password(tmp_path: Path):
    make_state(tmp_path, "job3", created_offset_h=0.5)
    make_result(tmp_path, "job3", status="complete",
                password="wonderful1", elapsed_s=180)
    r = run(tmp_path, "job3")
    assert r.returncode == 0
    out = json.loads(r.stdout)
    assert out["status"] == "complete"
    assert out["password"] == "wonderful1"
    assert out["elapsed_s"] == 180
    assert out["hash_label"] == "bcrypt"


def test_no_match(tmp_path: Path):
    make_state(tmp_path, "job4", created_offset_h=0.5)
    make_result(tmp_path, "job4", status="no_match", password=None, elapsed_s=3600)
    r = run(tmp_path, "job4")
    assert r.returncode == 1
    out = json.loads(r.stdout)
    assert out["status"] == "no_match"
    assert out["wordlist"] == "rockyou"


def test_missing_state_file(tmp_path: Path):
    r = run(tmp_path, "nonexistent")
    assert r.returncode == 4
    out = json.loads(r.stdout)
    assert out["status"] == "error"
    assert "missing" in out["detail"]


def test_malformed_state_file(tmp_path: Path):
    (tmp_path / "bad.json").write_text("{not valid json")
    r = run(tmp_path, "bad")
    assert r.returncode == 4
    out = json.loads(r.stdout)
    assert out["status"] == "error"


def test_unexpected_result_status(tmp_path: Path):
    make_state(tmp_path, "job5", created_offset_h=0.5)
    # Write a result with an unknown status value
    (tmp_path / "job5.result.json").write_text(json.dumps({
        "job_id": "job5", "status": "weird_state", "password": None, "elapsed_s": 100,
    }))
    r = run(tmp_path, "job5")
    assert r.returncode == 4
    out = json.loads(r.stdout)
    assert out["status"] == "error"


def test_polled_at_timestamp_present(tmp_path: Path):
    make_state(tmp_path, "job6", created_offset_h=0.5)
    r = run(tmp_path, "job6")
    out = json.loads(r.stdout)
    assert "polled_at" in out
    # ISO 8601 UTC suffix
    assert out["polled_at"].endswith("Z")
