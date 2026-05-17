"""
Tests for state_inspector.py — querying cross-session state history.
"""
import json
import subprocess
import sys
from pathlib import Path


SCRIPT = Path(__file__).parent.parent / "scripts" / "state_inspector.py"
FIXTURE = Path(__file__).parent / "fixtures" / "state" / "last-cycle-with-history.json"


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(SCRIPT), "--state-file", str(FIXTURE), *args],
        capture_output=True, text=True, timeout=10,
    )


def test_summary_for_monitorsfour():
    r = run("--slug", "monitorsfour", "--cmd", "summary")
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["slug"] == "monitorsfour"
    assert out["tried_credentials"]["total"] == 4
    assert out["tried_credentials"]["success"] == 1
    assert out["tried_credentials"]["failed"] == 3
    assert out["tried_hashes"]["cracked"] == 1
    assert out["tried_hashes"]["no_match"] == 2
    assert out["tried_endpoints"]["interesting"] == 2


def test_list_hashes():
    r = run("--slug", "monitorsfour", "--cmd", "list-hashes")
    assert r.returncode == 0
    out = json.loads(r.stdout)
    assert len(out) == 3
    assert any(h["type"] == "bcrypt" for h in out)


def test_check_credential_tried_fail():
    """admin:wonderful1 against winrm IS already tried — exit 0."""
    r = run(
        "--slug", "monitorsfour", "--cmd", "check-credential",
        "--user", "admin", "--password", "wonderful1", "--service", "winrm",
    )
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["result"] == "auth_failed"


def test_check_credential_not_tried():
    """janderson:Spring2026 hasn't been tried — exit 1."""
    r = run(
        "--slug", "monitorsfour", "--cmd", "check-credential",
        "--user", "janderson", "--password", "Spring2026", "--service", "winrm",
    )
    assert r.returncode == 1
    out = json.loads(r.stdout)
    assert out == {"tried": False}


def test_check_hash_bcrypt_with_rockyou_no_match():
    """bcrypt admin against rockyou IS tried and didn't match — exit 0."""
    r = run(
        "--slug", "monitorsfour", "--cmd", "check-hash",
        "--hash-preview", "$2y$10$wqlo06C4...", "--wordlist", "rockyou",
    )
    assert r.returncode == 0
    out = json.loads(r.stdout)
    assert out["result"] == "no_match"


def test_check_hash_not_tried_with_different_wordlist():
    """Same bcrypt against SecLists isn't tried yet — exit 1."""
    r = run(
        "--slug", "monitorsfour", "--cmd", "check-hash",
        "--hash-preview", "$2y$10$wqlo06C4...", "--wordlist", "seclists-top10k",
    )
    assert r.returncode == 1


def test_check_hash_rules_filter():
    """MD5 was tried with best64 rules — query without rules also returns first match."""
    r = run(
        "--slug", "monitorsfour", "--cmd", "check-hash",
        "--hash-preview", "69196959c16b26ef00b77d82cf6eb169",
        "--wordlist", "rockyou", "--rules", "best64",
    )
    assert r.returncode == 0


def test_check_hash_rules_filter_negative():
    """MD5 was tried ONLY with best64 — query with 'dive' rules returns not tried."""
    r = run(
        "--slug", "monitorsfour", "--cmd", "check-hash",
        "--hash-preview", "69196959c16b26ef00b77d82cf6eb169",
        "--wordlist", "rockyou", "--rules", "dive",
    )
    assert r.returncode == 1


def test_check_endpoint_tried():
    r = run(
        "--slug", "monitorsfour", "--cmd", "check-endpoint",
        "--path", "/api/v1/users", "--vhost", "monitorsfour.htb",
    )
    assert r.returncode == 0
    out = json.loads(r.stdout)
    assert out["status"] == 200


def test_check_endpoint_not_tried():
    r = run(
        "--slug", "monitorsfour", "--cmd", "check-endpoint",
        "--path", "/forgot-password", "--vhost", "monitorsfour.htb",
    )
    assert r.returncode == 1


def test_unknown_slug():
    r = run("--slug", "doesnotexist", "--cmd", "summary")
    assert r.returncode == 2
    assert "not in state.data.machines" in r.stderr


def test_missing_state_file(tmp_path: Path):
    bogus = tmp_path / "nope.json"
    r = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--state-file", str(bogus),
         "--slug", "x", "--cmd", "summary"],
        capture_output=True, text=True, timeout=5,
    )
    assert r.returncode == 2


def test_machine_without_history_fields_returns_empty(tmp_path: Path):
    """A machine entry without v0.2 fields should produce zero counts (backward compat)."""
    minimal = {
        "data": {
            "machines": {
                "newmachine": {"machine_id": 1, "machine_os": "Linux"}
            }
        }
    }
    state_file = tmp_path / "minimal.json"
    state_file.write_text(json.dumps(minimal))
    r = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--state-file", str(state_file),
         "--slug", "newmachine", "--cmd", "summary"],
        capture_output=True, text=True, timeout=5,
    )
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout)
    assert out["tried_credentials"]["total"] == 0
    assert out["tried_hashes"]["total"] == 0
    assert out["tried_endpoints"]["total"] == 0
