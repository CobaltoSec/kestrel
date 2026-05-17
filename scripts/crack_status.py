#!/usr/bin/env python3
"""
Kestrel crack_status.py — poll an async hash-crack job.

The async flow:
1. crack-helper.sh --async ... creates <jobs_dir>/<job_id>.json with status=pending_upload
2. User uploads slug file to Colab/Kaggle, runs notebook with appended cell-7 snippet
   that writes <job_id>.result.json to Google Drive
3. User downloads the result.json into <jobs_dir>/
4. crack_status.py reads both files and emits consolidated status

Status values returned by this script:
    pending_upload  – job created, no result file yet, within timeout window
    pending_crack   – result file exists but crack still running (rare; result is final once written)
    complete        – password was cracked successfully
    no_match        – wordlist exhausted, no password found
    expired         – timeout reached, no result; user must restart
    error           – malformed file or unexpected state

Exit codes mirror this:
    0 = complete  (cracked)
    1 = no_match  (exhausted)
    2 = pending_upload | pending_crack  (still waiting)
    3 = expired
    4 = error
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def iso_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def elapsed_hours(created_ts: str) -> float:
    delta = datetime.now(timezone.utc) - parse_iso(created_ts)
    return delta.total_seconds() / 3600.0


def load_state(jobs_dir: Path, job_id: str) -> dict:
    state_file = jobs_dir / f"{job_id}.json"
    if not state_file.exists():
        return {"_error": f"state file missing: {state_file}"}
    try:
        return json.loads(state_file.read_text())
    except json.JSONDecodeError as exc:
        return {"_error": f"malformed state JSON: {exc}"}


def load_result(jobs_dir: Path, job_id: str) -> dict | None:
    result_file = jobs_dir / f"{job_id}.result.json"
    if not result_file.exists():
        return None
    try:
        return json.loads(result_file.read_text())
    except json.JSONDecodeError as exc:
        return {"_error": f"malformed result JSON: {exc}"}


def compute_status(state: dict, result: dict | None) -> dict:
    if "_error" in state:
        return {"status": "error", "detail": state["_error"]}
    if result is not None and "_error" in result:
        return {"status": "error", "detail": result["_error"]}

    timeout_h = state.get("timeout_hours", 4)
    created = state.get("created_ts")
    if not created:
        return {"status": "error", "detail": "state missing created_ts"}

    age_h = elapsed_hours(created)

    if result is None:
        if age_h >= timeout_h:
            return {
                "status": "expired",
                "job_id": state.get("job_id"),
                "elapsed_hours": round(age_h, 2),
                "timeout_hours": timeout_h,
                "detail": "Job exceeded timeout without a result file. Restart or extend timeout.",
            }
        return {
            "status": "pending_upload",
            "job_id": state.get("job_id"),
            "elapsed_hours": round(age_h, 2),
            "timeout_hours": timeout_h,
            "expected_result_file": state.get("expected_result_file"),
            "detail": "Waiting for result.json — upload the slug file + run the notebook cell snippet.",
        }

    # Result present → terminal status from result
    rstatus = result.get("status")
    if rstatus == "complete":
        return {
            "status":     "complete",
            "job_id":     state.get("job_id"),
            "password":   result.get("password"),
            "elapsed_s":  result.get("elapsed_s"),
            "hash_label": state.get("hash_label"),
            "wordlist":   state.get("wordlist"),
            "detail":     "Password cracked successfully.",
        }
    if rstatus == "no_match":
        return {
            "status":     "no_match",
            "job_id":     state.get("job_id"),
            "elapsed_s":  result.get("elapsed_s"),
            "wordlist":   state.get("wordlist"),
            "detail":     "Wordlist exhausted without a match. Try alternate wordlist or escalate.",
        }
    return {
        "status": "error",
        "job_id": state.get("job_id"),
        "detail": f"Unexpected result status: {rstatus!r}",
    }


STATUS_EXIT_CODES = {
    "complete":       0,
    "no_match":       1,
    "pending_upload": 2,
    "pending_crack":  2,
    "expired":        3,
    "error":          4,
}


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--job-id",   required=True)
    ap.add_argument("--jobs-dir", required=True, type=Path)
    args = ap.parse_args()

    state = load_state(args.jobs_dir, args.job_id)
    result = load_result(args.jobs_dir, args.job_id)
    status = compute_status(state, result)
    status["polled_at"] = iso_now()
    print(json.dumps(status, indent=2))
    sys.exit(STATUS_EXIT_CODES.get(status["status"], 4))


if __name__ == "__main__":
    main()
