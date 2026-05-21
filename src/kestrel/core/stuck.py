#!/usr/bin/env python3
"""
Kestrel stuck_detector — L3 → L2 stuck signal parser.

Reads engagement artifacts (estado.md / findings.md / sessions.jsonl) post
sub-paso and emits a structured JSON signal so Kestrel can decide whether to
replan the chain (switch vector, escalate to GPU, etc.). Does NOT modify the
artifacts — read-only.

Signals detected:
    shell_lost         – RCE/foothold artifact dead (connection reset, dead, etc.)
    hash_stuck         – hash policy triggered without resolution
    cred_exhausted     – >= 3 auth_failed without success in recent events
    progress_stalled   – no findings/state update in last STALL_MINUTES wall-clock

Recommendation values:
    switch_vector      – primary path stuck, try alternatives_from_findings
    escalate_gpu       – hash path stuck, go async crack
    reset_listener     – shell artifacts dead, re-foothold
    continue           – no stuck signals detected

Usage (legacy CLI):
    python -m kestrel.core.stuck \\
        --session-dir sectors/red-team/htb-sessions/htb-2026-05-08-monitorsfour \\
        --output stuck.json

Exit codes:
    0 = stuck=false
    1 = stuck=true (one or more signals)
    2 = error
"""
import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

STALL_MINUTES = 30
CRED_FAIL_THRESHOLD = 3
LAB_UNSTABLE_WINDOW_MINUTES = 10
LAB_UNSTABLE_THRESHOLD = 3   # >= N matches in window = lab_unstable signal

SHELL_LOST_PATTERNS = [
    r"shell\s+(?:dead|muerta|lost|died|caída|caida)",
    r"connection\s+reset",
    r"shell\s+se\s+cae",
    r"rce\s+(?:gone|murió|murio|broken)",
    r"reverse[_ ]shell\s+no\s+funciona",
    r"shell\s+expired",
]

HASH_STUCK_PATTERNS = [
    r"hash[_ ]policy[_ ]triggered",
    r"hash\s+no\s+rompe",
    r"no\s+match\s+in\s+\d+\s+min",
    r"bcrypt\s+timeout",
    r"hashcat\s+exhausted",
    r"sin\s+crackear",
    r"crackear\s+bcrypt",
    r"crackear\s+\w+\s+con\s+(?:gpu|colab|kaggle|wordlists)",
    r"\$2y\$10\$.{5,}.*(?:pendiente|sin\s+rompe|no\s+rompe)",
]

CRED_FAILED_KEYWORDS = (
    "auth_failed", "auth failed", "incorrect cred",
    "no creds work", "all creds fail", "spray exhausted",
    "ninguna cred", "ninguna credential", "no usable",
    "creds no funcionan", "creds rechazadas", "spray failed",
)

# v0.3 — Lab/VPN stability patterns (P3.1)
LAB_UNSTABLE_PATTERNS = [
    r"connection reset by peer",
    r"network is unreachable",
    r"no route to host",
    r"ssh.*timeout",
    r"ssh.*broken pipe",
    r"target machine refused",
    r"host unreachable",
    r"timed out",
    r"vpn.*down",
    r"tun0.*gone",
]


def parse_iso(ts: str) -> datetime | None:
    """Best-effort ISO8601 parse. Returns None on failure."""
    if not ts:
        return None
    try:
        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None


def read_file_safe(path: Path) -> str:
    if not path.exists():
        return ""
    try:
        return path.read_text(errors="ignore").lower()
    except OSError:
        return ""


def read_jsonl(path: Path) -> list[dict]:
    if not path.exists():
        return []
    entries = []
    for line in path.read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return entries


def detect_shell_lost(estado: str, findings: str) -> bool:
    blob = estado + "\n" + findings
    return any(re.search(p, blob) for p in SHELL_LOST_PATTERNS)


def detect_hash_stuck(estado: str, jsonl: list[dict]) -> bool:
    if any(re.search(p, estado) for p in HASH_STUCK_PATTERNS):
        return True
    triggered = [e for e in jsonl if "hash_policy" in e.get("event", "")]
    if not triggered:
        return False
    # If the latest hash_policy_triggered has no matching resolution event after it
    last = triggered[-1]
    last_ts = parse_iso(last.get("ts", ""))
    if not last_ts:
        return True
    later = [e for e in jsonl if (parse_iso(e.get("ts", "")) or datetime.min.replace(tzinfo=timezone.utc)) > last_ts]
    resolved_keywords = ("crack_complete", "password_found", "hash_cracked", "match")
    if any(kw in e.get("event", "") + e.get("detail", "") for e in later for kw in resolved_keywords):
        return False
    return True


def detect_cred_exhausted(estado: str, jsonl: list[dict]) -> bool:
    # Natural-language signals in estado.md (Spanish + English)
    natural_signal = any(kw in estado for kw in CRED_FAILED_KEYWORDS)
    if natural_signal:
        return True
    # Quantitative: >= N auth_failed events
    fails = sum(1 for e in jsonl
                if "auth_failed" in (e.get("event", "") + e.get("detail", "")).lower())
    return fails >= CRED_FAIL_THRESHOLD


def detect_progress_stalled(estado_path: Path, findings_path: Path,
                            jsonl_path: Path, now: datetime) -> bool:
    candidates = []
    for p in (estado_path, findings_path, jsonl_path):
        if p.exists():
            candidates.append(p.stat().st_mtime)
    if not candidates:
        return False
    latest = max(candidates)
    age_min = (now.timestamp() - latest) / 60
    return age_min >= STALL_MINUTES


def detect_lab_unstable(jsonl: list[dict], now: datetime) -> bool:
    """v0.3 P3.1 — ≥ LAB_UNSTABLE_THRESHOLD network error patterns in the last window."""
    cutoff = now.timestamp() - LAB_UNSTABLE_WINDOW_MINUTES * 60
    recent = [
        e for e in jsonl
        if (parse_iso(e.get("ts", "")) or datetime.min.replace(tzinfo=timezone.utc)).timestamp() >= cutoff
    ]
    # Build a blob from recent events' details
    blob = " ".join(e.get("detail", "") + " " + e.get("event", "") for e in recent).lower()
    matches = sum(1 for p in LAB_UNSTABLE_PATTERNS if re.search(p, blob))
    return matches >= LAB_UNSTABLE_THRESHOLD


def alternatives_from_attack_plan(session_dir: Path) -> list[str]:
    """v0.3 P2.3 — Read alternative_chains from fingerprint.json attack_plan."""
    fp_path = session_dir / "fingerprint.json"
    if not fp_path.exists():
        return []
    try:
        fp = json.loads(fp_path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    chains = fp.get("attack_plan", {}).get("alternative_chains", [])
    alts = []
    for chain in chains:
        cats = chain.get("categories", [])
        alts.extend(cats)
    return list(dict.fromkeys(alts))


def alternatives_from_findings(findings_md: str) -> list[str]:
    """Extract category hints from findings.md (services/ports listed)."""
    blob = findings_md.lower()
    alts = []
    if "winrm" in blob or "5985" in blob or "5986" in blob:
        alts.append("winrm-lateral")
    if "445" in blob and "smb" in blob:
        alts.append("smb-exploit")
    if "kerberos" in blob or "88" in blob:
        alts.append("ad-abuse")
    if "mysql" in blob or "postgres" in blob or "mongodb" in blob:
        alts.append("database-exposed")
    if "docker" in blob or "2375" in blob:
        alts.append("docker-escape")
    # ICS / OT / industrial control systems
    if "opc-ua" in blob or "opc ua" in blob or "4840" in blob or "opcua" in blob:
        alts.append("opcua-browse-full")
    if "nifi" in blob or "apache nifi" in blob:
        alts.append("nifi-groovy-exec")
    if "modbus" in blob or "502" in blob or "dnp3" in blob or "scada" in blob:
        alts.append("ics-protocol-enum")
    if "maintenance" in blob or "plc" in blob or "helix" in blob:
        alts.append("ics-service-check")
    if "support-bundle" in blob or "support_bundle" in blob or "backup" in blob:
        alts.append("backup-file-enum")
    return list(dict.fromkeys(alts))


def merged_alternatives(findings_md: str, session_dir: Path) -> list[str]:
    """v0.3 P2.3 — Merge findings-derived + attack_plan alternatives. Never empty if either has entries."""
    from_findings = alternatives_from_findings(findings_md)
    from_plan = alternatives_from_attack_plan(session_dir)
    combined = list(dict.fromkeys(from_findings + from_plan))
    return combined


def recommend(signals: list[str], findings_md: str,
              session_dir: Path) -> tuple[str, list[str], str]:
    alts = merged_alternatives(findings_md, session_dir)

    if "lab_unstable" in signals:
        return ("switch_vpn_server", alts,
                "Lab/VPN unstable — verificar VPN + respawn machine si es necesario.")
    if "shell_lost" in signals:
        return ("reset_listener", alts,
                "Foothold artifact dead — re-exploit el mismo vector o probar alternativo.")
    if "hash_stuck" in signals:
        return ("escalate_gpu", alts,
                "Hash CPU timeout — lanzar crack-helper.sh --async + paralelizar otros vectores.")
    if "cred_exhausted" in signals:
        return ("switch_vector", alts,
                "Cred spray agotado — pivot a vector lateral alternativo (ver alternatives).")
    if "progress_stalled" in signals:
        return ("switch_vector", alts,
                "Sin progreso en >30 min — replantear con alternatives.")
    return ("continue", [], "No stuck signals — flow normal.")


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--session-dir", required=True, type=Path)
    ap.add_argument("--output",      default=None, type=Path,
                    help="Output JSON path (default: stdout only)")
    ap.add_argument("--stall-minutes", type=int, default=STALL_MINUTES,
                    help=f"Wall-clock minutes without artifact update = stalled (default {STALL_MINUTES})")
    args = ap.parse_args()

    if not args.session_dir.exists():
        print(json.dumps({"error": f"session-dir not found: {args.session_dir}"}), file=sys.stderr)
        sys.exit(2)

    estado_path  = args.session_dir / "estado.md"
    finds_path   = args.session_dir / "findings.md"
    jsonl_path   = args.session_dir / "sessions.jsonl"

    estado   = read_file_safe(estado_path)
    findings = read_file_safe(finds_path)
    jsonl    = read_jsonl(jsonl_path)

    now = datetime.now(timezone.utc)
    signals = []
    if detect_shell_lost(estado, findings):
        signals.append("shell_lost")
    if detect_hash_stuck(estado, jsonl):
        signals.append("hash_stuck")
    if detect_cred_exhausted(estado, jsonl):
        signals.append("cred_exhausted")

    # Stall check uses real file mtime — only meaningful when this is the live session.
    # Allow override via stall_minutes=0 to skip in tests.
    if args.stall_minutes > 0 and detect_progress_stalled(
            estado_path, finds_path, jsonl_path, now):
        signals.append("progress_stalled")

    # v0.3 P3.1 — lab/VPN stability signal
    if detect_lab_unstable(jsonl, now):
        signals.append("lab_unstable")

    recommendation, alternatives, rationale = recommend(signals, findings, args.session_dir)

    result = {
        "stuck":           len(signals) > 0,
        "signals":         signals,
        "recommendation":  recommendation,
        "alternatives":    alternatives,
        "rationale":       rationale,
        "session_dir":     str(args.session_dir),
        "scanned_at":      datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }

    out_json = json.dumps(result, indent=2)
    print(out_json)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(out_json)

    sys.exit(1 if result["stuck"] else 0)


if __name__ == "__main__":
    main()
