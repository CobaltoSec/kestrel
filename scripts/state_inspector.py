#!/usr/bin/env python3
"""
Kestrel state_inspector.py — query helper for last-cycle.json cross-session history.

Reads the optional `tried_credentials` / `tried_endpoints` / `tried_hashes` arrays
introduced in v0.2 (sub-bloque C). Lets the caller ask "did I already try this?"
without re-running an expensive operation across resumed sessions.

Usage examples:
    # Print all hashes tried against a machine
    python3 scripts/state_inspector.py --state-file last-cycle.json \\
        --slug monitorsfour --cmd list-hashes

    # Check whether a specific cred has been tried (exit 0 if yes, 1 if no)
    python3 scripts/state_inspector.py --state-file last-cycle.json \\
        --slug monitorsfour --cmd check-credential \\
        --user admin --password wonderful1 --service winrm

    # Check whether a hash+wordlist combo has been tried
    python3 scripts/state_inspector.py --state-file last-cycle.json \\
        --slug monitorsfour --cmd check-hash \\
        --hash-preview '$2y$10$wqlo06...' --wordlist rockyou

    # Summary (counts) for a slug
    python3 scripts/state_inspector.py --state-file last-cycle.json \\
        --slug monitorsfour --cmd summary

Exit codes:
    0  - found / tried
    1  - not found / not tried yet
    2  - error (missing file, bad slug, schema)
"""
import argparse
import json
import sys
from pathlib import Path


def load_machine(state_file: Path, slug: str) -> dict:
    if not state_file.exists():
        print(f"ERROR: state file not found: {state_file}", file=sys.stderr)
        sys.exit(2)
    try:
        state = json.loads(state_file.read_text())
    except json.JSONDecodeError as exc:
        print(f"ERROR: malformed JSON in {state_file}: {exc}", file=sys.stderr)
        sys.exit(2)

    machines = state.get("data", {}).get("machines", {})
    if slug not in machines:
        print(f"ERROR: slug '{slug}' not in state.data.machines", file=sys.stderr)
        sys.exit(2)
    return machines[slug]


def cmd_list(machine: dict, key: str) -> int:
    entries = machine.get(key, [])
    print(json.dumps(entries, indent=2))
    return 0 if entries else 1


def cmd_summary(machine: dict, slug: str) -> int:
    creds = machine.get("tried_credentials", [])
    eps = machine.get("tried_endpoints", [])
    hashes = machine.get("tried_hashes", [])
    summary = {
        "slug": slug,
        "tried_credentials": {
            "total": len(creds),
            "success": sum(1 for c in creds if c.get("result") == "success"),
            "failed":  sum(1 for c in creds if c.get("result") in ("auth_failed", "error", "account_locked")),
        },
        "tried_endpoints": {
            "total": len(eps),
            "interesting": sum(1 for e in eps if e.get("interesting")),
        },
        "tried_hashes": {
            "total": len(hashes),
            "cracked": sum(1 for h in hashes if h.get("result") == "match"),
            "no_match": sum(1 for h in hashes if h.get("result") == "no_match"),
        },
    }
    print(json.dumps(summary, indent=2))
    return 0


def cmd_check_credential(machine: dict, user: str, password: str, service: str) -> int:
    for c in machine.get("tried_credentials", []):
        if (c.get("user") == user
                and c.get("password") == password
                and c.get("service") == service):
            print(json.dumps(c, indent=2))
            return 0
    print(json.dumps({"tried": False}, indent=2))
    return 1


def cmd_check_hash(machine: dict, hash_preview: str, wordlist: str,
                   rules: str | None = None) -> int:
    for h in machine.get("tried_hashes", []):
        if h.get("hash_preview") == hash_preview and h.get("wordlist") == wordlist:
            if rules is not None and h.get("rules") != rules:
                continue
            print(json.dumps(h, indent=2))
            return 0
    print(json.dumps({"tried": False}, indent=2))
    return 1


def cmd_check_endpoint(machine: dict, path: str, vhost: str | None = None,
                       method: str = "GET") -> int:
    for e in machine.get("tried_endpoints", []):
        if e.get("path") != path or e.get("method", "GET") != method:
            continue
        if vhost is not None and e.get("vhost") != vhost:
            continue
        print(json.dumps(e, indent=2))
        return 0
    print(json.dumps({"tried": False}, indent=2))
    return 1


def main():
    ap = argparse.ArgumentParser(
        description="Query Kestrel last-cycle.json for cross-session history",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--state-file", required=True, type=Path,
                    help="Path to last-cycle.json")
    ap.add_argument("--slug", required=True,
                    help="Machine slug (key under data.machines)")
    ap.add_argument("--cmd", required=True,
                    choices=[
                        "summary",
                        "list-credentials", "list-endpoints", "list-hashes",
                        "check-credential", "check-hash", "check-endpoint",
                    ])
    # check-credential fields
    ap.add_argument("--user")
    ap.add_argument("--password")
    ap.add_argument("--service")
    # check-hash fields
    ap.add_argument("--hash-preview")
    ap.add_argument("--wordlist")
    ap.add_argument("--rules", default=None,
                    help="Optional rules filter for check-hash (e.g. best64)")
    # check-endpoint fields
    ap.add_argument("--path")
    ap.add_argument("--vhost", default=None)
    ap.add_argument("--method", default="GET")

    args = ap.parse_args()
    machine = load_machine(args.state_file, args.slug)

    if args.cmd == "summary":
        sys.exit(cmd_summary(machine, args.slug))
    if args.cmd == "list-credentials":
        sys.exit(cmd_list(machine, "tried_credentials"))
    if args.cmd == "list-endpoints":
        sys.exit(cmd_list(machine, "tried_endpoints"))
    if args.cmd == "list-hashes":
        sys.exit(cmd_list(machine, "tried_hashes"))

    if args.cmd == "check-credential":
        if not (args.user and args.password and args.service):
            ap.error("check-credential requires --user --password --service")
        sys.exit(cmd_check_credential(machine, args.user, args.password, args.service))

    if args.cmd == "check-hash":
        if not (args.hash_preview and args.wordlist):
            ap.error("check-hash requires --hash-preview --wordlist")
        sys.exit(cmd_check_hash(machine, args.hash_preview, args.wordlist, args.rules))

    if args.cmd == "check-endpoint":
        if not args.path:
            ap.error("check-endpoint requires --path")
        sys.exit(cmd_check_endpoint(machine, args.path, args.vhost, args.method))


if __name__ == "__main__":
    main()
