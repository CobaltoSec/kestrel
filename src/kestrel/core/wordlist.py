#!/usr/bin/env python3
"""
Kestrel wordlist_strategy — context-aware wordlist plan.

Given a target's metadata (machine name, vhosts, framework, hash type) emits a
priority-ordered JSON plan of which wordlists to try first. Designed to replace
"default rockyou everywhere" with a strategy that exploits context: bcrypt gets
short token+common-creds passes first, fast hashes go straight to rockyou+rules.

Does NOT execute anything itself — emits paths, rule names, and a cewl recipe
string for the caller (Kestrel p3 Hash Policy) to run.

Usage (legacy CLI):
    python -m kestrel.core.wordlist \\
        --machine-name MonitorsFour \\
        --vhosts cacti.monitorsfour.htb,monitorsfour.htb \\
        --framework cacti \\
        --hash-type bcrypt \\
        --output wordlist-plan.json
"""
import argparse
import json
import re
from datetime import datetime
from pathlib import Path

# ─── Wordlist catalog ─────────────────────────────────────────────────────────
# Paths assume standard Kali/SecLists installation. Caller verifies existence.

SECLISTS = "/usr/share/seclists"
WORDLISTS = "/usr/share/wordlists"

CATALOG = {
    "common15":       f"{SECLISTS}/Passwords/Common-Credentials/10-million-password-list-top-100.txt",
    "common1k":       f"{SECLISTS}/Passwords/Common-Credentials/10-million-password-list-top-1000.txt",
    "common10k":      f"{SECLISTS}/Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
    "rockyou":        f"{WORDLISTS}/rockyou.txt",
    "rockyou75":      f"{SECLISTS}/Passwords/Leaked-Databases/rockyou-75.txt",
    "names":          f"{SECLISTS}/Usernames/Names/names.txt",
    "darkweb":        f"{SECLISTS}/Passwords/darkweb2017-top10000.txt",
    "richelieu":      f"{SECLISTS}/Passwords/Leaked-Databases/richelieu-french-top5000.txt",
    "cewl_runtime":   "/tmp/cewl-{slug}.txt",
}

# ─── Hash type → speed bucket ─────────────────────────────────────────────────
# Fast = high-throughput on CPU (md5/sha1/ntlm). Slow = expensive (bcrypt/argon2).

FAST_HASHES = {"md5", "md4", "sha1", "sha256", "sha512", "ntlm", "ntlmv1", "netntlmv2"}
SLOW_HASHES = {"bcrypt", "argon2", "scrypt", "pbkdf2"}


def split_camelcase(name: str) -> list[str]:
    """Split CamelCase / PascalCase / snake_case / kebab-case into tokens."""
    tokens = re.split(r"(?<=[a-z])(?=[A-Z])|[_\-\s]+", name)
    return [t.lower() for t in tokens if t]


def tokenize_machine(machine_name: str) -> list[str]:
    parts = split_camelcase(machine_name)
    tokens = list(dict.fromkeys(parts + [machine_name.lower()]))
    return tokens


def tokenize_vhosts(vhosts: list[str]) -> list[str]:
    tokens = []
    for v in vhosts:
        for part in re.split(r"[\.\-_]+", v):
            part = part.strip().lower()
            if part and part not in {"htb", "com", "net", "org", "local", "lan", "www"}:
                tokens.append(part)
    return list(dict.fromkeys(tokens))


def build_context_wordlist(tokens: list[str], framework: str | None,
                           output_dir: str = "/tmp") -> dict:
    """Generate a small inline wordlist from tokens + common mangling.

    Returns a recipe (filename + lines to write). Caller writes the file when
    it's ready to use it — we don't touch disk here.
    """
    years = ["2024", "2025", "2026"]
    suffixes = ["", "!", "123", "@1", "2024", "2025", "2026", "01"]

    base = list(tokens)
    if framework:
        base.append(framework.lower())

    expanded = []
    for tok in base:
        # capitalizations
        variants = {tok, tok.capitalize(), tok.upper()}
        for v in variants:
            for s in suffixes:
                expanded.append(v + s)
            for y in years:
                expanded.append(v + y)
                expanded.append(v + y + "!")

    expanded = list(dict.fromkeys(expanded))
    slug = (tokens[0] if tokens else "kestrel")
    return {
        "path": f"{output_dir}/context-{slug}.txt",
        "entries": expanded,
        "count": len(expanded),
        "rationale": (
            "Tokens del machine name + vhosts + framework, expandidos con years "
            "(2024-2026) y suffixes comunes (!,123,@1,01). Alta probabilidad de "
            "match si el password fue elegido por el author de la VM."
        ),
    }


def estimate_time_minutes(wordlist_size: int, hash_type: str, rules: str) -> int:
    """Rough estimate of CPU crack time. Pessimistic for safety."""
    rule_mult = {"none": 1, "best64": 64, "dive": 350, "rockyou": 16}.get(rules, 1)
    effective = wordlist_size * rule_mult
    if hash_type in FAST_HASHES:
        # ~10M hashes/sec/core CPU for MD5
        return max(1, effective // 10_000_000 // 60)
    if hash_type in SLOW_HASHES:
        # ~50 hashes/sec/core for bcrypt cost=10
        return max(1, effective // 50 // 60)
    return max(1, effective // 1_000_000 // 60)


WORDLIST_SIZES = {
    "common15":  100,
    "common1k":  1_000,
    "common10k": 10_000,
    "rockyou75": 75_000,
    "rockyou":   14_344_391,
    "names":     10_000,
    "darkweb":   10_000,
    "richelieu": 5_000,
}


def recommend_strategy(hash_type: str, plan: list[dict]) -> str:
    """Auto-decision: cpu | gpu_async | hint_first.

    gpu_async: slow hash AND (estimated time > 30 min OR largest wordlist > 1M entries).
    cpu: fast hash OR estimated time for full plan < 5 min.
    hint_first: otherwise — suggest intel/writeup before burning GPU.
    """
    hash_norm = hash_type.lower()
    if hash_norm in SLOW_HASHES:
        # Check any step with a known size > 1M or estimated time > 30 min
        for step in plan:
            size = step.get("size") or 0
            est = step.get("estimated_time_minutes") or 0
            if size > 1_000_000 or est > 30:
                return "gpu_async"
        return "hint_first"
    # Fast hash path
    total_est = sum(s.get("estimated_time_minutes") or 0 for s in plan if s.get("estimated_time_minutes"))
    if total_est < 5:
        return "cpu"
    return "cpu"   # fast hashes always go CPU; GPU only for slow


def build_plan(machine_name: str, vhosts: list[str], framework: str | None,
               hash_type: str | None, target_ip: str | None) -> dict:
    machine_tokens = tokenize_machine(machine_name)
    vhost_tokens = tokenize_vhosts(vhosts)
    all_tokens = list(dict.fromkeys(machine_tokens + vhost_tokens))

    context_list = build_context_wordlist(all_tokens, framework)

    plan = []
    hash_norm = (hash_type or "unknown").lower()

    # Priority 1: context wordlist (tiny, high-yield)
    plan.append({
        "priority": 1,
        "wordlist_id": "context_runtime",
        "wordlist_path": context_list["path"],
        "rules": "none",
        "size": context_list["count"],
        "estimated_time_minutes": estimate_time_minutes(
            context_list["count"], hash_norm, "none"),
        "rationale": context_list["rationale"],
        "needs_generation": True,
    })

    # Priority 2: top common credentials (always cheap)
    plan.append({
        "priority": 2,
        "wordlist_id": "common10k",
        "wordlist_path": CATALOG["common10k"],
        "rules": "none",
        "size": WORDLIST_SIZES["common10k"],
        "estimated_time_minutes": estimate_time_minutes(
            WORDLIST_SIZES["common10k"], hash_norm, "none"),
        "rationale": "Top 10k most common credentials — covers low-effort passwords.",
        "needs_generation": False,
    })

    # Priority 3: branching by hash type
    if hash_norm in SLOW_HASHES:
        plan.append({
            "priority": 3,
            "wordlist_id": "rockyou75",
            "wordlist_path": CATALOG["rockyou75"],
            "rules": "none",
            "size": WORDLIST_SIZES["rockyou75"],
            "estimated_time_minutes": estimate_time_minutes(
                WORDLIST_SIZES["rockyou75"], hash_norm, "none"),
            "rationale": "rockyou 75k — slow-hash sweet spot (bcrypt cost=10 ~25 min CPU).",
            "needs_generation": False,
        })
        plan.append({
            "priority": 4,
            "wordlist_id": "cewl_runtime",
            "wordlist_path": CATALOG["cewl_runtime"].format(slug=machine_tokens[0]),
            "rules": "none",
            "size": None,
            "estimated_time_minutes": None,
            "rationale": "CeWL harvest from live vhosts — context-specific words.",
            "needs_generation": True,
            "recipe": (
                f"cewl http://{vhosts[0]} -d 2 -m 6 -w "
                f"{CATALOG['cewl_runtime'].format(slug=machine_tokens[0])}"
            ) if vhosts else None,
        })
        plan.append({
            "priority": 5,
            "wordlist_id": "rockyou_full",
            "wordlist_path": CATALOG["rockyou"],
            "rules": "none",
            "size": WORDLIST_SIZES["rockyou"],
            "estimated_time_minutes": estimate_time_minutes(
                WORDLIST_SIZES["rockyou"], hash_norm, "none"),
            "rationale": "Full rockyou — last CPU pass before GPU offload.",
            "gpu_recommended": True,
            "needs_generation": False,
        })
    else:
        # Fast hashes: go wide with mangling
        plan.append({
            "priority": 3,
            "wordlist_id": "rockyou_best64",
            "wordlist_path": CATALOG["rockyou"],
            "rules": "best64",
            "size": WORDLIST_SIZES["rockyou"],
            "estimated_time_minutes": estimate_time_minutes(
                WORDLIST_SIZES["rockyou"], hash_norm, "best64"),
            "rationale": "rockyou + best64 — covers most common mutations.",
            "needs_generation": False,
        })
        plan.append({
            "priority": 4,
            "wordlist_id": "cewl_runtime",
            "wordlist_path": CATALOG["cewl_runtime"].format(slug=machine_tokens[0]),
            "rules": "best64",
            "size": None,
            "estimated_time_minutes": None,
            "rationale": "CeWL + best64 — fast-hash sweet spot.",
            "needs_generation": True,
            "recipe": (
                f"cewl http://{vhosts[0]} -d 2 -m 6 -w "
                f"{CATALOG['cewl_runtime'].format(slug=machine_tokens[0])}"
            ) if vhosts else None,
        })
        plan.append({
            "priority": 5,
            "wordlist_id": "rockyou_dive",
            "wordlist_path": CATALOG["rockyou"],
            "rules": "dive",
            "size": WORDLIST_SIZES["rockyou"],
            "estimated_time_minutes": estimate_time_minutes(
                WORDLIST_SIZES["rockyou"], hash_norm, "dive"),
            "rationale": "rockyou + dive (350 rules) — heavy mangling, GPU only.",
            "gpu_recommended": True,
            "needs_generation": False,
        })

    recommendation = recommend_strategy(hash_norm, plan) if hash_norm != "unknown" else "cpu"

    return {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "machine": machine_name,
        "target_ip": target_ip,
        "hash_type": hash_norm,
        "framework": framework,
        "recommendation": recommendation,
        "tokens": {
            "machine": machine_tokens,
            "vhosts": vhost_tokens,
            "combined": all_tokens,
        },
        "context_wordlist": context_list,
        "plan": plan,
        "next_step_if_no_match": (
            "GPU offload via crack-helper.sh --async + crack_status.py poll. "
            "Mientras corre, paralelizar otros vectores via parallel_explorer.py."
        ),
    }


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--machine-name", required=True)
    ap.add_argument("--vhosts", default="",
                    help="Comma-separated list of vhosts")
    ap.add_argument("--framework", default=None,
                    help="Detected framework (cacti, laravel, etc.)")
    ap.add_argument("--target-ip", default=None)
    ap.add_argument("--hash-type", default=None,
                    help="bcrypt, md5, sha1, sha256, ntlm, etc.")
    ap.add_argument("--output", required=True, type=Path)
    args = ap.parse_args()

    vhosts = [v.strip() for v in args.vhosts.split(",") if v.strip()]
    plan = build_plan(args.machine_name, vhosts, args.framework,
                      args.hash_type, args.target_ip)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(plan, indent=2))
    print(f"[wordlist-strategy] {args.machine_name} → {len(plan['plan'])} entries → {args.output}")


if __name__ == "__main__":
    main()
