#!/usr/bin/env python3
"""
Kestrel blind_fingerprint.py — L1 Intel Layer, blind mode.

Classifies a target VM from nmap/httpx output into probable attack categories
with confidence scores, then optionally queries a pgvector KB for technique context.

Usage:
    python3 scripts/blind_fingerprint.py \
        --nmap /tmp/scan.gnmap \
        --target 10.10.10.x \
        --os Windows \
        --difficulty Medium \
        --output ./fingerprint.json

    # Or with inline JSON (no nmap file needed):
    python3 scripts/blind_fingerprint.py \
        --ports-json '{"ports":["88","445"],"services":["kerberos","smb"],"banners":[]}' \
        --target 10.10.10.x \
        --output ./fingerprint.json

nmap input: grepable (-oG) or normal text (-oN).
httpx input: JSON lines from `httpx -tech-detect -json -u http://<target>`.

KB query (optional): set KESTREL_KB_PATH env var to the directory containing
kb/query/smart.py, or pass --no-kb to disable explicitly.
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path
from datetime import datetime

# ─── ATT&CK tactic numbers ────────────────────────────────────────────────────
# 1=Recon 3=InitialAccess 4=Execution 5=Persistence 6=PrivEsc
# 7=DefenseEvasion 8=CredAccess 9=Discovery 10=LateralMovement

RULES = [
    {
        "category": "ad-abuse",
        "description": "Active Directory: Kerberoast/AS-REP/ADCS/DCSync/BloodHound paths",
        "tactics": [3, 6, 8, 9, 10],
        "kb_tags": ["kerberoast", "adcs", "bloodhound", "dcsync"],
        "signals": [
            {"ports_any": ["88"],                           "weight": 0.50},
            {"ports_any": ["389", "636", "3268", "3269"],   "weight": 0.25},
            {"ports_any": ["445"],                          "weight": 0.10},
            {"ports_any": ["5985", "5986"],                 "weight": 0.08},
            {"os_eq": "windows",                            "weight": 0.07},
        ],
    },
    {
        "category": "smb-exploit",
        "description": "SMB/NetBIOS exploitation: EternalBlue, share enum, null session, relay",
        "tactics": [3, 4, 10],
        "kb_tags": ["smb", "ms17-010", "netexec", "ntlm relay"],
        "signals": [
            {"ports_any": ["445", "139"],                   "weight": 0.60},
            {"os_eq": "windows",                            "weight": 0.20},
            {"banner_contains": ["samba", "windows"],       "weight": 0.15},
        ],
    },
    {
        "category": "docker-escape",
        "description": "Docker API unauthenticated (port 2375) or socket exposed",
        "tactics": [3, 4, 6],
        "kb_tags": ["docker", "container escape", "docker socket"],
        "signals": [
            {"ports_any": ["2375"],                         "weight": 0.90},
            {"services_any": ["docker"],                    "weight": 0.90},
        ],
    },
    {
        "category": "web-exploit",
        "description": "Generic web exploitation: SQLi, RCE, auth bypass, file upload",
        "tactics": [3, 4],
        "kb_tags": ["web exploit", "sqli", "rce"],
        "signals": [
            {"ports_any": ["80", "443", "8080", "8443", "8000", "8888"], "weight": 0.40},
            {"framework_not_null": True,                    "weight": 0.30},
        ],
    },
    {
        "category": "database-exposed",
        "description": "Unauthenticated or weakly-authenticated database",
        "tactics": [3, 8],
        "kb_tags": ["mysql", "mongodb", "redis", "postgres", "database exposure"],
        "signals": [
            {"ports_any": ["27017"],                        "weight": 0.75},
            {"ports_any": ["6379"],                         "weight": 0.70},
            {"ports_any": ["3306"],                         "weight": 0.55},
            {"ports_any": ["5432"],                         "weight": 0.50},
        ],
    },
    {
        "category": "nfs-exposed",
        "description": "NFS share exposed: mount enumerate and read/write paths",
        "tactics": [3, 8, 9],
        "kb_tags": ["nfs", "mount", "nfs enumeration"],
        "signals": [
            {"ports_any": ["2049"],                         "weight": 0.80},
            {"ports_any": ["111"],                          "weight": 0.20},
        ],
    },
    {
        "category": "winrm-lateral",
        "description": "WinRM credential exploitation or lateral movement",
        "tactics": [3, 10],
        "kb_tags": ["evil-winrm", "winrm", "ps remoting"],
        "signals": [
            {"ports_any": ["5985", "5986"],                 "weight": 0.70},
            {"os_eq": "windows",                            "weight": 0.20},
        ],
    },
    {
        "category": "rdp-attack",
        "description": "RDP: brute force, credential spray, BlueKeep, pass-the-hash",
        "tactics": [3, 10],
        "kb_tags": ["rdp", "bluekeep", "rdp brute"],
        "signals": [
            {"ports_any": ["3389"],                         "weight": 0.75},
            {"os_eq": "windows",                            "weight": 0.15},
        ],
    },
]

FRAMEWORK_CATEGORIES = {
    "laravel":    ("laravel-exploit",    [3, 4],     ["laravel", "laravel rce", "laravel sqli"]),
    "wordpress":  ("wordpress-exploit",  [3, 6],     ["wordpress", "wp-admin", "xmlrpc"]),
    "drupal":     ("drupal-exploit",     [3, 4],     ["drupal", "drupalgeddon"]),
    "django":     ("django-exploit",     [3, 4],     ["django", "debug mode", "ssti django"]),
    "flask":      ("flask-exploit",      [3, 4],     ["flask", "ssti", "jinja2 ssti"]),
    "express":    ("nodejs-exploit",     [3, 4],     ["express", "nodejs", "prototype pollution"]),
    "spring":     ("spring-exploit",     [3, 4],     ["spring4shell", "spring boot", "actuator"]),
    "tomcat":     ("tomcat-exploit",     [3, 4],     ["tomcat", "ghostcat", "ajp connector"]),
    "phpmyadmin": ("phpmyadmin-exploit", [3, 4],     ["phpmyadmin", "sql file upload"]),
}

KB_CONFIDENCE_THRESHOLD = 0.80


def parse_nmap(path: str) -> tuple[list[str], list[str], list[str]]:
    """Parse nmap grepable (-oG) or normal text (-oN) output."""
    text = Path(path).read_text(errors="ignore")
    ports, services, banners = [], [], []

    if "Status: Up" in text or "Ports:" in text:
        for match in re.finditer(r"(\d+)/open/\w+//([^/]*)//([^/,]*)", text):
            port, svc, banner = match.groups()
            ports.append(port.strip())
            services.append(svc.strip().lower())
            banners.append(banner.strip().lower())
    else:
        for match in re.finditer(r"^(\d+)/tcp\s+open\s+(\S+)\s*(.*)", text, re.MULTILINE):
            port, svc, banner = match.groups()
            ports.append(port.strip())
            services.append(svc.strip().lower())
            banners.append(banner.strip().lower())

    return ports, services, banners


def parse_httpx(path: str | None) -> tuple[list[str], str | None]:
    """Parse httpx -tech-detect -json output."""
    if not path or not Path(path).exists():
        return [], None

    tech = []
    for line in Path(path).read_text(errors="ignore").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            raw = obj.get("tech", obj.get("technologies", []))
            tech.extend(t.lower() for t in raw)
        except json.JSONDecodeError:
            continue

    framework = None
    for fw in FRAMEWORK_CATEGORIES:
        if any(fw in t for t in tech):
            framework = fw
            break

    return tech, framework


def parse_ports_json(raw: str) -> tuple[list[str], list[str], list[str]]:
    """Parse inline --ports-json argument."""
    obj = json.loads(raw)
    ports    = [str(p) for p in obj.get("ports", [])]
    services = [str(s).lower() for s in obj.get("services", [])]
    banners  = [str(b).lower() for b in obj.get("banners", [])]
    while len(banners) < len(ports):
        banners.append("")
    return ports, services, banners


def score_rules(
    ports: list[str],
    services: list[str],
    banners: list[str],
    os_hint: str,
    framework: str | None,
) -> list[dict]:
    """Score each rule and return categories sorted by confidence."""
    results = []
    os_lower = os_hint.lower()

    for rule in RULES:
        score = 0.0
        for sig in rule["signals"]:
            if "ports_any" in sig and any(p in ports for p in sig["ports_any"]):
                score += sig["weight"]
            if "services_any" in sig and any(s in services for s in sig["services_any"]):
                score += sig["weight"]
            if "os_eq" in sig and sig["os_eq"] in os_lower:
                score += sig["weight"]
            if "banner_contains" in sig and any(kw in b for b in banners for kw in sig["banner_contains"]):
                score += sig["weight"]
            if "framework_not_null" in sig and framework:
                score += sig["weight"]

        score = min(score, 0.95)
        if score > 0.05:
            results.append({
                "category": rule["category"],
                "description": rule["description"],
                "confidence": round(score, 2),
                "tactics": rule["tactics"],
                "kb_tags": rule["kb_tags"],
            })

    if framework and framework in FRAMEWORK_CATEGORIES:
        cat_name, tactics, tags = FRAMEWORK_CATEGORIES[framework]
        results.append({
            "category": cat_name,
            "description": f"Framework-specific: {framework}",
            "confidence": 0.87,
            "tactics": tactics,
            "kb_tags": tags,
        })

    results.sort(key=lambda x: x["confidence"], reverse=True)
    return results


def query_kb(categories: list[dict]) -> list[dict]:
    """Query KB for high-confidence categories. Skips gracefully if unavailable."""
    kb_results = []
    high_conf = [c for c in categories if c["confidence"] >= KB_CONFIDENCE_THRESHOLD]
    if not high_conf:
        return kb_results

    kb_path = os.environ.get("KESTREL_KB_PATH", "")
    if not kb_path:
        return kb_results

    try:
        sys.path.insert(0, kb_path)
        from kb.query.smart import smart_search

        for cat in high_conf:
            query = " ".join(cat["kb_tags"][:2])
            try:
                results, _ = smart_search(query, top_k=3)
                chunks = [
                    {
                        "text": r.get("content", "")[:400],
                        "source": r.get("metadata", {}).get("source", ""),
                        "score": round(float(r.get("score", 0)), 3),
                    }
                    for r in results
                ]
                if chunks:
                    kb_results.append({"category": cat["category"], "chunks": chunks})
            except Exception:
                continue
    except ImportError:
        pass

    return kb_results


def infer_os(ports: list[str], banners: list[str], os_hint: str) -> str:
    ports_set = set(ports)
    win_signals = {"88", "389", "445", "3389", "5985", "5986", "636", "3268"}
    if win_signals & ports_set:
        return "windows"
    if any("windows" in b or "microsoft" in b for b in banners):
        return "windows"
    if any("linux" in b or "ubuntu" in b or "debian" in b for b in banners):
        return "linux"
    return os_hint.lower() if os_hint else "unknown"


def build_summary(categories: list[dict], os_likely: str, framework: str | None) -> str:
    if not categories:
        return "No strong attack signals detected. Run full vuln scan."
    top = categories[0]
    second = f" | secondary: {categories[1]['category']}" if len(categories) > 1 else ""
    fw_note = f" ({framework} stack)" if framework else ""
    return (
        f"{os_likely.capitalize()} host{fw_note}. "
        f"Top path: {top['category']} (conf={top['confidence']}){second}. "
        f"ATT&CK tactics: {', '.join(str(t) for t in top['tactics'][:3])}."
    )


def main():
    ap = argparse.ArgumentParser(description="Kestrel blind fingerprinter — L1 Intel Layer")
    grp = ap.add_mutually_exclusive_group(required=True)
    grp.add_argument("--nmap",       help="nmap grepable (-oG) or normal (-oN) output file")
    grp.add_argument("--ports-json", help='Inline JSON: \'{"ports":["22","80"],"services":["ssh","http"],"banners":["openssh 8.9","nginx"]}\'')
    ap.add_argument("--httpx",      default=None,      help="httpx -tech-detect -json output file (optional)")
    ap.add_argument("--target",     required=True,     help="Target IP")
    ap.add_argument("--os",         default="unknown", help="OS hint from HTB API (Linux|Windows)")
    ap.add_argument("--difficulty", default="Easy",    help="Difficulty hint (Easy|Medium|Hard)")
    ap.add_argument("--output",     required=True,     help="Output path for fingerprint.json")
    ap.add_argument("--no-kb",      action="store_true", help="Skip KB query even if KESTREL_KB_PATH is set")
    args = ap.parse_args()

    if args.nmap:
        ports, services, banners = parse_nmap(args.nmap)
    else:
        ports, services, banners = parse_ports_json(args.ports_json)

    tech, framework = parse_httpx(args.httpx)
    os_likely = infer_os(ports, banners, args.os)
    ad_joined = any(p in ports for p in ["88", "389", "636", "3268"])

    categories = score_rules(ports, services, banners, os_likely, framework)

    if args.no_kb:
        kb_results = []
    else:
        kb_results = query_kb(categories)

    output_categories = [{k: v for k, v in c.items() if k != "kb_tags"} for c in categories]

    result = {
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "target_ip": args.target,
        "difficulty": args.difficulty,
        "ports_open": ports,
        "services": services,
        "os_likely": os_likely,
        "ad_joined": ad_joined,
        "framework": framework,
        "exposed_db": [s for s in services if s in {"mysql", "postgres", "mongodb", "redis", "elasticsearch"}],
        "tech_stack": tech,
        "attack_categories": output_categories,
        "kb_results": kb_results,
        "kb_queried": len(kb_results) > 0,
        "summary": build_summary(categories, os_likely, framework),
    }

    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(f"[kestrel-fp] {args.target} → {len(categories)} categories, "
          f"KB {'queried' if result['kb_queried'] else 'skipped'} → {args.output}")


if __name__ == "__main__":
    main()
