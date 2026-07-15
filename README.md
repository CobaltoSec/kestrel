![CI](https://github.com/CobaltoSec/kestrel/actions/workflows/test.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

# Kestrel — AI-Native HTB Engagement Framework

> Intel-first orchestration for HackTheBox VMs. Hover before you dive.

> **Legal**: This tool is for authorized security testing, CTF competitions (HackTheBox), and research only. Use against systems you do not own or lack explicit written permission to test is illegal. Authors assume no liability for misuse. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

Kestrel is a [Claude Code](https://claude.ai/code) skill that applies an intelligence layer before executing against a target VM. Rather than running generic scans, it classifies the target first — then directs execution toward the probable attack chain, narrating in real time.

## Why

Most HTB automation either runs full blind recon (slow, noisy) or requires you to already know the chain. Kestrel sits in between: fingerprint → knowledge query → directed execution — with ~6 human decision points instead of ~19.

## Architecture — 4 Layers

```
┌─────────────────────────────────────────────────────────┐
│  4. MEMORY                                              │
│     estado.md · state.json · writeup.md                 │
│     KB synthesis · cross-session resume                 │
│     → persists between sessions, learns from each run   │
├─────────────────────────────────────────────────────────┤
│  3. EXECUTION                                           │
│     delegated to /pentest --mode lab                    │
│     discovery → vuln → exploit                          │
│     → Kestrel orchestrates, doesn't execute directly    │
├─────────────────────────────────────────────────────────┤
│  2. ORCHESTRATION                                       │
│     phases p0 → p1 → p1.5 → p2 → p3 → p4 → p5 → p6   │
│     mode switching · HITL gates · continuous narration  │
│     → workflow engine, core of Kestrel                  │
├─────────────────────────────────────────────────────────┤
│  1. INTEL                                               │
│     WebSearch retired + blind_fingerprint.py active     │
│     intel.md · fingerprint.json · optional KB query     │
│     → the hover before the dive                         │
└─────────────────────────────────────────────────────────┘
```

## Modes

| Mode | When | Intel source |
|---|---|---|
| **Guided** | Retired machines | WebSearch writeup synthesis → `intel.md` → directed execution |
| **Blind** | Active machines | `blind_fingerprint.py` post-discovery → attack categories → optional KB query |

HTB TOS: no writeup search for active machines. Blind mode is the compliant path.

## Standalone Scripts

Both scripts work independently of the full Claude Code skill.

### `scripts/blind_fingerprint.py`

Classifies a target from nmap/httpx output into attack categories with confidence scores.

```bash
# From nmap file
python3 scripts/blind_fingerprint.py \
    --nmap /tmp/scan.gnmap \
    --target 10.10.10.x \
    --os Windows \
    --difficulty Medium \
    --output ./fingerprint.json

# Or inline JSON (no file needed)
python3 scripts/blind_fingerprint.py \
    --ports-json '{"ports":["88","445","389"],"services":["kerberos","smb","ldap"],"banners":[]}' \
    --target 10.10.10.x \
    --output ./fingerprint.json
```

Sample output:
```json
{
  "target_ip": "10.10.10.x",
  "os_likely": "windows",
  "ad_joined": true,
  "attack_categories": [
    {"category": "ad-abuse", "confidence": 0.92, "tactics": [3, 6, 8, 9, 10]},
    {"category": "smb-exploit", "confidence": 0.70, "tactics": [3, 4, 10]}
  ],
  "summary": "Windows host. Top path: ad-abuse (conf=0.92). ATT&CK tactics: 3, 6, 8."
}
```

Optional: connect to a pgvector KB for technique context (set `KESTREL_KB_PATH` — see `.env.example`).

### `scripts/resume_validator.sh`

Validates session state before resuming: VPN up, machine reachable, listeners alive. Designed to run on your Kali VM.

```bash
MACHINE_IP=10.10.10.x \
LISTENERS_JSON='[{"pid":1234,"port":9001,"type":"nc","cmd":"nc -lvnp 9001"}]' \
bash scripts/resume_validator.sh
```

Output:
```json
{
  "vpn_up": true,
  "machine_reachable": false,
  "listeners_alive": [{"port": 9001, "alive": false}],
  "needs_recovery": true,
  "recovery_actions": ["respawn_machine", "restart_listener_9001"]
}
```

## ATT&CK Coverage

| Tactic | # | How Kestrel covers it |
|---|---|---|
| Reconnaissance | 1 | p1.5 WebSearch (guided) + blind_fingerprint.py port/banner classification (blind) |
| Initial Access | 3 | p3 exploit phase via /pentest |
| Execution | 4 | p3 post-foothold commands |
| Privilege Escalation | 6 | p3 LinPEAS/WinPEAS + guided vector from intel |
| Credential Access | 8 | hash detection + Hash Policy automation (5 min cap → GPU offload) |
| Discovery | 9 | p3 PASO 1 + fingerprint.py classification |

Gaps (complex chains only): Persistence (5), Defense Evasion (7), Lateral Movement (10) — handled by `/pentest-ad` delegation when detected.

## Requirements

- Python 3.10+
- [Claude Code](https://claude.ai/code) CLI (for the full orchestration skill)
- Kali Linux VM with SSH access (execution platform)
- HTB VPN connection
- Optional: pgvector + Ollama for KB-enhanced blind mode

## Configuration

```bash
cp .env.example .env
# Edit .env with your values
```

## Status

- **<!-- KESTREL_VERSION_START -->v0.7.1<!-- KESTREL_VERSION_END -->** (2026-07-01): <!-- KESTREL_TOOLS_COUNT_START -->77<!-- KESTREL_TOOLS_COUNT_END --> MCP tools. Operational hardening sprint — web-only pivot, NextJS detection, UDP fallback, username extraction, dirfuzz bypass, intel_cve_lookup auto-nuclei.
- **v0.2** (roadmap): Multi-path hypothesis + L3 feedback loop + active Hard machine validation
- **v0.3** (roadmap): Sanitized phase library + full case studies + comparison vs AutoPwn/HackBot

## Case Studies

- **Kobold** (Easy Linux, retired) — CVE-2026-23520 command injection → Docker socket escape → root. Guided mode, ~90 min, intel match=full.
- **Garfield** (Hard Windows, retired) — blind mode validation; chain: SYSVOL → RBCD → KeyList attack. HTB flag regeneration bug encountered (documented, not a Kestrel issue).

---

Built by [CobaltoSec](https://cobalto-sec.tech) · Offensive Security Platform Engineering
