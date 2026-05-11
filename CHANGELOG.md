# Changelog

All notable changes to Kestrel are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning: [Semantic Versioning](https://semver.org/).

---

## [Unreleased]

### Planned (v0.2)
- Multi-path hypothesis when confidence < 0.60
- L3 → L2 feedback loop when `/pentest` finds complex AD chain
- KB synthesis automatic for Medium+ machines

---

## [0.1.0] — 2026-05-08

### Added
- `scripts/blind_fingerprint.py` — L1 intel layer. Classifies nmap/httpx output into
  8 attack categories with confidence scores. Optional pgvector KB integration.
- `scripts/resume_validator.py` / `resume_validator.sh` — L4 cross-session health check.
  Validates VPN up, machine reachable, listeners alive. Returns JSON recovery actions.
- `docs/architecture.md` — 4-layer architecture doc (Intel / Orchestration / Execution / Memory).
- ATT&CK coverage table (Recon, Initial Access, Execution, Privilege Escalation,
  Credential Access, Discovery).

### Case studies
- **Kobold** (Easy Linux, retired) — CVE-2026-23520 command injection → Docker socket
  escape → root. Guided mode, ~90 min, intel match=full.
- **Garfield** (Hard Windows, retired) — Blind mode. Chain: SYSVOL → RBCD → KeyList attack.
  HTB flag regeneration bug documented (not a Kestrel issue).
