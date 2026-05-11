# Security Policy

## Scope

Kestrel is a workflow framework for CTF practice (HackTheBox) and authorized
professional engagements. It wraps the HTB API and orchestrates operator-owned
toolchains — it ships no exploit code.

**In scope for vulnerability reports:**
- `scripts/blind_fingerprint.py` — command injection or path traversal via input
- `scripts/resume_validator.py` — injection via env var parsing
- State file handling — if Kestrel trusts a tampered `last-cycle.json` in a way
  that leads to command execution

**Out of scope:**
- Vulnerabilities in HackTheBox infrastructure or API
- Vulnerabilities in third-party tools invoked by Kestrel (nmap, impacket, etc.)
- Issues that require the attacker to already control the Kali operator machine

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Email: **nicolas@cobalto-sec.tech**  
Subject line: `[KESTREL SECURITY] <short description>`

Include:
1. Description of the vulnerability and affected component
2. Reproduction steps (minimal proof of concept)
3. Potential impact assessment
4. Your suggested fix (optional but appreciated)

We will acknowledge receipt within **48 hours** and aim to ship a fix within
**7 days** for critical issues, **30 days** for moderate issues.

## Disclosure policy

We follow coordinated disclosure. Please give us time to patch before public
disclosure. We will credit you in the release notes unless you prefer
anonymity.
