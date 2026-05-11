# Contributing to Kestrel

Kestrel is an intel-driven HTB workflow framework maintained by CobaltoSec.
Contributions that improve speed, coverage, or operator experience are welcome.

## What we accept

### 1. Fingerprint categories (`scripts/blind_fingerprint.py`)
The current 8 categories live in `scripts/blind_fingerprint.py` (rules dict).
To add a category:
1. Add a detection rule (port patterns, service banners, or both).
2. Map it to ≥1 KB query string in the `kb_queries` dict.
3. Add a test case in `tests/` with a fixture `ports` dict and expected `attack_categories` output.

Rule of thumb: a category must be derivable from nmap output alone (no auth required).

### 2. Script improvements (`scripts/`)
- `scripts/blind_fingerprint.py` — fingerprint logic, KB integration
- `scripts/resume_validator.py` / `scripts/resume_validator.sh` — cross-session health checks

Both scripts are stdlib-only (Python 3.10+). Keep it that way unless there is a strong reason to add a dependency.

### 3. Documentation
Improvements to `README.md` and `docs/architecture.md` are welcome — especially corrections to the ATT&CK coverage table or case studies.

## PR review criteria

| Criterion | How we check |
|-----------|--------------|
| Fingerprint tests pass | `pytest tests/ -v` (if tests exist) |
| No hardcoded credentials | grep for `password\|token\|key` in `*.py` / `*.sh` |
| Platform TOS respected | No writeup scraping for active machines |
| stdlib-only (scripts) | No new third-party imports without justification |

## Commit message conventions

```
<type>(<scope>): <subject>
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

Scopes: `fingerprint`, `resume-validator`, `docs`, `scripts`

Examples:
```
feat(fingerprint): add mssql-exposed category for port 1433/1434
fix(resume-validator): handle missing LISTENERS_JSON gracefully
docs(readme): update ATT&CK coverage table
```

Subject: imperative mood, ≤72 chars, no trailing period.

## Local setup

```bash
# Python 3.10+ required, no external deps
python3 --version

# Run fingerprint script directly
python3 scripts/blind_fingerprint.py \
    --ports-json '{"ports":["80","443"],"services":["http","https"],"banners":[]}' \
    --target 10.10.10.x

# Validate resume_validator
MACHINE_IP=127.0.0.1 LISTENERS_JSON='[]' bash scripts/resume_validator.sh
```

HTB API token: set `HTB_TOKEN` env var. Never commit tokens or session state files.
