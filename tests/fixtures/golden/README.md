# Golden fixtures — blind_fingerprint regression suite

Each `<machine>.json` represents the recon snapshot of an HTB machine we've owned,
along with the expected fingerprint categories. Used by `test_fingerprint_golden.py`
to guard against regressions when `blind_fingerprint.py` is modified.

## Fixture schema

```json
{
  "machine": "monitorsfour",
  "source": "htb-sessions/htb-2026-05-08-monitorsfour",
  "input": {
    "ports": ["80", "5985"],
    "services": ["http", "wsman"],
    "banners": ["Microsoft-IIS/10.0", "Microsoft HTTPAPI httpd 2.0"],
    "os": "Windows",
    "difficulty": "Easy"
  },
  "expected": {
    "top_category": "winrm-lateral",
    "top_confidence_min": 0.70,
    "categories_present": [
      {"name": "winrm-lateral", "min_confidence": 0.70},
      {"name": "web-exploit",   "min_confidence": 0.40}
    ],
    "os_likely": "windows",
    "ad_joined": false
  }
}
```

## Adding new fixtures

When a new machine is owned, capture the nmap output → distill ports/services/banners
into a fixture and add the actual outcome (which category turned out to be the
foothold vector) to `expected.categories_present`. The test treats `min_confidence`
as a lower bound — it does not require an exact match.
