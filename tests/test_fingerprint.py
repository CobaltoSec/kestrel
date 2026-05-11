"""
Basic smoke tests for blind_fingerprint.py
"""
import json, subprocess, sys
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "scripts" / "blind_fingerprint.py"


def run_fingerprint(ports_json: dict) -> dict:
    result = subprocess.run(
        [sys.executable, str(SCRIPT),
         "--ports-json", json.dumps(ports_json),
         "--target", "10.10.10.x"],
        capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0, f"Script failed: {result.stderr}"
    return json.loads(result.stdout)


def test_ad_ports_detected():
    out = run_fingerprint({
        "ports": ["88", "389", "445", "636"],
        "services": ["kerberos", "ldap", "smb", "ldaps"],
        "banners": []
    })
    categories = [c["category"] for c in out.get("attack_categories", [])]
    assert any("ad" in c for c in categories), f"Expected AD category, got: {categories}"


def test_web_ports_detected():
    out = run_fingerprint({
        "ports": ["80", "443"],
        "services": ["http", "https"],
        "banners": ["Apache/2.4"]
    })
    assert "attack_categories" in out
    assert len(out["attack_categories"]) > 0


def test_output_schema():
    out = run_fingerprint({
        "ports": ["22", "80"],
        "services": ["ssh", "http"],
        "banners": []
    })
    assert "target_ip" in out
    assert "attack_categories" in out
    assert "summary" in out
