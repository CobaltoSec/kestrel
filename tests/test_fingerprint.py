"""
Basic smoke tests for blind_fingerprint.py.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "scripts" / "blind_fingerprint.py"


def run_fingerprint(ports_json: dict) -> dict:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        result = subprocess.run(
            [sys.executable, str(SCRIPT),
             "--ports-json", json.dumps(ports_json),
             "--target", "10.10.10.x",
             "--output", tmp_path,
             "--no-kb"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, f"Script failed: {result.stderr}"
        return json.loads(Path(tmp_path).read_text())
    finally:
        Path(tmp_path).unlink(missing_ok=True)


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


# ─── P2.1 — STATIC_ALTERNATIVES guarantee ────────────────────────────────────

def test_kb_miss_alternative_chains_nonempty():
    """P2.1: --no-kb + single dominant category → alternative_chains from STATIC_ALTERNATIVES."""
    out = run_fingerprint({
        "ports": ["80", "443"],
        "services": ["http", "https"],
        "banners": ["Apache/2.4"],
    })
    plan = out.get("attack_plan", {})
    alts = plan.get("alternative_chains", [])
    assert len(alts) >= 2, (
        f"Expected ≥2 alternative_chains when KB miss, got {len(alts)}: {alts}"
    )
    # Each entry must have at least a categories field
    for chain in alts:
        assert "categories" in chain, f"Chain missing 'categories': {chain}"


# ─── P4.1 — web_in_container heuristic ───────────────────────────────────────

def test_web_in_container_monitorsfour_fixture():
    """P4.1: Windows host (445) + web-only (80) + Cacti banner → web_in_container ≥ 0.70."""
    out = run_fingerprint({
        "ports": ["445", "80"],
        "services": ["smb", "http"],
        "banners": ["Server: nginx/1.25 (Linux)", "X-Powered-By: PHP/8.1", "cacti 1.2.28"],
    })
    categories = out.get("attack_categories", [])
    cats = [c["category"] for c in categories]
    assert "web_in_container" in cats, (
        f"Expected 'web_in_container' category for Windows+Cacti fixture, got: {cats}"
    )
    wic = next(c for c in categories if c["category"] == "web_in_container")
    assert wic["confidence"] >= 0.70, (
        f"Expected confidence ≥ 0.70, got {wic['confidence']}"
    )
    # Alternative chains should include docker-escape paths
    plan = out.get("attack_plan", {})
    alts = plan.get("alternative_chains", [])
    assert len(alts) >= 1, "Expected alternative_chains for web_in_container"


def test_web_in_container_not_triggered_for_linux():
    """P4.1: Linux host should never trigger web_in_container."""
    out = run_fingerprint({
        "ports": ["22", "80"],
        "services": ["ssh", "http"],
        "banners": ["nginx/1.25"],
    })
    cats = [c["category"] for c in out.get("attack_categories", [])]
    assert "web_in_container" not in cats
