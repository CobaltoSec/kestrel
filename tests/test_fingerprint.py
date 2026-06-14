"""
Basic smoke tests for blind_fingerprint.py.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

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


# ─── IMP-20 — Jenkins / Elasticsearch / Jupyter fingerprint rules ─────────────


def test_jenkins_port_8080_detected():
    """IMP-20: port 8080 should produce jenkins-exploit category."""
    out = run_fingerprint({
        "ports": ["8080"],
        "services": ["http"],
        "banners": [],
    })
    cats = [c["category"] for c in out.get("attack_categories", [])]
    assert "jenkins-exploit" in cats, f"Expected jenkins-exploit, got: {cats}"


def test_jenkins_banner_hudson_detected():
    """IMP-20: banner containing 'hudson' should produce jenkins-exploit."""
    out = run_fingerprint({
        "ports": ["8080"],
        "services": ["http"],
        "banners": ["X-Jenkins: 2.387", "Server: Jetty/Hudson"],
    })
    cats = [c["category"] for c in out.get("attack_categories", [])]
    assert "jenkins-exploit" in cats, f"Expected jenkins-exploit via banner, got: {cats}"


def test_elasticsearch_port_9200_detected():
    """IMP-20: port 9200 should produce elasticsearch-expose category."""
    out = run_fingerprint({
        "ports": ["9200"],
        "services": ["http"],
        "banners": [],
    })
    cats = [c["category"] for c in out.get("attack_categories", [])]
    assert "elasticsearch-expose" in cats, f"Expected elasticsearch-expose, got: {cats}"


def test_jupyter_port_8888_detected():
    """IMP-20: port 8888 should produce jupyter-rce category."""
    out = run_fingerprint({
        "ports": ["8888"],
        "services": ["http"],
        "banners": [],
    })
    cats = [c["category"] for c in out.get("attack_categories", [])]
    assert "jupyter-rce" in cats, f"Expected jupyter-rce, got: {cats}"


def test_jupyter_banner_detected():
    """IMP-20: banner containing 'jupyter' should produce jupyter-rce category."""
    out = run_fingerprint({
        "ports": ["8888"],
        "services": ["http"],
        "banners": ["Jupyter Notebook", "Server: tornado"],
    })
    cats = [c["category"] for c in out.get("attack_categories", [])]
    assert "jupyter-rce" in cats, f"Expected jupyter-rce via banner, got: {cats}"


def test_elasticsearch_static_alternatives_nonempty():
    """IMP-20: elasticsearch-expose category must have static alternatives defined."""
    out = run_fingerprint({
        "ports": ["9200"],
        "services": ["http"],
        "banners": ["elasticsearch"],
    })
    plan = out.get("attack_plan", {})
    alts = plan.get("alternative_chains", [])
    assert len(alts) >= 1, f"Expected ≥1 alternative_chains for elasticsearch, got: {alts}"


def test_web_in_container_not_triggered_for_linux():
    """P4.1: Linux host should never trigger web_in_container."""
    out = run_fingerprint({
        "ports": ["22", "80"],
        "services": ["ssh", "http"],
        "banners": ["nginx/1.25"],
    })
    cats = [c["category"] for c in out.get("attack_categories", [])]
    assert "web_in_container" not in cats


# ─── IMP-07a + IMP-13 ────────────────────────────────────────────────────────

def test_kb_confidence_threshold_value():
    """IMP-07a: KB_CONFIDENCE_THRESHOLD must be 0.60."""
    import sys
    from pathlib import Path
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    from kestrel.core.fingerprint import KB_CONFIDENCE_THRESHOLD
    assert KB_CONFIDENCE_THRESHOLD == 0.60, (
        f"Expected KB_CONFIDENCE_THRESHOLD=0.60, got {KB_CONFIDENCE_THRESHOLD}"
    )


def test_score_rules_normalized_partial_signals():
    """IMP-13: partial activation normalizes correctly.

    Rule with signals [0.40, 0.60] (max_possible=1.0).
    Only port signal (0.40) active → raw=0.40, normalized=0.40/1.0=0.40.

    Rule with signals [0.30, 0.30] (max_possible=0.60).
    Only one signal active → raw=0.30, normalized=0.30/0.60=0.50.
    Without normalization it would be 0.30; with normalization it is 0.50.
    We verify via docker-escape rule: signals are [0.90 (port), 0.90 (service)]
    → max_possible=1.80. With only port 2375 active (no 'docker' service):
    raw=0.90, normalized=0.90/1.80=0.50 (not 0.90).
    """
    out = run_fingerprint({
        "ports": ["2375"],
        "services": ["http"],   # NOT 'docker' — only port signal fires
        "banners": [],
    })
    cats = {c["category"]: c["confidence"] for c in out.get("attack_categories", [])}
    assert "docker-escape" in cats, "docker-escape should trigger on port 2375"
    conf = cats["docker-escape"]
    # With normalization: 0.90/1.80 = 0.50
    # Without normalization (old cap): min(0.90, 0.95) = 0.90
    assert conf == pytest.approx(0.50, abs=0.01), (
        f"Expected docker-escape confidence ~0.50 (normalized), got {conf}"
    )


def test_score_rules_full_signals_caps_at_095():
    """IMP-13: all signals active on a rule → confidence capped at 0.95.

    docker-escape: port 2375 (0.90) + service 'docker' (0.90) → raw=1.80,
    normalized=1.80/1.80=1.00 → capped at 0.95.
    """
    out = run_fingerprint({
        "ports": ["2375"],
        "services": ["docker"],   # both signals fire
        "banners": [],
    })
    cats = {c["category"]: c["confidence"] for c in out.get("attack_categories", [])}
    assert "docker-escape" in cats, "docker-escape should trigger"
    conf = cats["docker-escape"]
    assert conf == pytest.approx(0.95, abs=0.01), (
        f"Expected docker-escape confidence 0.95 (cap), got {conf}"
    )
