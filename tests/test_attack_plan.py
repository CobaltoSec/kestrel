"""
Tests for the v0.2 multi-path attack_plan output of blind_fingerprint.py.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "scripts" / "blind_fingerprint.py"


def run_fp(ports_json: dict, os_hint: str = "unknown") -> dict:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        result = subprocess.run(
            [sys.executable, str(SCRIPT),
             "--ports-json", json.dumps(ports_json),
             "--target", "10.10.10.x",
             "--os", os_hint,
             "--output", tmp_path,
             "--no-kb"],
            capture_output=True, text=True, timeout=10,
        )
        assert result.returncode == 0, result.stderr
        return json.loads(Path(tmp_path).read_text())
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_attack_plan_present_in_output():
    out = run_fp({"ports": ["80"], "services": ["http"], "banners": []})
    assert "attack_plan" in out
    plan = out["attack_plan"]
    assert {"primary_chain", "alternative_chains", "parallel_tracks", "execution_hint"} <= plan.keys()


def test_single_path_high_confidence_no_parallel():
    """Pure docker exposure → single path, conf >= 0.80, no parallel tracks."""
    out = run_fp({
        "ports": ["2375"],
        "services": ["docker"],
        "banners": ["docker engine"],
    })
    plan = out["attack_plan"]
    assert plan["primary_chain"]["categories"] == ["docker-escape"]
    assert plan["primary_chain"]["confidence"] >= 0.80
    assert plan["execution_hint"] == "single-path"


def test_multi_path_with_ad_and_winrm():
    """Windows DC with WinRM → multi-path, parallel tracks suggested."""
    out = run_fp({
        "ports": ["88", "389", "445", "5985"],
        "services": ["kerberos", "ldap", "smb", "wsman"],
        "banners": [],
    }, os_hint="Windows")
    plan = out["attack_plan"]
    assert plan["primary_chain"]["categories"][0] == "ad-abuse"
    assert plan["execution_hint"] == "multi-path"
    # Parallel track should mention AD + WinRM combo
    assert any("AD" in t or "WinRM" in t for t in plan["parallel_tracks"])


def test_alternatives_only_above_floor():
    """Categories below 0.40 confidence must NOT show up as alternatives."""
    out = run_fp({
        "ports": ["5985"],
        "services": ["wsman"],
        "banners": [],
    }, os_hint="Windows")
    plan = out["attack_plan"]
    for alt in plan["alternative_chains"]:
        assert alt["confidence"] >= 0.40, f"alt {alt} below 0.40 floor"


def test_low_confidence_combines_top_two():
    """If top confidence < 0.80, primary_chain should bundle top-2."""
    # http on a non-standard port — confidence stays moderate
    out = run_fp({
        "ports": ["8080"],
        "services": ["http-proxy"],
        "banners": [],
    })
    plan = out["attack_plan"]
    if plan["primary_chain"]["confidence"] < 0.80 and len(out["attack_categories"]) >= 2:
        # Either combined or just one if second is below 0.40
        second_conf = out["attack_categories"][1]["confidence"]
        if second_conf >= 0.40:
            assert len(plan["primary_chain"]["categories"]) >= 2


def test_empty_no_categories():
    """No services → wide-scan hint."""
    out = run_fp({"ports": [], "services": [], "banners": []})
    plan = out["attack_plan"]
    assert plan["execution_hint"] == "wide-scan"
    assert plan["primary_chain"]["categories"] == []


def test_monitorsfour_case():
    """Real MonitorsFour input → multi-path with WinRM as primary."""
    out = run_fp({
        "ports": ["80", "5985"],
        "services": ["http", "wsman"],
        "banners": ["microsoft-iis/10.0"],
    }, os_hint="Windows")
    plan = out["attack_plan"]
    assert plan["primary_chain"]["categories"][0] == "winrm-lateral"
    assert plan["execution_hint"] == "multi-path"
    # Should suggest parallel track between web exploit and WinRM spray
    assert any("WinRM" in t or "Web" in t for t in plan["parallel_tracks"])


def test_attack_categories_intact_v01_compat():
    """attack_categories field must NOT change format — backward compat."""
    out = run_fp({"ports": ["80"], "services": ["http"], "banners": []})
    assert "attack_categories" in out
    for c in out["attack_categories"]:
        assert "category" in c
        assert "confidence" in c
        assert "tactics" in c
        # kb_tags removed in output (consistent with v0.1.1)
        assert "kb_tags" not in c
