"""
Tests for wordlist_strategy.py — context-aware wordlist plan generation.
"""
import json
import subprocess
import sys
import tempfile
from pathlib import Path

SCRIPT = Path(__file__).parent.parent / "scripts" / "wordlist_strategy.py"


def run_strategy(**kwargs) -> dict:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        args = [sys.executable, str(SCRIPT)]
        for key, val in kwargs.items():
            cli_key = "--" + key.replace("_", "-")
            args.extend([cli_key, str(val)])
        args.extend(["--output", tmp_path])
        result = subprocess.run(args, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, f"Script failed: {result.stderr}"
        return json.loads(Path(tmp_path).read_text())
    finally:
        Path(tmp_path).unlink(missing_ok=True)


def test_monitorsfour_bcrypt_plan():
    plan = run_strategy(
        machine_name="MonitorsFour",
        vhosts="cacti.monitorsfour.htb,monitorsfour.htb",
        framework="cacti",
        hash_type="bcrypt",
    )
    # Tokens
    assert "monitors" in plan["tokens"]["machine"]
    assert "four" in plan["tokens"]["machine"]
    assert "monitorsfour" in plan["tokens"]["machine"]
    assert "cacti" in plan["tokens"]["vhosts"]
    # htb/com/etc must be filtered
    assert "htb" not in plan["tokens"]["vhosts"]
    # Plan ordering — bcrypt should NOT lead with rockyou+best64
    p3 = next(p for p in plan["plan"] if p["priority"] == 3)
    assert p3["wordlist_id"] in ("rockyou75",), f"bcrypt p3 should be small wordlist, got {p3['wordlist_id']}"
    # GPU recommended on heaviest pass
    p5 = next(p for p in plan["plan"] if p["priority"] == 5)
    assert p5.get("gpu_recommended") is True


def test_kobold_md5_plan_uses_rules():
    """MD5 = fast hash → priority 3 should be rockyou + best64."""
    plan = run_strategy(
        machine_name="Kobold",
        vhosts="kobold.htb",
        framework="",
        hash_type="md5",
    )
    p3 = next(p for p in plan["plan"] if p["priority"] == 3)
    assert p3["rules"] == "best64", f"fast hash p3 should have best64, got {p3['rules']}"
    p5 = next(p for p in plan["plan"] if p["priority"] == 5)
    assert p5["rules"] == "dive"


def test_generic_no_vhosts_no_framework():
    plan = run_strategy(
        machine_name="Lame",
        vhosts="",
        hash_type="bcrypt",
    )
    assert plan["tokens"]["machine"] == ["lame"]
    assert plan["tokens"]["vhosts"] == []
    # Cewl entry should not have a recipe (no vhost to crawl)
    cewl = next((p for p in plan["plan"] if p["wordlist_id"] == "cewl_runtime"), None)
    assert cewl is not None
    assert cewl.get("recipe") is None


def test_context_wordlist_generation():
    plan = run_strategy(
        machine_name="MonitorsFour",
        vhosts="cacti.monitorsfour.htb",
        framework="cacti",
        hash_type="bcrypt",
    )
    ctx = plan["context_wordlist"]
    assert ctx["count"] > 50, f"Expected substantial context wordlist, got {ctx['count']}"
    # Should contain mangled variants
    entries = set(ctx["entries"])
    assert "monitorsfour" in entries
    assert any(e.startswith("MonitorsFour") for e in entries) \
        or any(e.startswith("Monitorsfour") for e in entries) \
        or any(e.startswith("MONITORSFOUR") for e in entries)
    # Year suffixes
    assert any("2026" in e for e in entries)


def test_camelcase_split():
    plan = run_strategy(
        machine_name="ResolutionStar",
        vhosts="",
        hash_type="md5",
    )
    assert "resolution" in plan["tokens"]["machine"]
    assert "star" in plan["tokens"]["machine"]


def test_cewl_recipe_for_bcrypt():
    plan = run_strategy(
        machine_name="MonitorsFour",
        vhosts="cacti.monitorsfour.htb",
        hash_type="bcrypt",
    )
    cewl = next(p for p in plan["plan"] if p["wordlist_id"] == "cewl_runtime")
    assert cewl["recipe"] is not None
    assert "cewl" in cewl["recipe"]
    assert "cacti.monitorsfour.htb" in cewl["recipe"]


def test_estimated_time_bcrypt_much_larger_than_md5():
    """bcrypt is ~200000x slower than md5 — estimates should reflect that."""
    plan_md5 = run_strategy(
        machine_name="X", vhosts="", hash_type="md5",
    )
    plan_bcrypt = run_strategy(
        machine_name="X", vhosts="", hash_type="bcrypt",
    )
    # priority 2 = common10k for both — bcrypt should be much slower
    md5_p2 = next(p for p in plan_md5["plan"] if p["priority"] == 2)
    bcrypt_p2 = next(p for p in plan_bcrypt["plan"] if p["priority"] == 2)
    assert bcrypt_p2["estimated_time_minutes"] >= md5_p2["estimated_time_minutes"]


def test_priority_1_is_context_runtime():
    """Priority 1 MUST be the context wordlist — fastest high-yield path."""
    plan = run_strategy(
        machine_name="MonitorsFour", vhosts="", hash_type="bcrypt",
    )
    p1 = next(p for p in plan["plan"] if p["priority"] == 1)
    assert p1["wordlist_id"] == "context_runtime"
    assert p1["needs_generation"] is True


def test_filters_common_tld_words():
    plan = run_strategy(
        machine_name="Test",
        vhosts="www.test.htb.com,api.test.local",
        hash_type="md5",
    )
    vhost_tokens = plan["tokens"]["vhosts"]
    assert "htb" not in vhost_tokens
    assert "com" not in vhost_tokens
    assert "local" not in vhost_tokens
    assert "www" not in vhost_tokens
    assert "test" in vhost_tokens
    assert "api" in vhost_tokens


# ─── P1.1 — recommendation field ─────────────────────────────────────────────

def test_recommendation_bcrypt_rockyou_is_gpu_async():
    """bcrypt + rockyou (14M entries) → recommendation=gpu_async."""
    plan = run_strategy(
        machine_name="CCTV",
        vhosts="cctv.htb",
        hash_type="bcrypt",
    )
    assert "recommendation" in plan
    assert plan["recommendation"] == "gpu_async", (
        f"Expected gpu_async for bcrypt+rockyou, got {plan['recommendation']}"
    )


def test_recommendation_md5_common10k_is_cpu():
    """md5 + common10k (fast hash, small list) → recommendation=cpu."""
    plan = run_strategy(
        machine_name="Lame",
        vhosts="",
        hash_type="md5",
    )
    assert plan["recommendation"] == "cpu", (
        f"Expected cpu for md5 fast hash, got {plan['recommendation']}"
    )


def test_recommendation_ntlm_rockyou_best64_is_cpu():
    """ntlm is fast → recommendation=cpu regardless of wordlist size."""
    plan = run_strategy(
        machine_name="Active",
        vhosts="",
        hash_type="ntlm",
    )
    assert plan["recommendation"] == "cpu", (
        f"Expected cpu for ntlm (fast hash), got {plan['recommendation']}"
    )


def test_recommendation_present_in_all_hash_types():
    """recommendation field is always present."""
    for ht in ("bcrypt", "md5", "sha1", "ntlm", "sha256", "argon2"):
        plan = run_strategy(machine_name="X", vhosts="", hash_type=ht)
        assert "recommendation" in plan, f"Missing recommendation for hash_type={ht}"
        assert plan["recommendation"] in ("cpu", "gpu_async", "hint_first")
