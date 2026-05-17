"""
Golden dataset regression tests for blind_fingerprint.py.

Each JSON fixture under tests/fixtures/golden/ represents an HTB machine we've
owned, plus the categories we expect the fingerprinter to surface for it. The
test treats every confidence floor as a lower bound — values above are fine,
values below indicate a regression.

When you own a new machine, drop a fixture in tests/fixtures/golden/<slug>.json
and it will be picked up automatically.
"""
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
SCRIPT = REPO_ROOT / "scripts" / "blind_fingerprint.py"
FIXTURES_DIR = Path(__file__).parent / "fixtures" / "golden"


def load_fixtures():
    """Discover all *.json fixtures except README.md."""
    return sorted(FIXTURES_DIR.glob("*.json"))


def _read_output(fixture: dict, ports_json: str, inp: dict) -> dict:
    """Run the script writing output to a tmp file we can read back."""
    import tempfile
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
        tmp_path = tmp.name
    try:
        result = subprocess.run(
            [sys.executable, str(SCRIPT),
             "--ports-json", ports_json,
             "--target",     "10.10.10.x",
             "--os",         inp.get("os", "unknown"),
             "--difficulty", inp.get("difficulty", "Easy"),
             "--output",     tmp_path,
             "--no-kb"],
            capture_output=True, text=True, timeout=15,
        )
        assert result.returncode == 0, f"Script failed: {result.stderr}"
        return json.loads(Path(tmp_path).read_text())
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@pytest.mark.parametrize("fixture_path", load_fixtures(), ids=lambda p: p.stem)
def test_golden_fixture(fixture_path: Path):
    fixture = json.loads(fixture_path.read_text())
    expected = fixture["expected"]

    out = _read_output(
        fixture,
        json.dumps({
            "ports":    fixture["input"]["ports"],
            "services": fixture["input"]["services"],
            "banners":  fixture["input"].get("banners", []),
        }),
        fixture["input"],
    )

    # 1. Schema is intact
    assert "attack_categories" in out
    assert "summary" in out
    assert "target_ip" in out

    # 2. OS inference matches
    assert out["os_likely"] == expected["os_likely"], \
        f"{fixture['machine']}: os_likely={out['os_likely']} expected {expected['os_likely']}"

    # 3. AD-joined inference matches
    assert out["ad_joined"] == expected["ad_joined"], \
        f"{fixture['machine']}: ad_joined={out['ad_joined']} expected {expected['ad_joined']}"

    categories_by_name = {c["category"]: c for c in out["attack_categories"]}

    # 4. Top category matches
    assert out["attack_categories"], f"{fixture['machine']}: no categories returned"
    top = out["attack_categories"][0]
    assert top["category"] == expected["top_category"], \
        f"{fixture['machine']}: top={top['category']} expected {expected['top_category']} " \
        f"(all categories: {list(categories_by_name.keys())})"
    assert top["confidence"] >= expected["top_confidence_min"], \
        f"{fixture['machine']}: top confidence {top['confidence']} below floor " \
        f"{expected['top_confidence_min']}"

    # 5. Each expected category is present with sufficient confidence
    for expected_cat in expected["categories_present"]:
        name = expected_cat["name"]
        floor = expected_cat["min_confidence"]
        assert name in categories_by_name, \
            f"{fixture['machine']}: category '{name}' missing from {list(categories_by_name.keys())}"
        actual_conf = categories_by_name[name]["confidence"]
        assert actual_conf >= floor, \
            f"{fixture['machine']}: '{name}' confidence {actual_conf} below floor {floor}"

    # 6. v0.2 — attack_plan schema (sub-bloque E)
    assert "attack_plan" in out, f"{fixture['machine']}: attack_plan missing"
    plan = out["attack_plan"]
    assert "primary_chain" in plan
    assert "alternative_chains" in plan
    assert "parallel_tracks" in plan
    assert "execution_hint" in plan
    assert plan["execution_hint"] in {"single-path", "multi-path", "wide-scan"}
    # Primary chain top category should match attack_categories[0]
    assert plan["primary_chain"]["categories"][0] == expected["top_category"], \
        f"{fixture['machine']}: attack_plan primary != attack_categories top"
