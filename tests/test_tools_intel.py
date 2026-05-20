"""Tests for kestrel.mcp.tools.intel — classify/kb_query/cve_lookup/save_synthesis."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from kestrel.mcp import context as mcp_context
from kestrel.mcp.tools import intel as intel_tools
from kestrel.mcp.tools import state as state_tools


@pytest.fixture
def fresh_ctx(tmp_path: Path, monkeypatch):
    # Force KB unavailable so query_kb returns []
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    mcp_context.reset_context()
    ctx = mcp_context.ServerContext.from_paths(
        state_dir=tmp_path / "state",
        session_root=tmp_path / "sessions",
    )
    mcp_context.set_context(ctx)
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "session_slug": "htb-test-lame"}
        )
    )
    yield ctx
    mcp_context.reset_context()


# ── intel_classify_blind ────────────────────────────────────────────────────


def test_classify_blind_smb_dominant(fresh_ctx):
    result = asyncio.run(
        intel_tools.intel_classify_blind(
            target="10.10.10.3",
            ports=["139", "445"],
            services=["netbios-ssn", "microsoft-ds"],
            banners=["Samba 3.0.20-Debian"],
            os_hint="Linux",
        )
    )
    cats = result["categories"]
    assert len(cats) > 0
    # smb-exploit should dominate due to 445/139 weight
    top = cats[0]
    assert top["category"] == "smb-exploit"
    assert top["confidence"] >= 0.4
    assert result["attack_plan"]["primary_chain"]["categories"][0] == "smb-exploit"


def test_classify_blind_ad_signals(fresh_ctx):
    result = asyncio.run(
        intel_tools.intel_classify_blind(
            target="10.10.10.141",
            ports=["88", "389", "445", "5985"],
            services=["kerberos", "ldap", "microsoft-ds", "winrm"],
            banners=[],
            os_hint="Windows",
            ad_joined=True,
        )
    )
    cats = result["categories"]
    top = cats[0]
    assert top["category"] == "ad-abuse"
    assert "kerberoast" in top["kb_tags"]


def test_classify_blind_empty_returns_wide_scan(fresh_ctx):
    result = asyncio.run(
        intel_tools.intel_classify_blind(target="10.10.10.99", ports=[], services=[], banners=[])
    )
    assert result["attack_plan"]["execution_hint"] == "wide-scan"


def test_classify_blind_docker_high_conf(fresh_ctx):
    result = asyncio.run(
        intel_tools.intel_classify_blind(
            target="10.10.10.50",
            ports=["2375"],
            services=["docker"],
            banners=[],
            os_hint="Linux",
        )
    )
    cats = result["categories"]
    top = cats[0]
    assert top["category"] == "docker-escape"
    assert top["confidence"] >= 0.85


# ── intel_kb_query (KB unavailable path) ────────────────────────────────────


def test_kb_query_unavailable_when_no_path(fresh_ctx):
    result = asyncio.run(intel_tools.intel_kb_query(query="smb enumeration"))
    assert result["available"] is False
    assert result["chunks"] == []
    assert result["reason"] == "kb_unavailable"


def test_kb_query_with_mocked_smart_module(fresh_ctx, monkeypatch):
    class FakeSmart:
        @staticmethod
        def smart_search(query, top_k=5):
            return (
                [
                    {"content": "Samba RCE via username map script", "metadata": {"source": "kb/sysn"}, "score": 0.92},
                    {"content": "MS17-010 EternalBlue", "metadata": {"source": "kb/htb"}, "score": 0.88},
                ],
                None,
            )

    monkeypatch.setattr(intel_tools, "_try_import_kb_smart", lambda: FakeSmart)
    result = asyncio.run(intel_tools.intel_kb_query(query="samba rce", top_k=3))
    assert result["available"] is True
    assert len(result["chunks"]) == 2
    assert result["chunks"][0]["score"] == 0.92


def test_kb_query_handles_smart_exception(fresh_ctx, monkeypatch):
    class FakeSmartBroken:
        @staticmethod
        def smart_search(query, top_k=5):
            raise RuntimeError("KB down")

    monkeypatch.setattr(intel_tools, "_try_import_kb_smart", lambda: FakeSmartBroken)
    result = asyncio.run(intel_tools.intel_kb_query(query="x"))
    assert result["available"] is False
    assert "error" in result["reason"]


# ── intel_cve_lookup (mocked stages) ────────────────────────────────────────


def test_cve_lookup_stages_present(fresh_ctx, monkeypatch):
    async def fake_nvd(product, version):
        return [{"cve_id": "CVE-2007-2447", "description": "Samba RCE", "published": "2007"}]

    monkeypatch.setattr(intel_tools, "_nvd_lookup", fake_nvd)
    monkeypatch.setattr(intel_tools, "_exploitdb_local_lookup", lambda p, v: [
        {"id": "16320", "title": "Samba 3.0.20 username map script (CVE-2007-2447)"}
    ])

    result = asyncio.run(intel_tools.intel_cve_lookup(product="samba", version="3.0.20"))
    assert "kb" in result["stages"]
    assert len(result["stages"]["nvd"]) == 1
    assert len(result["stages"]["exploitdb_local"]) == 1
    # Ranking: nvd CVE matched by edb title → priority 2
    ranked = result["ranked_cves"]
    assert ranked[0]["cve_id"] == "CVE-2007-2447"
    assert ranked[0]["has_exploitdb"] is True


def test_cve_lookup_handles_nvd_failure(fresh_ctx, monkeypatch):
    async def fake_nvd_fail(product, version):
        return []

    monkeypatch.setattr(intel_tools, "_nvd_lookup", fake_nvd_fail)
    monkeypatch.setattr(intel_tools, "_exploitdb_local_lookup", lambda p, v: [])

    result = asyncio.run(intel_tools.intel_cve_lookup(product="bogus", version="1.0"))
    assert result["stages"]["nvd"] == []
    assert result["ranked_cves"] == []


# ── intel_save_synthesis ─────────────────────────────────────────────────────


def test_save_synthesis_writes_intel_md_and_updates_state(fresh_ctx):
    content = "# Intel — Lame\n\n## Foothold\nSamba usermap_script (CVE-2007-2447)\n"
    result = asyncio.run(
        intel_tools.intel_save_synthesis(
            machine="lame",
            content_md=content,
            confidence="high",
            sources=["https://www.exploit-db.com/exploits/16320", "https://nvd.nist.gov/vuln/detail/CVE-2007-2447"],
        )
    )
    assert result["confidence"] == "high"
    assert result["sources_count"] == 2
    intel_path = Path(result["intel_path"])
    assert intel_path.exists()
    assert "CVE-2007-2447" in intel_path.read_text(encoding="utf-8")
    # State updated
    m = fresh_ctx.state_store.get_machine("lame")
    assert m is not None
    assert m.intel_confidence == "high"
    assert m.intel_path == str(intel_path)
    assert len(m.intel_sources) == 2


def test_save_synthesis_invalid_confidence(fresh_ctx):
    result = asyncio.run(
        intel_tools.intel_save_synthesis(
            machine="lame", content_md="x", confidence="bogus", sources=[]
        )
    )
    assert result["error"] == "invalid_confidence"
