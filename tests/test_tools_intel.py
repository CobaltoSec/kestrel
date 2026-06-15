"""Tests for kestrel.mcp.tools.intel — classify/kb_query/cve_lookup/save_synthesis/next_step/lolbin."""

from __future__ import annotations

import asyncio
import json
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


# ── intel_next_step ──────────────────────────────────────────────────────────


class FakeSmartNextStep:
    @staticmethod
    def smart_search(query, top_k=5):
        return (
            [
                {
                    "content": "sudo find / -exec /bin/sh \\; — SUID find privesc",
                    "metadata": {"source": "gtfobins/find"},
                    "score": 0.91,
                },
                {
                    "content": "python3 -c 'import os; os.setuid(0); os.system(\"/bin/bash\")'",
                    "metadata": {"source": "gtfobins/python"},
                    "score": 0.88,
                },
                {
                    "content": "linpeas.sh — automated linux privesc enum script",
                    "metadata": {"source": "htb/privesc"},
                    "score": 0.75,
                },
            ],
            None,
        )


def test_next_step_returns_steps_structure(fresh_ctx, monkeypatch):
    monkeypatch.setattr(intel_tools, "_try_import_kb_smart", lambda: FakeSmartNextStep)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p4_privesc",
            tried=[],
            findings=["SUID find binary", "python3 available"],
            os_hint="linux",
            top_k=5,
        )
    )
    assert result["machine"] == "lame"
    assert result["phase"] == "p4_privesc"
    assert result["kb_available"] is True
    assert isinstance(result["steps"], list)
    assert len(result["steps"]) > 0
    step = result["steps"][0]
    assert "priority" in step
    assert "action" in step
    assert "command" in step
    assert "rationale" in step
    assert "source" in step
    assert step["priority"] == 1


def test_next_step_stuck_signals_key_present(fresh_ctx, monkeypatch):
    """stuck_signals always present in return dict even when no session_dir given."""
    monkeypatch.setattr(intel_tools, "_try_import_kb_smart", lambda: FakeSmartNextStep)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p4_privesc",
            tried=[],
            findings=[],
        )
    )
    assert "stuck_signals" in result
    assert isinstance(result["stuck_signals"], list)


def test_next_step_filters_tried(fresh_ctx, monkeypatch):
    monkeypatch.setattr(intel_tools, "_try_import_kb_smart", lambda: FakeSmartNextStep)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p4_privesc",
            tried=["sudo find / -exec /bin/sh"],
            findings=["SUID find binary"],
            os_hint="linux",
        )
    )
    commands = [s["command"] for s in result["steps"]]
    assert not any("find" in c and "exec" in c for c in commands)


def test_next_step_fallback_when_kb_unavailable(fresh_ctx, monkeypatch):
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p4_privesc",
            tried=[],
            findings=[],
            os_hint="linux",
        )
    )
    assert result["kb_available"] is False
    assert len(result["steps"]) > 0
    assert any(s["source"] == "builtin" for s in result["steps"])


def test_next_step_fallback_richer_p4(fresh_ctx, monkeypatch):
    """IMPROVEMENT-3: p4_privesc fallback now has ≥ 8 templates."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p4_privesc",
            tried=[],
            findings=[],
            top_k=10,
        )
    )
    assert len(result["steps"]) >= 8
    actions = {s["action"] for s in result["steps"]}
    assert "capabilities_check" in actions
    assert "cron_writable" in actions
    assert "path_hijack" in actions
    assert "group_check" in actions


def test_next_step_fallback_richer_p2(fresh_ctx, monkeypatch):
    """IMPROVEMENT-3: p2_enum fallback includes ICS/OT and docker templates."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p2_enum",
            tried=[],
            findings=[],
            top_k=10,
        )
    )
    assert len(result["steps"]) >= 8
    actions = {s["action"] for s in result["steps"]}
    assert "ics_ot_scan" in actions
    assert "docker_api_check" in actions
    assert "nifi_check" in actions


def test_next_step_fallback_richer_p3(fresh_ctx, monkeypatch):
    """IMPROVEMENT-3: p3_foothold has rce_verify + ssh_key_hunt + config_creds_hunt."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p3_foothold",
            tried=[],
            findings=[],
            top_k=10,
        )
    )
    actions = {s["action"] for s in result["steps"]}
    assert "rce_verify" in actions
    assert "ssh_key_hunt" in actions
    assert "config_creds_hunt" in actions


def test_next_step_stuck_shell_lost_prepended(fresh_ctx, monkeypatch, tmp_path):
    """IMPROVEMENT-1: shell_lost signal → reset_listener step prepended at priority 1."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    sdir = tmp_path / "sessions" / "lame"
    sdir.mkdir(parents=True)
    (sdir / "estado.md").write_text("shell dead — connection reset by peer")
    (sdir / "findings.md").write_text("")
    (sdir / "sessions.jsonl").write_text("")

    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p3_foothold",
            tried=[],
            findings=[],
            session_dir=str(sdir),
        )
    )
    assert "shell_lost" in result["stuck_signals"]
    assert result["steps"][0]["action"] == "reset_listener"
    assert result["steps"][0]["source"] == "stuck"
    assert result["steps"][0]["priority"] == 1


def test_next_step_stuck_hash_stuck_prepended(fresh_ctx, monkeypatch, tmp_path):
    """IMPROVEMENT-1: hash_stuck signal → escalate_gpu step prepended at priority 1."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    sdir = tmp_path / "sessions" / "lame"
    sdir.mkdir(parents=True)
    (sdir / "estado.md").write_text("hashcat exhausted — no match in 60 min")
    (sdir / "findings.md").write_text("")
    (sdir / "sessions.jsonl").write_text("")

    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p4_privesc",
            tried=[],
            findings=[],
            session_dir=str(sdir),
        )
    )
    assert "hash_stuck" in result["stuck_signals"]
    assert result["steps"][0]["action"] == "escalate_gpu"
    assert result["steps"][0]["priority"] == 1


def test_next_step_stuck_cred_exhausted_prepended(fresh_ctx, monkeypatch, tmp_path):
    """IMPROVEMENT-1: cred_exhausted → pivot_vector step prepended."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    sdir = tmp_path / "sessions" / "lame"
    sdir.mkdir(parents=True)
    (sdir / "estado.md").write_text("spray exhausted — ninguna cred funciona")
    (sdir / "findings.md").write_text("")
    (sdir / "sessions.jsonl").write_text("")

    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p3_foothold",
            tried=[],
            findings=[],
            session_dir=str(sdir),
        )
    )
    assert "cred_exhausted" in result["stuck_signals"]
    assert result["steps"][0]["action"] == "pivot_vector"
    assert result["steps"][0]["priority"] == 1


def test_next_step_no_stuck_signals_when_dir_missing(fresh_ctx, monkeypatch):
    """IMPROVEMENT-1 fallback: nonexistent session_dir → no stuck signals, normal flow."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p2_enum",
            tried=[],
            findings=[],
            session_dir="/nonexistent/path/session",
        )
    )
    assert result["stuck_signals"] == []
    assert len(result["steps"]) > 0


def test_next_step_query_includes_phase_and_findings(fresh_ctx, monkeypatch):
    captured: list[str] = []

    class CapturingFake:
        @staticmethod
        def smart_search(query, top_k=5):
            captured.append(query)
            return ([], None)

    monkeypatch.setattr(intel_tools, "_try_import_kb_smart", lambda: CapturingFake)
    asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p3_foothold",
            tried=[],
            findings=["Samba 3.0.20"],
            os_hint="linux",
        )
    )
    assert len(captured) == 1
    query = captured[0]
    assert "foothold" in query
    assert "Samba" in query or "samba" in query.lower()
    assert "linux" in query


def test_next_step_priority_renumbered_after_filter(fresh_ctx, monkeypatch):
    monkeypatch.setattr(intel_tools, "_try_import_kb_smart", lambda: FakeSmartNextStep)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p4_privesc",
            tried=["sudo find / -exec /bin/sh"],
            findings=[],
        )
    )
    priorities = [s["priority"] for s in result["steps"]]
    assert priorities == list(range(1, len(priorities) + 1))


def test_next_step_empty_machine_returns_dict(fresh_ctx, monkeypatch):
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="unknown_box",
            current_phase="p2_enum",
            tried=[],
            findings=[],
        )
    )
    assert "steps" in result
    assert "query_used" in result


# ── IMPROVEMENT-2: Jaccard similarity unit tests ──────────────────────────────


def test_jaccard_similarity_identical():
    a = {"sudo", "-l", "2>/dev/null"}
    assert intel_tools._jaccard_similarity(a, a) == 1.0


def test_jaccard_similarity_disjoint():
    a = {"sudo", "-l"}
    b = {"nmap", "-sV"}
    assert intel_tools._jaccard_similarity(a, b) == 0.0


def test_jaccard_similarity_partial():
    a = {"sudo", "-l"}
    b = {"sudo", "-l", "2>/dev/null"}
    # |A∩B|=2, |A∪B|=3
    assert abs(intel_tools._jaccard_similarity(a, b) - 2 / 3) < 1e-9


def test_jaccard_both_empty():
    assert intel_tools._jaccard_similarity(set(), set()) == 1.0


def test_chunk_matches_tried_jaccard_variant(monkeypatch):
    """IMPROVEMENT-2: 'sudo -l 2>/dev/null' matches tried 'sudo -l' via Jaccard ≥ 0.6."""
    chunk_text = "sudo -l 2>/dev/null — check sudo permissions"
    assert intel_tools._chunk_matches_tried(chunk_text, ["sudo -l"]) is True


def test_chunk_matches_tried_dissimilar_not_filtered(monkeypatch):
    """Unrelated tried command must NOT filter an unrelated chunk."""
    chunk_text = "getcap -r / 2>/dev/null — check linux capabilities"
    assert intel_tools._chunk_matches_tried(chunk_text, ["nmap -sV -p 80"]) is False


# ── lolbin_suggest ───────────────────────────────────────────────────────────


class FakeSmartLolbin:
    @staticmethod
    def smart_search(query, top_k=5):
        if "find" in query:
            return (
                [{"content": "find / -exec /bin/sh \\;", "metadata": {"source": "gtfobins"}, "score": 0.93}],
                None,
            )
        if "vim" in query:
            return (
                [{"content": ":!/bin/bash — vim shell escape", "metadata": {"source": "gtfobins"}, "score": 0.89}],
                None,
            )
        return ([], None)


def test_lolbin_suggest_structure(fresh_ctx, monkeypatch):
    monkeypatch.setattr(intel_tools, "_try_import_kb_smart", lambda: FakeSmartLolbin)
    result = asyncio.run(
        intel_tools.lolbin_suggest(
            binaries=["find", "vim", "curl"],
            context="SUID",
            os_hint="linux",
            top_k_per_binary=2,
        )
    )
    assert "suggestions" in result
    assert "binaries_with_hits" in result
    assert "binaries_queried" in result
    assert set(result["binaries_queried"]) == {"find", "vim", "curl"}
    assert "find" in result["suggestions"]
    assert "vim" in result["suggestions"]
    assert "curl" in result["suggestions"]


def test_lolbin_suggest_hits_populated(fresh_ctx, monkeypatch):
    monkeypatch.setattr(intel_tools, "_try_import_kb_smart", lambda: FakeSmartLolbin)
    result = asyncio.run(
        intel_tools.lolbin_suggest(binaries=["find", "vim"], context="sudo nopasswd")
    )
    assert "find" in result["binaries_with_hits"]
    assert "vim" in result["binaries_with_hits"]
    find_tech = result["suggestions"]["find"][0]
    assert "technique" in find_tech
    assert "command" in find_tech
    assert "source" in find_tech


def test_lolbin_suggest_no_hits_binary_absent_from_hits(fresh_ctx, monkeypatch):
    monkeypatch.setattr(intel_tools, "_try_import_kb_smart", lambda: FakeSmartLolbin)
    result = asyncio.run(
        intel_tools.lolbin_suggest(binaries=["curl"], context="SUID", os_hint="linux")
    )
    assert "curl" not in result["binaries_with_hits"]
    assert result["suggestions"]["curl"] == []


def test_lolbin_suggest_empty_binaries(fresh_ctx, monkeypatch):
    result = asyncio.run(intel_tools.lolbin_suggest(binaries=[]))
    assert result["suggestions"] == {}
    assert result["binaries_with_hits"] == []
    assert result["binaries_queried"] == []


def test_lolbin_suggest_kb_unavailable_fallback(fresh_ctx, monkeypatch):
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    result = asyncio.run(
        intel_tools.lolbin_suggest(binaries=["python3", "nc"], context="SUID")
    )
    assert "python3" in result["suggestions"]
    assert "nc" in result["suggestions"]
    assert result["binaries_with_hits"] == []


def test_lolbin_suggest_deduplicates_binaries(fresh_ctx, monkeypatch):
    """QW: duplicate binary names must only generate one KB query each."""
    call_log: list[str] = []

    class LoggingFake:
        @staticmethod
        def smart_search(query, top_k=5):
            call_log.append(query)
            return ([], None)

    monkeypatch.setattr(intel_tools, "_try_import_kb_smart", lambda: LoggingFake)
    result = asyncio.run(
        intel_tools.lolbin_suggest(binaries=["find", "find", "vim", "vim", "vim"])
    )
    # Only 2 unique binaries → 2 KB calls
    assert len(call_log) == 2
    assert result["binaries_queried"] == ["find", "vim"]


# ── QW: intel_cve_lookup concurrent execution ────────────────────────────────


def test_cve_lookup_concurrent_stages(fresh_ctx, monkeypatch):
    """QW: KB and NVD are now launched with asyncio.gather — both results present."""
    kb_called = []
    nvd_called = []

    async def fake_kb(query, top_k=5):
        kb_called.append(query)
        return {"available": True, "query": query, "chunks": []}

    async def fake_nvd(product, version):
        nvd_called.append((product, version))
        return [{"cve_id": "CVE-2007-2447", "description": "Samba RCE", "published": "2007"}]

    monkeypatch.setattr(intel_tools, "intel_kb_query", fake_kb)
    monkeypatch.setattr(intel_tools, "_nvd_lookup", fake_nvd)
    monkeypatch.setattr(intel_tools, "_exploitdb_local_lookup", lambda p, v: [])

    result = asyncio.run(intel_tools.intel_cve_lookup(product="samba", version="3.0.20"))
    assert len(kb_called) == 1
    assert len(nvd_called) == 1
    assert result["stages"]["nvd"][0]["cve_id"] == "CVE-2007-2447"


# ── IMP-02: intel_classify_blind async KB ────────────────────────────────────


def test_intel_classify_blind_kb_active_field(fresh_ctx, monkeypatch):
    """IMP-07b: result includes kb_active (bool) and kb_note (str or None)."""
    result = asyncio.run(
        intel_tools.intel_classify_blind(
            target="10.10.10.3",
            ports=["445"],
            services=["microsoft-ds"],
            banners=[],
        )
    )
    assert "kb_active" in result
    assert isinstance(result["kb_active"], bool)
    assert "kb_note" in result
    # KB unavailable in fresh_ctx (no KESTREL_KB_PATH) → kb_active=False, kb_note non-null
    assert result["kb_active"] is False
    assert result["kb_note"] is not None
    assert isinstance(result["kb_note"], str)


def test_intel_classify_blind_kb_active_true_when_chunks(fresh_ctx, monkeypatch):
    """IMP-07b: when KB returns chunks, kb_active=True and kb_note=None."""
    fake_chunks = [{"category": "smb-exploit", "text": "Samba RCE", "score": 0.9}]

    async def fake_to_thread(fn, *args, **kwargs):
        return fake_chunks

    monkeypatch.setattr(asyncio, "to_thread", fake_to_thread)

    result = asyncio.run(
        intel_tools.intel_classify_blind(
            target="10.10.10.3",
            ports=["445"],
            services=["microsoft-ds"],
            banners=[],
        )
    )
    assert result["kb_active"] is True
    assert result["kb_note"] is None


def test_intel_classify_blind_asyncio_not_blocking(fresh_ctx, monkeypatch):
    """IMP-02: query_kb is called via asyncio.to_thread (non-blocking path)."""
    thread_calls: list[str] = []
    original_to_thread = asyncio.to_thread

    async def tracking_to_thread(fn, *args, **kwargs):
        thread_calls.append(fn.__name__ if hasattr(fn, "__name__") else repr(fn))
        return []

    monkeypatch.setattr(asyncio, "to_thread", tracking_to_thread)

    asyncio.run(
        intel_tools.intel_classify_blind(
            target="10.10.10.3",
            ports=["445"],
            services=["microsoft-ds"],
            banners=[],
        )
    )
    # query_kb must have been dispatched through to_thread
    assert any("query_kb" in call for call in thread_calls)


# ── IMP-10: p3a / p3b phase support ─────────────────────────────────────────


def test_intel_next_step_p3a_phase_accepted(fresh_ctx, monkeypatch):
    """IMP-10: p3a_pre_foothold is a valid phase — returns steps without error."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p3a_pre_foothold",
            tried=[],
            findings=["apache 2.4.49"],
            top_k=5,
        )
    )
    assert "steps" in result
    assert "phase" in result
    assert result["phase"] == "p3a_pre_foothold"
    assert len(result["steps"]) > 0
    actions = {s["action"] for s in result["steps"]}
    # p3a_pre_foothold has exploit/sqli/brute-focused steps
    assert any(a in actions for a in ("test_rce_endpoint", "searchsploit_service", "run_poc", "sqli_auto", "brute_web_login"))


def test_intel_next_step_p3b_phase_accepted(fresh_ctx, monkeypatch):
    """IMP-10: p3b_post_foothold is a valid phase — returns steps without error."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p3b_post_foothold",
            tried=[],
            findings=["got shell as www-data"],
            top_k=5,
        )
    )
    assert "steps" in result
    assert result["phase"] == "p3b_post_foothold"
    assert len(result["steps"]) > 0
    actions = {s["action"] for s in result["steps"]}
    assert any(a in actions for a in ("pty_upgrade", "fix_terminal", "basic_loot", "suid_search", "sudo_check"))


def test_intel_next_step_p3_foothold_still_works(fresh_ctx, monkeypatch):
    """IMP-10: original p3_foothold still resolves (backwards compat)."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p3_foothold",
            tried=[],
            findings=[],
            top_k=10,
        )
    )
    assert len(result["steps"]) > 0
    actions = {s["action"] for s in result["steps"]}
    assert "rce_verify" in actions


# ── IMP-17: auto_tried_merged from state ─────────────────────────────────────


def test_intel_next_step_tried_autoload(fresh_ctx, monkeypatch):
    """IMP-17: tried_credentials with auth_failed results are auto-merged into tried."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)

    # Seed state with two failed credentials
    from kestrel.mcp.tools import state as state_tools
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame",
            patch={
                "tried_credentials": [
                    {"user": "admin", "password": "password123", "service": "ssh", "result": "auth_failed", "ts": "2026-01-01T00:00:00Z"},
                    {"user": "root", "password": "toor", "service": "ssh", "result": "auth_failed", "ts": "2026-01-01T00:01:00Z"},
                    {"user": "admin", "password": "letmein", "service": "ssh", "result": "success", "ts": "2026-01-01T00:02:00Z"},
                ]
            },
        )
    )

    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p3_foothold",
            tried=[],
            findings=[],
        )
    )
    # Two auth_failed creds should have been merged
    assert result["auto_tried_merged"] >= 2
    assert "auto_tried_merged" in result


def test_intel_next_step_tried_autoload_no_state(fresh_ctx, monkeypatch):
    """IMP-17: auto_tried_merged=0 when machine has no tried_credentials in state."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="unknown_machine_xyz",
            current_phase="p2_enum",
            tried=[],
            findings=[],
        )
    )
    assert "auto_tried_merged" in result
    assert result["auto_tried_merged"] == 0


def test_intel_next_step_kb_active_field_present(fresh_ctx, monkeypatch):
    """IMP-07b: kb_active key always present in intel_next_step result."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p4_privesc",
            tried=[],
            findings=[],
        )
    )
    assert "kb_active" in result
    assert isinstance(result["kb_active"], bool)
    # KB unavailable → kb_active=False
    assert result["kb_active"] is False


# ── IMP-04: UDP step in p2_enum fallback ─────────────────────────────────────


def test_p2_enum_includes_udp_step(fresh_ctx, monkeypatch):
    """IMP-04: p2_enum fallback steps must include udp_top100_scan."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p2_enum",
            tried=[],
            findings=[],
        )
    )
    actions = [s["action"] for s in result["steps"]]
    assert "udp_top100_scan" in actions, f"udp_top100_scan missing from p2_enum steps: {actions}"


def test_p2_enum_udp_step_has_correct_command(fresh_ctx, monkeypatch):
    """IMP-04: UDP step command uses nmap -sU --top-ports 100."""
    monkeypatch.delenv("KESTREL_KB_PATH", raising=False)
    result = asyncio.run(
        intel_tools.intel_next_step(
            machine="lame",
            current_phase="p2_enum",
            tried=[],
            findings=[],
        )
    )
    udp_steps = [s for s in result["steps"] if s["action"] == "udp_top100_scan"]
    assert udp_steps, "No udp_top100_scan step found"
    cmd = udp_steps[0]["command"]
    assert "-sU" in cmd, f"UDP flag missing in cmd: {cmd}"
    assert "--top-ports" in cmd, f"--top-ports missing in cmd: {cmd}"


# ── IMP-03: auto-nuclei in intel_cve_lookup ──────────────────────────────────


def test_cve_lookup_auto_nuclei_skipped_when_no_target(fresh_ctx, monkeypatch):
    """IMP-03: without target, nuclei_auto_run=False and no nuclei call made."""
    async def fake_nvd(product, version):
        return [{"cve_id": "CVE-2025-29927", "description": "Next.js middleware bypass", "published": "2025"}]

    monkeypatch.setattr(intel_tools, "_nvd_lookup", fake_nvd)
    monkeypatch.setattr(intel_tools, "_exploitdb_local_lookup", lambda p, v: [
        {"id": "99999", "title": "Next.js CVE-2025-29927 middleware bypass"}
    ])

    result = asyncio.run(
        intel_tools.intel_cve_lookup(product="next.js", version="15.0.3")
    )
    assert result["nuclei_auto_run"] is False
    assert result["nuclei_findings"] == []
    assert result["nuclei_finding_count"] == 0


def test_cve_lookup_auto_nuclei_fires_on_high_priority(fresh_ctx, monkeypatch):
    """IMP-03: when target provided + high-priority CVE, nuclei_auto_run=True."""
    from unittest.mock import AsyncMock, patch

    async def fake_nvd(product, version):
        return [{"cve_id": "CVE-2025-29927", "description": "Next.js middleware bypass", "published": "2025"}]

    monkeypatch.setattr(intel_tools, "_nvd_lookup", fake_nvd)
    monkeypatch.setattr(intel_tools, "_exploitdb_local_lookup", lambda p, v: [
        {"id": "99999", "title": "Next.js CVE-2025-29927 middleware bypass"}
    ])

    nuclei_called_with: list = []

    async def fake_nuclei_targeted(target, templates, machine=None, **kwargs):
        nuclei_called_with.append({"target": target, "templates": templates})
        return {"findings": [], "finding_count": 0}

    with patch("kestrel.mcp.tools.vuln.vuln_nuclei_targeted", new=fake_nuclei_targeted):
        result = asyncio.run(
            intel_tools.intel_cve_lookup(
                product="next.js",
                version="15.0.3",
                target="http://10.10.10.3:3000",
                machine="lame",
                auto_nuclei=True,
            )
        )

    assert result["nuclei_auto_run"] is True, f"Expected nuclei_auto_run=True, got {result}"
    assert len(nuclei_called_with) == 1, f"Expected 1 nuclei call, got {nuclei_called_with}"
    assert "CVE-2025-29927" in nuclei_called_with[0]["templates"]
