"""Tests for kestrel.mcp.tools.vuln — nuclei/exploit_db/msf_search (mocked)."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from kestrel.mcp import context as mcp_context
from kestrel.mcp.tools import state as state_tools
from kestrel.mcp.tools import vuln as vuln_tools
from kestrel.transport.base import ExecResult


@pytest.fixture
def fresh_ctx(tmp_path: Path, monkeypatch):
    # Force exploit-db CSV path to a tmp location (not real ~/.kestrel)
    monkeypatch.setenv("KESTREL_EXPLOITDB_CSV", str(tmp_path / "exploitdb.csv"))
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
    vuln_tools._reset_msf_session_for_tests()
    yield ctx
    mcp_context.reset_context()
    vuln_tools._reset_msf_session_for_tests()


@pytest.fixture
def mock_via_kali(monkeypatch):
    calls: list[tuple[str, float]] = []
    return_value = {"result": ExecResult(stdout="", stderr="", rc=0, duration_s=0.1)}

    def fake(cmd: str, timeout: float = 120.0, **kwargs):
        calls.append((cmd, timeout))
        return return_value["result"]

    monkeypatch.setattr("kestrel.mcp.tools.vuln.kali_proxy.via_kali", fake)
    return {"calls": calls, "return": return_value}


# ── nuclei JSONL parsing ────────────────────────────────────────────────────


def test_parse_nuclei_jsonl_basic():
    sample = (
        '{"template-id":"CVE-2007-2447","info":{"severity":"critical"},"host":"10.10.10.3"}\n'
        '{"template-id":"samba-version","info":{"severity":"info"},"host":"10.10.10.3"}\n'
    )
    out = vuln_tools._parse_nuclei_jsonl(sample)
    assert len(out) == 2
    assert out[0]["template-id"] == "CVE-2007-2447"


def test_parse_nuclei_jsonl_skips_bad_lines():
    sample = '{"valid":1}\nnot json line\n{"valid":2}\n'
    out = vuln_tools._parse_nuclei_jsonl(sample)
    assert len(out) == 2


# ── vuln_nuclei_targeted ────────────────────────────────────────────────────


def test_nuclei_targeted_invokes_cmd_with_ids(fresh_ctx, mock_via_kali):
    sample = json.dumps({"template-id": "CVE-2007-2447", "info": {"severity": "critical"}, "host": "10.10.10.3"}) + "\n"
    mock_via_kali["return"]["result"] = ExecResult(stdout=sample, stderr="", rc=0, duration_s=4.2)
    result = asyncio.run(
        vuln_tools.vuln_nuclei_targeted(target="10.10.10.3", templates=["CVE-2007-2447", "samba"])
    )
    assert result["finding_count"] == 1
    assert result["findings"][0]["template-id"] == "CVE-2007-2447"
    cmd = mock_via_kali["calls"][0][0]
    # IMP-03: comma-separated, single -id flag
    assert "-id CVE-2007-2447,samba" in cmd
    assert "-jsonl" in cmd


def test_nuclei_targeted_with_severity(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(stdout="", stderr="", rc=0, duration_s=1.0)
    asyncio.run(
        vuln_tools.vuln_nuclei_targeted(
            target="10.10.10.3", templates=["cves"], severity="critical"
        )
    )
    cmd = mock_via_kali["calls"][0][0]
    assert "-severity critical" in cmd


def test_nuclei_targeted_persists_artifact(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(stdout='{"x":1}\n', stderr="", rc=0, duration_s=1.0)
    result = asyncio.run(
        vuln_tools.vuln_nuclei_targeted(target="10.10.10.3", templates=["cves"], machine="lame")
    )
    assert result["artifact"] is not None
    assert Path(result["artifact"]).exists()


# ── vuln_nuclei_broad ───────────────────────────────────────────────────────


def test_nuclei_broad_default_severity(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(stdout="", stderr="", rc=0, duration_s=5.0)
    asyncio.run(vuln_tools.vuln_nuclei_broad(target="10.10.10.3"))
    cmd = mock_via_kali["calls"][0][0]
    assert "critical,high" in cmd


def test_nuclei_broad_custom_severity(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(stdout="", stderr="", rc=0, duration_s=5.0)
    asyncio.run(vuln_tools.vuln_nuclei_broad(target="10.10.10.3", severity="critical"))
    cmd = mock_via_kali["calls"][0][0]
    assert "-severity critical" in cmd
    assert "high" not in cmd.split("-severity")[1].split()[0]


# ── vuln_check_exploit_db ───────────────────────────────────────────────────


def test_exploit_db_csv_not_found(fresh_ctx):
    result = asyncio.run(vuln_tools.vuln_check_exploit_db(query="samba"))
    assert result["available"] is False
    assert result["reason"] == "csv_not_found"


def test_exploit_db_finds_matches(fresh_ctx, tmp_path):
    csv_path = Path(tmp_path / "exploitdb.csv")
    csv_path.write_text(
        'id,file,description,date_published\n'
        '16320,exploits/multiple/remote/16320.rb,"Samba 3.0.20 < 3.0.25rc3 username map script",2007-05-14\n'
        '40347,exploits/linux/remote/40347.rb,"Apache Cocoon RCE",2016-09-15\n',
        encoding="utf-8",
    )
    result = asyncio.run(vuln_tools.vuln_check_exploit_db(query="samba"))
    assert result["available"] is True
    assert result["count"] == 1
    assert result["results"][0]["id"] == "16320"


# ── vuln_msf_search ─────────────────────────────────────────────────────────


def test_msf_search_unavailable_when_no_rpc(fresh_ctx, monkeypatch):
    monkeypatch.setattr(vuln_tools, "_get_msf_session", lambda: None)
    result = asyncio.run(vuln_tools.vuln_msf_search(query="samba usermap"))
    assert result["available"] is False
    assert result["reason"] == "rpc_unavailable"


def test_msf_search_returns_modules(fresh_ctx, monkeypatch):
    class FakeSess:
        def search_modules(self, query):
            return [
                {"fullname": "exploit/multi/samba/usermap_script", "type": "exploit", "rank": "excellent", "name": "usermap_script"},
                {"fullname": "auxiliary/scanner/smb/smb_version", "type": "auxiliary", "rank": "normal", "name": "smb_version"},
            ]

    monkeypatch.setattr(vuln_tools, "_get_msf_session", lambda: FakeSess())
    result = asyncio.run(vuln_tools.vuln_msf_search(query="samba"))
    assert result["available"] is True
    assert result["count"] == 2
    assert result["modules"][0]["fullname"] == "exploit/multi/samba/usermap_script"


def test_msf_search_handles_exception(fresh_ctx, monkeypatch):
    class FakeBroken:
        def search_modules(self, query):
            raise ConnectionError("RPC connection refused")

    monkeypatch.setattr(vuln_tools, "_get_msf_session", lambda: FakeBroken())
    result = asyncio.run(vuln_tools.vuln_msf_search(query="x"))
    assert result["available"] is False
    assert "error" in result["reason"]


# ── IMP-03: nuclei comma-separated -id ──────────────────────────────────────


def test_nuclei_targeted_multi_templates_comma_separated(fresh_ctx, mock_via_kali):
    """IMP-03: multiple templates must produce a single -id CVE-A,CVE-B (not two -id flags)."""
    mock_via_kali["return"]["result"] = ExecResult(stdout="", stderr="", rc=0, duration_s=1.0)
    asyncio.run(
        vuln_tools.vuln_nuclei_targeted(target="10.10.10.3", templates=["CVE-A", "CVE-B"])
    )
    cmd = mock_via_kali["calls"][0][0]
    assert "-id CVE-A,CVE-B" in cmd
    # Ensure there is only one -id flag, not two separate ones
    assert cmd.count("-id ") == 1


def test_nuclei_targeted_single_template_no_comma(fresh_ctx, mock_via_kali):
    """Single template should still produce -id <name> without trailing comma."""
    mock_via_kali["return"]["result"] = ExecResult(stdout="", stderr="", rc=0, duration_s=1.0)
    asyncio.run(
        vuln_tools.vuln_nuclei_targeted(target="10.10.10.3", templates=["CVE-2007-2447"])
    )
    cmd = mock_via_kali["calls"][0][0]
    assert "-id CVE-2007-2447" in cmd
    assert "," not in cmd.split("-id ")[1].split()[0]


def test_nuclei_targeted_three_templates_comma_separated(fresh_ctx, mock_via_kali):
    """Three templates: -id t1,t2,t3 (still one flag)."""
    mock_via_kali["return"]["result"] = ExecResult(stdout="", stderr="", rc=0, duration_s=1.0)
    asyncio.run(
        vuln_tools.vuln_nuclei_targeted(target="10.10.10.3", templates=["t1", "t2", "t3"])
    )
    cmd = mock_via_kali["calls"][0][0]
    assert "-id t1,t2,t3" in cmd
    assert cmd.count("-id ") == 1
