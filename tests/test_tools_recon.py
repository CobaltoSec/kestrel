"""Tests for kestrel.mcp.tools.recon — nmap/web/smb/dns/ldap enum (mocked via_kali)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from kestrel.mcp import context as mcp_context
from kestrel.mcp.tools import recon as recon_tools
from kestrel.mcp.tools import state as state_tools
from kestrel.transport.base import ExecResult


NMAP_XML_SAMPLE = """<?xml version="1.0"?>
<nmaprun>
<host>
<status state="up"/>
<address addr="10.10.10.3"/>
<ports>
<port protocol="tcp" portid="139">
<state state="open"/>
<service name="netbios-ssn" product="Samba" version="3.0.20-Debian"/>
</port>
<port protocol="tcp" portid="445">
<state state="open"/>
<service name="microsoft-ds" product="Samba" version="3.0.20-Debian"/>
</port>
</ports>
</host>
</nmaprun>"""


@pytest.fixture
def fresh_ctx(tmp_path: Path):
    mcp_context.reset_context()
    ctx = mcp_context.ServerContext.from_paths(
        state_dir=tmp_path / "state",
        session_root=tmp_path / "sessions",
    )
    mcp_context.set_context(ctx)
    # Pre-create a machine for artifact persistence tests
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "session_slug": "htb-test-lame"}
        )
    )
    yield ctx
    mcp_context.reset_context()


@pytest.fixture
def mock_via_kali(monkeypatch):
    calls: list[tuple[str, float]] = []
    return_value = {"result": ExecResult(stdout="", stderr="", rc=0, duration_s=0.1)}

    def fake_via_kali(cmd: str, timeout: float = 120.0, **kwargs):
        calls.append((cmd, timeout))
        return return_value["result"]

    monkeypatch.setattr("kestrel.mcp.tools.recon.kali_proxy.via_kali", fake_via_kali)
    return {"calls": calls, "return": return_value}


# ── nmap parsing ────────────────────────────────────────────────────────────


def test_nmap_xml_parses_ports(fresh_ctx):
    parsed = recon_tools._parse_nmap_xml(NMAP_XML_SAMPLE)
    assert parsed["host_count"] == 1
    host = parsed["hosts"][0]
    assert host["address"] == "10.10.10.3"
    assert host["status"] == "up"
    assert len(host["ports"]) == 2
    p139 = next(p for p in host["ports"] if p["port"] == 139)
    assert p139["service"] == "netbios-ssn"
    assert p139["product"] == "Samba"
    assert p139["version"] == "3.0.20-Debian"


def test_nmap_xml_parse_error_returns_empty(fresh_ctx):
    parsed = recon_tools._parse_nmap_xml("<not xml")
    assert "parse_error" in parsed
    assert parsed["hosts"] == []


# ── recon_nmap_scan ──────────────────────────────────────────────────────────


def test_recon_nmap_scan_quick_profile(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(
        stdout=NMAP_XML_SAMPLE, stderr="", rc=0, duration_s=12.3
    )
    result = asyncio.run(recon_tools.recon_nmap_scan(target="10.10.10.3", profile="quick"))
    assert result["rc"] == 0
    assert result["summary"]["host_count"] == 1
    # Check the cmd looks sensible
    cmd = mock_via_kali["calls"][0][0]
    assert "nmap" in cmd
    assert "10.10.10.3" in cmd
    assert "--top-ports=1000" in cmd


def test_recon_nmap_scan_invalid_profile(fresh_ctx, mock_via_kali):
    result = asyncio.run(recon_tools.recon_nmap_scan(target="10.10.10.3", profile="bogus"))
    assert result["error"] == "invalid_profile"
    assert "quick" in result["valid"]


def test_recon_nmap_scan_full_profile(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(
        stdout=NMAP_XML_SAMPLE, stderr="", rc=0, duration_s=60.0
    )
    asyncio.run(recon_tools.recon_nmap_scan(target="10.10.10.3", profile="full"))
    cmd = mock_via_kali["calls"][0][0]
    assert "-p-" in cmd
    assert "-sV" in cmd


def test_recon_nmap_scan_persists_artifact(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(
        stdout=NMAP_XML_SAMPLE, stderr="", rc=0, duration_s=10.0
    )
    result = asyncio.run(
        recon_tools.recon_nmap_scan(target="10.10.10.3", profile="quick", machine="lame")
    )
    assert result["artifact"] is not None
    assert Path(result["artifact"]).exists()
    content = Path(result["artifact"]).read_text(encoding="utf-8")
    assert "10.10.10.3" in content


def test_recon_nmap_scan_custom_ports(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(
        stdout=NMAP_XML_SAMPLE, stderr="", rc=0, duration_s=2.0
    )
    asyncio.run(
        recon_tools.recon_nmap_scan(target="10.10.10.3", profile="quick", ports="22,80,443")
    )
    cmd = mock_via_kali["calls"][0][0]
    assert "-p 22,80,443" in cmd


# ── recon_web_fingerprint ────────────────────────────────────────────────────


def test_recon_web_fingerprint_parses_headers(fresh_ctx, mock_via_kali):
    sample = (
        "HTTP/1.1 200 OK\r\n"
        "Server: nginx/1.18\r\n"
        "X-Powered-By: PHP/7.4\r\n"
        "---BODY---\n"
        "<html><head><title>Welcome</title></head></html>"
    )
    mock_via_kali["return"]["result"] = ExecResult(
        stdout=sample, stderr="", rc=0, duration_s=0.5
    )
    result = asyncio.run(recon_tools.recon_web_fingerprint(target="10.10.10.3", port=80))
    assert result["server"] == "nginx/1.18"
    assert result["powered_by"] == "PHP/7.4"
    assert result["title"] == "Welcome"


def test_recon_web_fingerprint_https_scheme(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(stdout="", stderr="", rc=0, duration_s=0.1)
    asyncio.run(recon_tools.recon_web_fingerprint(target="10.10.10.3", port=443))
    cmd = mock_via_kali["calls"][0][0]
    assert "https://10.10.10.3:443" in cmd


# ── recon_smb_enum ───────────────────────────────────────────────────────────


def test_recon_smb_enum_extracts_shares(fresh_ctx, mock_via_kali):
    sample = (
        "=== smbclient -L ===\n"
        "        Sharename       Type      Comment\n"
        "        ---------       ----      -------\n"
        "        print$          Disk      Printer Drivers\n"
        "        tmp             Disk      oh noes!\n"
        "        IPC$            IPC       IPC Service\n"
    )
    mock_via_kali["return"]["result"] = ExecResult(
        stdout=sample, stderr="", rc=0, duration_s=3.0
    )
    result = asyncio.run(recon_tools.recon_smb_enum(target="10.10.10.3"))
    assert "print$" in result["shares_detected"]
    assert "tmp" in result["shares_detected"]
    assert "IPC$" in result["shares_detected"]


# ── recon_dns_enum ───────────────────────────────────────────────────────────


def test_recon_dns_enum_invokes_dig(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(
        stdout="ns1.example.com.\n", stderr="", rc=0, duration_s=1.0
    )
    result = asyncio.run(recon_tools.recon_dns_enum(target="10.10.10.3", domain="example.com"))
    cmd = mock_via_kali["calls"][0][0]
    assert "dig" in cmd
    assert "axfr" in cmd
    assert "example.com" in cmd
    assert result["domain"] == "example.com"


# ── recon_ldap_enum ──────────────────────────────────────────────────────────


def test_recon_ldap_enum_extracts_naming_contexts(fresh_ctx, mock_via_kali):
    sample = (
        "namingContexts: DC=cobaltolab,DC=local\n"
        "namingContexts: CN=Configuration,DC=cobaltolab,DC=local\n"
    )
    mock_via_kali["return"]["result"] = ExecResult(
        stdout=sample, stderr="", rc=0, duration_s=1.5
    )
    result = asyncio.run(recon_tools.recon_ldap_enum(target="10.10.10.141"))
    assert len(result["naming_contexts"]) == 2
    assert "DC=cobaltolab,DC=local" in result["naming_contexts"]


# ── recon_service_probe ──────────────────────────────────────────────────────


def test_recon_service_probe_builds_cmd(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(
        stdout=NMAP_XML_SAMPLE, stderr="", rc=0, duration_s=5.0
    )
    asyncio.run(
        recon_tools.recon_service_probe(target="10.10.10.3", port=445, service_hint="smb-vuln")
    )
    cmd = mock_via_kali["calls"][0][0]
    assert "-sV -sC" in cmd
    assert "default,smb-vuln" in cmd
    assert "-p 445" in cmd


# ── IMP-01 + IMP-08: NMAP_PROFILES improvements ─────────────────────────────


def test_nmap_profiles_full_contains_host_timeout():
    assert "--host-timeout" in recon_tools.NMAP_PROFILES["full"]


def test_nmap_profiles_has_os_detect():
    assert "os_detect" in recon_tools.NMAP_PROFILES


def test_nmap_profiles_os_detect_has_osscan_guess():
    assert "--osscan-guess" in recon_tools.NMAP_PROFILES["os_detect"]


def test_nmap_profiles_udp_has_max_rtt_timeout():
    assert "--max-rtt-timeout" in recon_tools.NMAP_PROFILES["udp"]


# ── IMP-08: _run_kali() adds timeout prefix for heavy commands ───────────────


def test_run_kali_prefixes_nmap_with_timeout(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(
        stdout=NMAP_XML_SAMPLE, stderr="", rc=0, duration_s=10.0
    )
    asyncio.run(recon_tools.recon_nmap_scan(target="10.10.10.3", profile="quick"))
    cmd = mock_via_kali["calls"][0][0]
    # _run_kali should have prefixed with "timeout Ns nmap ..."
    assert cmd.startswith("timeout ") and "nmap" in cmd


def test_run_kali_timeout_prefix_value_is_safe_secs(fresh_ctx, mock_via_kali):
    """The timeout prefix should be timeout - 30 seconds (floor 30)."""
    mock_via_kali["return"]["result"] = ExecResult(
        stdout=NMAP_XML_SAMPLE, stderr="", rc=0, duration_s=5.0
    )
    # recon_nmap_scan calls _run_kali with timeout=900.0
    asyncio.run(recon_tools.recon_nmap_scan(target="10.10.10.3", profile="quick"))
    cmd = mock_via_kali["calls"][0][0]
    # "timeout 870s nmap ..."
    assert "timeout 870s" in cmd


# ── IMP-12: infrastructure_error in _run_kali result ────────────────────────


def test_run_kali_propagates_infrastructure_error(fresh_ctx, mock_via_kali):
    mock_via_kali["return"]["result"] = ExecResult(
        stdout="", stderr="kali_unreachable:connect_failed", rc=-1,
        duration_s=0.0, infrastructure_error=True,
    )
    result = asyncio.run(recon_tools.recon_nmap_scan(target="10.10.10.3", profile="quick"))
    # The raw result from _run_kali should carry infrastructure_error hint
    # recon_nmap_scan returns the top-level result; we verify no exception was raised
    assert result["rc"] == -1
