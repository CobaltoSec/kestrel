"""Tests for kestrel.mcp.resources.* — verify URIs registered + handlers respond."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry, server
from kestrel.mcp.server import _load_handler_modules
from kestrel.mcp.tools import state as state_tools


@pytest.fixture
def fresh_ctx_loaded(tmp_path: Path):
    mcp_context.reset_context()
    ctx = mcp_context.ServerContext.from_paths(
        state_dir=tmp_path / "state",
        session_root=tmp_path / "sessions",
    )
    mcp_context.set_context(ctx)
    _load_handler_modules()
    yield ctx
    mcp_context.reset_context()


EXPECTED_URIS = (
    "kestrel://config",
    "kestrel://state/last-cycle",
    "kestrel://state/sessions-jsonl",
    "kestrel://state/profile",
    "kestrel://session/{machine}/intel",
    "kestrel://session/{machine}/findings",
    "kestrel://session/{machine}/writeup",
    "kestrel://session/{machine}/fingerprint",
    "kestrel://session/{machine}/recon",
    "kestrel://kb/categories",
)


def test_all_expected_resources_registered(fresh_ctx_loaded):
    uris = {r.uri for r in registry.all_resources()}
    missing = [u for u in EXPECTED_URIS if u not in uris]
    assert not missing, f"missing resources: {missing}"


def test_state_last_cycle_returns_valid_json(fresh_ctx_loaded):
    spec = registry.get_resource("kestrel://state/last-cycle")
    text = asyncio.run(spec.handler("kestrel://state/last-cycle"))
    data = json.loads(text)
    assert data["agent"] == "htb"
    assert "data" in data


def test_state_sessions_jsonl_no_session(fresh_ctx_loaded):
    spec = registry.get_resource("kestrel://state/sessions-jsonl")
    text = asyncio.run(spec.handler("kestrel://state/sessions-jsonl"))
    data = json.loads(text)
    assert data["error"] == "no_current_session"


def test_state_sessions_jsonl_with_events(fresh_ctx_loaded):
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "session_slug": "htb-test-lame"}
        )
    )
    fresh_ctx_loaded.state_store.set_current_phase("p3", session_slug="htb-test-lame")
    asyncio.run(
        state_tools.state_append_event(
            phase="p3", event="msf_session_opened", machine="lame", detail="lame-foothold"
        )
    )
    spec = registry.get_resource("kestrel://state/sessions-jsonl")
    text = asyncio.run(spec.handler("kestrel://state/sessions-jsonl"))
    data = json.loads(text)
    assert data["session"] == "htb-test-lame"
    assert len(data["events"]) == 1


def test_state_profile_missing(fresh_ctx_loaded):
    spec = registry.get_resource("kestrel://state/profile")
    text = asyncio.run(spec.handler("kestrel://state/profile"))
    data = json.loads(text)
    assert data["error"] == "profile_not_fetched"


def test_state_profile_present(fresh_ctx_loaded):
    (fresh_ctx_loaded.state_dir / "profile.json").write_text(
        json.dumps({"name": "Cobalt0", "rank": "Hacker"}), encoding="utf-8"
    )
    spec = registry.get_resource("kestrel://state/profile")
    text = asyncio.run(spec.handler("kestrel://state/profile"))
    data = json.loads(text)
    assert data["name"] == "Cobalt0"


def test_session_intel_read(fresh_ctx_loaded):
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "session_slug": "htb-test-lame"}
        )
    )
    session_dir = fresh_ctx_loaded.session_root / "htb-test-lame"
    session_dir.mkdir(parents=True, exist_ok=True)
    (session_dir / "intel.md").write_text("# Lame intel\nSamba 3.0.20", encoding="utf-8")
    # Resource lookup via template match
    uri = "kestrel://session/lame/intel"
    spec = registry.get_resource(uri)
    if spec is None:
        # Fall back to template-aware match
        for r in registry.all_resources():
            if server._uri_template_matches(r.uri, uri):
                spec = r
                break
    assert spec is not None
    text = asyncio.run(spec.handler(uri))
    assert "Samba 3.0.20" in text


def test_session_intel_machine_not_tracked(fresh_ctx_loaded):
    uri = "kestrel://session/ghost/intel"
    # Find template handler
    for r in registry.all_resources():
        if server._uri_template_matches(r.uri, uri):
            text = asyncio.run(r.handler(uri))
            data = json.loads(text)
            assert data["error"] == "machine_not_tracked"
            return
    pytest.fail("no template matched")


def test_session_recon_lists_files(fresh_ctx_loaded):
    asyncio.run(
        state_tools.state_write_machine(
            machine="lame", patch={"machine_id": 1, "session_slug": "htb-test-lame"}
        )
    )
    recon_dir = fresh_ctx_loaded.session_root / "htb-test-lame" / "recon" / "nmap"
    recon_dir.mkdir(parents=True, exist_ok=True)
    (recon_dir / "scan.xml").write_text("<nmaprun/>", encoding="utf-8")
    uri = "kestrel://session/lame/recon"
    for r in registry.all_resources():
        if server._uri_template_matches(r.uri, uri):
            text = asyncio.run(r.handler(uri))
            data = json.loads(text)
            assert data["file_count"] == 1
            assert "scan.xml" in data["files"][0]["path"]
            return
    pytest.fail("no template matched")


def test_kb_categories_returns_rules(fresh_ctx_loaded):
    spec = registry.get_resource("kestrel://kb/categories")
    text = asyncio.run(spec.handler("kestrel://kb/categories"))
    data = json.loads(text)
    assert data["count"] >= 5
    cat_names = {c["category"] for c in data["categories"]}
    assert "smb-exploit" in cat_names
    assert "ad-abuse" in cat_names
