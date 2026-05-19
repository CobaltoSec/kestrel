"""Tests for kestrel.mcp.server boilerplate + registry."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from kestrel.mcp import context as mcp_context
from kestrel.mcp import registry, server


@pytest.fixture
def fresh_context(tmp_path: Path):
    """Reset registry + context for isolated test runs."""
    mcp_context.reset_context()
    ctx = mcp_context.ServerContext.from_paths(
        state_dir=tmp_path / "state",
        session_root=tmp_path / "sessions",
    )
    mcp_context.set_context(ctx)
    yield ctx
    mcp_context.reset_context()


# ── Registry primitives ──────────────────────────────────────────────────────


def test_registry_collects_tools_via_decorator():
    @registry.tool(name="dummy_tool_test", description="A dummy.", category="test")
    async def _t(x: str) -> dict:
        return {"got": x}

    spec = registry.get_tool("dummy_tool_test")
    assert spec is not None
    assert spec.name == "dummy_tool_test"
    assert spec.description == "A dummy."
    assert spec.category == "test"
    assert spec.input_schema["properties"]["x"]["type"] == "string"
    assert "x" in spec.input_schema["required"]


def test_registry_optional_param_not_required():
    @registry.tool(name="dummy_optional_test", description="")
    async def _t(message: str = "hi") -> dict:
        return {"got": message}

    spec = registry.get_tool("dummy_optional_test")
    assert spec is not None
    schema = spec.input_schema
    assert "required" not in schema or "message" not in schema.get("required", [])
    assert schema["properties"]["message"]["default"] == "hi"


def test_registry_prompt_decorator():
    @registry.prompt(name="dummy_prompt_test", description="A prompt.")
    async def _p() -> str:
        return "hello"

    spec = registry.get_prompt("dummy_prompt_test")
    assert spec is not None
    assert spec.description == "A prompt."


def test_registry_resource_decorator():
    @registry.resource(uri="kestrel://test/x", name="test_resource", description="")
    async def _r(uri: str) -> str:
        return json.dumps({"uri": uri})

    spec = registry.get_resource("kestrel://test/x")
    assert spec is not None
    assert spec.uri == "kestrel://test/x"
    assert spec.mime_type == "application/json"


# ── Dummy handlers registered in server module ───────────────────────────────


def test_kestrel_ping_registered():
    spec = registry.get_tool("kestrel_ping")
    assert spec is not None
    assert spec.category == "meta"


def test_kestrel_version_registered():
    spec = registry.get_tool("kestrel_version")
    assert spec is not None


def test_kestrel_config_resource_registered():
    spec = registry.get_resource("kestrel://config")
    assert spec is not None


def test_kestrel_kickoff_prompt_registered():
    spec = registry.get_prompt("kestrel_kickoff")
    assert spec is not None


# ── Handler invocation ───────────────────────────────────────────────────────


def test_ping_handler_returns_pong(fresh_context):
    from kestrel.mcp.server import _ping

    result = asyncio.run(_ping(message="hola"))
    assert result["pong"] == "hola"
    assert "ts" in result
    assert result["kestrel_version"]


def test_version_handler(fresh_context):
    from kestrel.mcp.server import _version

    result = asyncio.run(_version())
    assert "version" in result
    assert "tools" in result
    assert result["tools"] >= 2  # kestrel_ping + kestrel_version at minimum


def test_config_resource_returns_json(fresh_context):
    from kestrel.mcp.server import _config_resource

    result = asyncio.run(_config_resource("kestrel://config"))
    payload = json.loads(result)
    assert payload["version"]
    assert "state_dir" in payload
    assert "session_root" in payload
    assert payload["tool_count"] >= 2


def test_kickoff_prompt_includes_state(fresh_context):
    from kestrel.mcp.server import _kickoff

    text = asyncio.run(_kickoff())
    assert "Kestrel" in text
    assert "phases p0-p5" in text or "p0-p5" in text
    assert "no machines tracked yet" in text  # fresh state


# ── URI template matching ────────────────────────────────────────────────────


def test_uri_template_match_exact():
    assert server._uri_template_matches("kestrel://config", "kestrel://config")


def test_uri_template_match_with_var():
    assert server._uri_template_matches(
        "kestrel://session/{machine}/intel", "kestrel://session/lame/intel"
    )


def test_uri_template_no_match_different_path():
    assert not server._uri_template_matches(
        "kestrel://session/{machine}/intel", "kestrel://session/lame/recon"
    )


def test_uri_template_no_match_different_length():
    assert not server._uri_template_matches(
        "kestrel://session/{machine}/intel", "kestrel://session/lame"
    )


# ── build_server returns valid Server ────────────────────────────────────────


def test_build_server_returns_mcp_server(fresh_context):
    from mcp.server import Server

    s = server.build_server()
    assert isinstance(s, Server)
    assert s.name == "kestrel"


def test_context_get_without_init_raises():
    mcp_context.reset_context()
    with pytest.raises(RuntimeError, match="not initialized"):
        mcp_context.get_context()
    # Restore for other tests
    mcp_context.set_context(mcp_context.ServerContext.from_paths())
