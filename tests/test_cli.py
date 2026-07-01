"""Tests for kestrel.cli — typer commands invoked via CliRunner."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from kestrel.cli import app


@pytest.fixture
def runner():
    return CliRunner()


def test_version_command(runner):
    res = runner.invoke(app, ["version"])
    assert res.exit_code == 0
    assert "kestrel" in res.stdout


def test_agent_command_no_api_key(runner, monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    res = runner.invoke(app, ["agent", "kobold"])
    assert res.exit_code == 1
    assert "ANTHROPIC_API_KEY" in res.output


def test_config_init_creates_file(runner, tmp_path):
    cfg_path = tmp_path / "config.toml"
    res = runner.invoke(app, ["config", "init", "--path", str(cfg_path)])
    assert res.exit_code == 0
    assert cfg_path.exists()
    assert "[paths]" in cfg_path.read_text(encoding="utf-8")


def test_config_init_no_overwrite_without_force(runner, tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text("existing", encoding="utf-8")
    res = runner.invoke(app, ["config", "init", "--path", str(cfg_path)])
    assert res.exit_code == 1
    assert "exists" in res.stdout
    # Content preserved
    assert cfg_path.read_text(encoding="utf-8") == "existing"


def test_config_init_force_overwrites(runner, tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text("old", encoding="utf-8")
    res = runner.invoke(app, ["config", "init", "--path", str(cfg_path), "--force"])
    assert res.exit_code == 0
    assert "[paths]" in cfg_path.read_text(encoding="utf-8")


def test_config_show_missing(runner, tmp_path):
    cfg_path = tmp_path / "missing.toml"
    res = runner.invoke(app, ["config", "show", "--path", str(cfg_path)])
    assert res.exit_code == 1
    assert "not found" in res.stdout


def test_config_show_renders_contents(runner, tmp_path):
    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text("[hello]\nworld=true\n", encoding="utf-8")
    res = runner.invoke(app, ["config", "show", "--path", str(cfg_path)])
    assert res.exit_code == 0
    assert "[hello]" in res.stdout


def test_state_show_top_level(runner, tmp_path, monkeypatch):
    monkeypatch.setenv("KESTREL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("KESTREL_SESSION_ROOT", str(tmp_path / "sessions"))
    res = runner.invoke(app, ["state", "show"])
    assert res.exit_code == 0
    data = json.loads(res.stdout)
    assert data["agent"] == "htb"


def test_state_show_specific_machine_missing(runner, tmp_path, monkeypatch):
    monkeypatch.setenv("KESTREL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("KESTREL_SESSION_ROOT", str(tmp_path / "sessions"))
    res = runner.invoke(app, ["state", "show", "--machine", "ghost"])
    assert res.exit_code == 1


def test_debug_tools_list_default(runner, tmp_path, monkeypatch):
    monkeypatch.setenv("KESTREL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("KESTREL_SESSION_ROOT", str(tmp_path / "sessions"))
    res = runner.invoke(app, ["debug", "tools-list"])
    assert res.exit_code == 0
    # ≥50 tools registered (we have 70)
    out_text = res.stdout
    # Count lines like "  [category] tool_name — ..."
    tool_lines = [ln for ln in out_text.splitlines() if ln.startswith("  [")]
    assert len(tool_lines) >= 50


def test_debug_tools_list_filter_by_category(runner, tmp_path, monkeypatch):
    monkeypatch.setenv("KESTREL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("KESTREL_SESSION_ROOT", str(tmp_path / "sessions"))
    res = runner.invoke(app, ["debug", "tools-list", "--category", "htb"])
    assert res.exit_code == 0
    # Only htb tools
    lines = [ln for ln in res.stdout.splitlines() if ln.startswith("  [")]
    assert all("[htb]" in ln for ln in lines)
    assert len(lines) == 6


def test_status_no_session_errors(runner, tmp_path, monkeypatch):
    monkeypatch.setenv("KESTREL_STATE_DIR", str(tmp_path / "state"))
    monkeypatch.setenv("KESTREL_SESSION_ROOT", str(tmp_path / "sessions"))
    res = runner.invoke(app, ["status"])
    assert res.exit_code == 1
    assert "current_session" in res.stdout
