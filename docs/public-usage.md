# Kestrel — Public Usage (v0.4)

> Setup guide for using Kestrel from Claude Code or Claude Desktop.

---

## What you need

- **Python 3.11 or 3.12** with a virtualenv.
- **Claude Code** (CLI) or **Claude Desktop**.
- **An HTB account** with API token at `~/.htb/token` (chmod 600).
- **A Kali VM** reachable via SSH (defaults: host `kali-pentest`, user `kali`, key `~/.ssh/kali-pentest`).
- *(Optional)* **MSF RPC daemon** running on Kali (`scripts/kali-setup-msfrpc.sh` to install).
- *(Optional)* **pgvector KB** for intel lookups (set `KESTREL_KB_PATH`).

---

## Install

```bash
git clone https://github.com/CobaltoSec/kestrel.git
cd kestrel
python -m venv .venv
. .venv/bin/activate   # or .venv\Scripts\activate on Windows
pip install -e ".[kb,dev]"
```

Verify:

```bash
kestrel version
kestrel --help
kestrel debug tools-list
```

You should see `kestrel 0.4.0-dev` and ~70 tools listed.

---

## Configure

Generate the default config and edit:

```bash
kestrel config init
kestrel config show
```

Edit `~/.kestrel/config.toml` to point at your Kali VM + state directories.

Then create `~/.htb/token` (HTB Profile → Settings → API Key):

```bash
mkdir -p ~/.htb
echo '<your_jwt_token>' > ~/.htb/token
chmod 600 ~/.htb/token
```

---

## Register with Claude Code

Edit `~/.claude.json` (Windows: `%USERPROFILE%/.claude.json`):

```json
{
  "mcpServers": {
    "kestrel": {
      "command": "C:/opsec/runner/.venv/Scripts/kestrel-mcp.exe",
      "args": [
        "--state-dir", "C:/Proyectos/CobaltoSec/fleet/agents/htb/state",
        "--session-root", "C:/Proyectos/CobaltoSec/sectors/red-team/htb-sessions",
        "--log-level", "INFO"
      ]
    }
  }
}
```

POSIX variant: command is the venv's `kestrel-mcp`, args same.

Restart Claude Code. Verify:

```bash
claude mcp
# Should list "kestrel" with status "connected"
```

In a new CC session: `kestrel_ping` tool should be callable.

---

## Register with Claude Desktop

Edit `%APPDATA%/Claude/claude_desktop_config.json` (Windows) or
`~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "kestrel": {
      "command": "/path/to/kestrel-mcp"
    }
  }
}
```

Restart Claude Desktop. Look for the 🔌 icon next to the input — Kestrel should appear in the tool list.

---

## First session

In Claude Code or Claude Desktop:

```
/kestrel
```

This invokes the skill (CC) or kicks off a tool-use session (Desktop). The first thing the LLM does is call the `kestrel_kickoff` prompt — that returns the role, phases, and current state summary.

Then it'll call `phase_enter('p0_setup')` and `htb_list_machines(status='retired', difficulty='Easy')` for you to pick a machine.

From here it's narration + HITL gates only at critical moments (machine pick, vector confirm, submit, debrief).

---

## Troubleshooting

| Symptom | Check |
|---------|-------|
| MCP server doesn't appear | `claude mcp` → if missing, check JSON syntax in `~/.claude.json` |
| `kestrel-mcp` exits immediately | Run it standalone with `--log-level DEBUG` and read the traceback |
| Tools registered = 2 (only meta) | `_load_handler_modules()` failed silently — check `%LOCALAPPDATA%/kestrel/mcp.log` |
| HTB tool returns `htb_token_missing` | `cat ~/.htb/token` — file must exist and contain a valid JWT |
| Kali tool returns connection refused | `ssh -i ~/.ssh/kali-pentest kali@kali-pentest` — verify reachable + key works |
| MSF tool returns `rpc_unavailable` | `kestrel debug msfrpc-ping` — if down, run `scripts/kali-setup-msfrpc.sh` on Kali |
| KB tool returns `kb_unavailable` | `KESTREL_KB_PATH` env not set; this is optional, returns empty list gracefully |
| HITL marker not honored | The MCP client isn't recognizing `_hitl: true` — Claude Code 0.5+ handles it; older versions may need manual prompting |

---

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `KESTREL_STATE_DIR` | `~/.kestrel/state` or fleet path | last-cycle.json location |
| `KESTREL_SESSION_ROOT` | `~/.kestrel/sessions` or sectors path | session dirs |
| `KESTREL_KALI_HOST` | `kali-pentest` | SSH host for Kali |
| `KESTREL_KALI_USER` | `kali` | SSH user for Kali |
| `KESTREL_KALI_KEY` | `~/.ssh/kali-pentest` | SSH key for Kali |
| `KESTREL_HTB_VPN_CMD` | `bash ~/htb-vpn.sh` | OpenVPN wrapper on Kali |
| `KESTREL_MSF_HOST` | `127.0.0.1` | MSF RPC host |
| `KESTREL_MSF_PORT` | `55553` | MSF RPC port |
| `KESTREL_MSF_PASSWORD` | (from secret file) | MSF RPC password |
| `KESTREL_KB_PATH` | (unset → KB disabled) | Directory with `kb/query/smart.py` |
| `KESTREL_EXPLOITDB_CSV` | `~/.kestrel/exploitdb.csv` | Local exploit-db mirror |
| `KESTREL_PUBLISH_EMIT` | CobaltoSec path | publish-prep emit.py script |

---

## Update

```bash
cd kestrel
git pull
pip install -e ".[kb,dev]" --upgrade
```

Then restart Claude Code / Desktop. New tools auto-register on next server start.
