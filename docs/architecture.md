# Kestrel — Architecture v0.4

> v0.4 — MCP server pivot (RT-KESTREL-V04, 2026-05-20).
>
> v0.3 architecture preserved at `architecture.md` for reference. This document describes
> what changed in v0.4 and how the new layout works.

---

## What changed from v0.3

| Aspect | v0.3 | v0.4 |
|--------|------|------|
| Distribution | Claude Code skill (markdown phases) + scripts dispersos | **Pip-installable MCP server** + thin Claude Code skill |
| Execution | Skill delegates to `/pentest --mode lab` | **MCP tools native** — 70+ tools registered by category |
| LLM contract | Markdown prompts Claude interprets | **MCP protocol** — tool-use, resources, prompts (typed) |
| Tools | Bash scripts + python scripts | Python modules in `src/kestrel/core/` + MCP wrappers |
| State | Manual `state.json` writes | `StateStore` with filelock + atomic temp/rename |
| Transport | Inline SSH commands | `transport/` layer: ssh (paramiko), winrm (pypsrp), msf (pymetasploit3 RPC) |
| HITL | Markdown prompts asking Nico | `request_user_confirmation` tool with `_hitl` marker for client |
| Skill lines | 134 | **105 (thin wrapper)** |

---

## 5-Layer Model (v0.4)

```
┌─────────────────────────────────────────────────────────────┐
│  5. MCP PROTOCOL                                            │
│     stdio transport · list_tools / call_tool                │
│     list_prompts / get_prompt · list_resources / read       │
│     → client = Claude Code; future = any MCP-capable LLM    │
├─────────────────────────────────────────────────────────────┤
│  4. MEMORY                                                  │
│     estado.md · last-cycle.json (StateStore + filelock)     │
│     writeup.md · feedback.md · sessions.jsonl               │
│     KB synthesis · publish-hint                             │
├─────────────────────────────────────────────────────────────┤
│  3. EXECUTION                                               │
│     transport/ssh.py (Kali via paramiko, persistent)        │
│     transport/winrm.py (post-foothold Windows)              │
│     transport/msf.py (pymetasploit3 RPC — exploit/sessions) │
│     transport/kali_proxy.py (shared via_kali helper)        │
├─────────────────────────────────────────────────────────────┤
│  2. ORCHESTRATION                                           │
│     phases p0_setup → p1_recon → p2_vector → p3_exploit     │
│     → p4_privesc → p5_close                                 │
│     prompts/ — Jinja2 templates per phase                   │
│     narrate_emit · stuck_check · heartbeat_status           │
├─────────────────────────────────────────────────────────────┤
│  1. INTEL                                                   │
│     core/fingerprint.py (rules + KB auto-query)             │
│     intel_classify_blind · intel_cve_lookup (4-stage)       │
│     intel_kb_query (graceful fallback)                      │
│     intel_save_synthesis (anti-spoiler validation)          │
└─────────────────────────────────────────────────────────────┘
```

---

## MCP layout

```
src/kestrel/
├── __init__.py           # __version__ = "0.4.0-dev"
├── cli.py                # typer — kestrel {mcp,status,state,config,debug,version,agent}
├── mcp/
│   ├── server.py         # entrypoint kestrel-mcp (stdio transport)
│   ├── registry.py       # @tool / @prompt / @resource decorators + global registry
│   ├── context.py        # ServerContext (state_dir, session_root, sessions, state_store)
│   ├── tools/            # 15 modules — 70 tools across 19 categories
│   │   ├── state.py      # state_read/write/append/session_dir
│   │   ├── phase.py      # phase_current/enter (returns guidance)
│   │   ├── narrate.py    # narrate_emit (📡 🔍 💡 ➡)
│   │   ├── htb.py        # HTB API v4 (list/info/spawn/release/submit/profile)
│   │   ├── vpn.py        # htb-vpn.sh wrapper
│   │   ├── kali.py       # kali_status / kali_ping_target
│   │   ├── recon.py      # nmap (4 profiles), web/smb/dns/ldap enum, service probe
│   │   ├── intel.py      # classify_blind, kb_query, cve_lookup, save_synthesis
│   │   ├── vuln.py       # nuclei targeted/broad, exploit-db local, msf search
│   │   ├── creds.py      # default_check, password_spray, hash crack/recommend/status
│   │   ├── exploit.py    # run_msf (RPC), run_poc, web LFI/RCE, smb_psexec, winrm
│   │   ├── post.py       # linpeas/winpeas, enum, privesc heuristics (sudo/kernel/token/potato)
│   │   ├── ad.py         # bloodhound, kerberoast, asreproast, dcsync (impacket)
│   │   ├── session.py    # session_open/exec/close/list (transport handles)
│   │   ├── flag.py       # extract + validate (HTB 32-hex format)
│   │   ├── writeup.py    # generate (Jinja2), kb_synthesize, publish_hint
│   │   ├── heartbeat.py  # stuck_check, heartbeat_status (wraps core/)
│   │   └── hitl.py       # request_user_confirmation (_hitl marker contract)
│   ├── prompts/          # 5 modules — 10 prompts
│   │   ├── kickoff.py    # kestrel_kickoff (role + phases + narration + HITL)
│   │   ├── phases.py     # p0_setup..p5_close (with state context interpolation)
│   │   ├── synthesis.py  # intel_synthesis_template (anti-spoiler rules)
│   │   ├── hint.py       # hint_generation (1-line, context-aware)
│   │   └── debrief.py    # debrief_template (5-section HARD GATE)
│   └── resources/        # 3 modules — 10 URIs
│       ├── state.py      # kestrel://state/{last-cycle,sessions-jsonl,profile}
│       ├── session.py    # kestrel://session/{machine}/{intel,recon,findings,fingerprint,writeup}
│       └── kb.py         # kestrel://kb/categories (RULES catalog)
├── core/                 # Pure-python logic, testable in isolation
│   ├── fingerprint.py
│   ├── stuck.py
│   ├── heartbeat.py
│   ├── wordlist.py
│   ├── crack.py
│   └── ...
├── state/
│   ├── schema.py         # Pydantic models (LastCycle, MachineState, etc.)
│   └── store.py          # StateStore with filelock + atomic writes
├── transport/
│   ├── base.py           # Session ABC, SessionRegistry (thread-safe)
│   ├── ssh.py            # paramiko (Kali default)
│   ├── winrm.py          # pypsrp
│   ├── msf.py            # pymetasploit3 RPC
│   └── kali_proxy.py     # via_kali() global helper
└── agent/                # STUB v0.5 — public ReAct agent runner
```

---

## HITL contract (`request_user_confirmation`)

MCP tools cannot natively block on user input. The HITL contract uses a structured marker:

```json
{
  "_hitl": true,
  "question": "Pick exploit vector?",
  "options": ["samba_usermap", "ms17-010"],
  "context": "Samba 3.0.20 + 445/139 open",
  "instruction_to_llm": "Stop, present this question..."
}
```

The MCP client (Claude Code) recognizes the `_hitl` marker and pauses to ask the operator.
The operator's answer arrives as the LLM's next prompt — the loop continues.

---

## Phase flow

```
                    ┌─────────────────┐
                    │  /kestrel start │
                    └────────┬────────┘
                             │ invoke prompt kestrel_kickoff
                             ▼
                  ┌──────────────────────┐
                  │  phase_enter(p0)     │ ← machine_pick HITL
                  └──────────┬───────────┘
                             ▼
                  ┌──────────────────────┐
                  │  phase_enter(p1)     │ ← recon + classify (no HITL)
                  └──────────┬───────────┘
                             ▼
                  ┌──────────────────────┐
                  │  phase_enter(p2)     │ ← vector_confirm HITL
                  └──────────┬───────────┘
                             ▼
                  ┌──────────────────────┐
                  │  phase_enter(p3)     │ ← optional destructive HITL
                  └──────────┬───────────┘
                             │ stuck? → stuck_check → switch_vector → loop back
                             ▼
                  ┌──────────────────────┐
                  │  phase_enter(p4)     │ ← skip si foothold ya es root
                  └──────────┬───────────┘
                             ▼
                  ┌──────────────────────┐
                  │  phase_enter(p5)     │ ← submit_confirm + debrief HITL
                  └──────────────────────┘
```

---

## Compatibility with v0.3

- v0.3 phases markdown archived at `docs/v03-phases-archive/` (read-only reference).
- v0.3 scripts (`scripts/*.py`) remain as shim files importing from `src/kestrel/core/*` with `DeprecationWarning`. Removed in v0.5.
- Public agent runner (ReAct with Anthropic/OpenAI/Ollama providers) **deferred to v0.5**. In v0.4 the only supported client is Claude Code via MCP.

---

## What v0.4 doesn't yet have (→ v0.5)

- Public ReAct agent runner (Anthropic / OpenAI / Ollama providers).
- WinRM full coverage (currently best-effort, pypsrp unwired).
- CI E2E job actually running against a HTB target.
- TUI for the operator side (currently just `/kestrel status` JSON dump).
