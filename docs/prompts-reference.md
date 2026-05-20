# Kestrel MCP — Prompts Reference (v0.4)

The Kestrel MCP server registers 10 prompts. Each is callable via `get_prompt(<name>)`
from any MCP client. Phase prompts dynamically interpolate state.

| Prompt | Trigger | Content |
|--------|---------|---------|
| `kestrel_kickoff` | `/kestrel` start | Role + phases + narration + HITL rules + state summary |
| `p0_setup` | Entering p0 | Machine pick + intel + spawn + ping |
| `p1_recon` | Entering p1 | nmap + service enum + classify_blind |
| `p2_vector` | Entering p2 | KB + CVE + MSF lookup → ranked vectors + HITL |
| `p3_exploit` | Entering p3 | Run vector + open session + stuck handling |
| `p4_privesc` | Entering p4 | Enum + escalate (skip si foothold = root) |
| `p5_close` | Entering p5 | Flags + submit + writeup + cleanup + debrief |
| `intel_synthesis_template` | Writing intel.md | Structure + anti-spoiler rules + confidence rating |
| `hint_generation` | `/kestrel hint` | 1-line context-aware nudge, anti-spoiler |
| `debrief_template` | p5 HARD GATE | 5-section feedback.md template |

## Detail

### `kestrel_kickoff`
Source: `src/kestrel/mcp/prompts/kickoff.py`. Includes machine summary by reading `StateStore` at invocation time. Override of dummy in `server.py`.

### Phase prompts (`p0_setup` ... `p5_close`)
Source: `src/kestrel/mcp/prompts/phases.py`. Same Jinja2 template, parameterized by `PHASE_GUIDANCE` from `src/kestrel/mcp/tools/phase.py`. Each renders:

- Phase description
- Suggested tools (`narrate_emit`, `recon_nmap_scan`, etc.)
- HITL gates (e.g. `vector_confirm` for p2)
- Current phase/session/machine snapshot
- Next-step hint specific to this phase

### `intel_synthesis_template`
Source: `src/kestrel/mcp/prompts/synthesis.py`. Static content (no state interpolation). Used by the LLM when writing intel.md to enforce anti-spoiler discipline.

### `hint_generation`
Source: `src/kestrel/mcp/prompts/hint.py`. Reads `state.current_phase` + last narrate line from `estado.md` to give context. The LLM must produce **one sentence ≤ 25 words**, no CVE-IDs, no exploit names.

### `debrief_template`
Source: `src/kestrel/mcp/prompts/debrief.py`. Static content. 5-section feedback.md HARD GATE — p5_close cannot release the machine until this is written.

---

## Adding a new prompt

1. Create a file in `src/kestrel/mcp/prompts/`.
2. Use `@registry.prompt(name="...", description="...")` decorator on an async function returning `str`.
3. The function is auto-loaded by `_load_handler_modules()` at server start.
4. Add a test in `tests/test_prompts.py` asserting registration + content keywords.
