"""Kestrel ReAct Agent — autonomous HTB engagement loop via Anthropic SDK.

Loop: observe → think → act → observe (repeat until owned / budget / max_iter).

Tool execution bridges the Anthropic tool_use protocol to the MCP tool Python
functions directly (no MCP transport — functions are imported and called async).

HITL gates: when the agent needs operator input, the loop prints to terminal
and blocks on input() — no MCP protocol involved.
"""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anthropic

from kestrel.agent.bridge import load_tools_for_anthropic
from kestrel.agent.metrics import RunMetrics


# Anthropic model for the agent (latest Sonnet by default)
DEFAULT_MODEL = "claude-sonnet-5"

# Hard limits
DEFAULT_BUDGET_TOKENS = 200_000
DEFAULT_MAX_ITERATIONS = 60

# Tools that signal flag submission (used to record timing)
_FLAG_SUBMIT_TOOLS = {"htb_submit_flag", "flag_validate"}

# System prompt for blind agent mode
_SYSTEM_BLIND = """\
You are Kestrel, an autonomous HackTheBox engagement agent. Your only goal: own the target machine.

## Engagement Phases
p0_setup   → pick target, classify surface, spawn machine, ping IP
p1_recon   → nmap full scan, web fingerprint, service enum, intel_classify_blind
p2_vector  → ranked attack vectors via intel_next_step + intel_cve_lookup; confirm with operator
p3_exploit → run confirmed vector, get foothold; open Kali session
p4_privesc → post_enum_system → lolbin_suggest → escalate (sudo/SUID/caps/kernel)
p5_close   → extract flags, submit, writeup_kb_synthesize, session_close

## Mandatory protocol
1. Start every new machine with: kali_vm_status → vpn_up → session_open → phase_enter("p0_setup")
2. Call phase_enter BEFORE using tools in that phase.
3. Call narrate_emit for every significant finding or action.
4. Call state_write_machine after: IP found, vector chosen, foothold obtained, flag obtained.
5. Call session_close at the end.

## HITL gates (operator confirmation required)
You CANNOT auto-answer these — the loop will pause and ask the operator:
- machine_pick: after listing machines, before spawning
- vector_confirm: before running any exploit
- submit_flag: before htb_submit_flag
- debrief: before cleanup

To trigger a gate, output ONLY this JSON on a line by itself (no other text on that line):
  {"_agent_hitl": true, "gate": "<gate_id>", "question": "<question>", "options": ["yes","no"]}

## Intelligence loop
- If 3 consecutive tools return no new information → call stuck_check; act on recommendation.
- If stuck_check.signals includes "rabbit_hole" → pivot vector immediately, don't retry.
- When unsure what to do next → intel_next_step(machine, current_phase, tried=[...], findings=[...])

## Blind mode
Do NOT use walkthroughs, writeups, or known solutions. Own it from first principles.
Leverage intel_kb_query and intel_cve_lookup for technique guidance — that's fair.

## Output format
Think briefly (1-3 sentences), then call 1-3 tools. Don't dump long reasoning blocks.
After each tool result, update your mental model and proceed.
"""


class ReActAgent:
    """Autonomous HTB engagement agent using Anthropic's tool_use protocol."""

    def __init__(
        self,
        machine: str,
        mode: str = "blind",
        provider: str = "anthropic",
        model: str = DEFAULT_MODEL,
        budget_tokens: int = DEFAULT_BUDGET_TOKENS,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        state_dir: Path | None = None,
        session_root: Path | None = None,
        api_key: str | None = None,
        verbose: bool = True,
    ) -> None:
        self.machine = machine
        self.mode = mode
        self.provider = provider
        self.model = model
        self.budget_tokens = budget_tokens
        self.max_iterations = max_iterations
        self.verbose = verbose

        # Resolve paths via MCP context (falls back to env / defaults)
        from kestrel.mcp import context as mcp_context
        from kestrel.mcp.server import _load_handler_modules

        ctx = mcp_context.ServerContext.from_paths(
            state_dir=str(state_dir) if state_dir else None,
            session_root=str(session_root) if session_root else None,
        )
        mcp_context.set_context(ctx)
        _load_handler_modules()

        self._ctx = ctx
        self._state_dir = ctx.state_dir
        self._runs_dir = self._state_dir / "runs"
        self._client = anthropic.Anthropic(api_key=api_key)
        self._tools = load_tools_for_anthropic()
        self._metrics = RunMetrics(machine=machine, mode=mode, provider=provider)

    # ── Public ───────────────────────────────────────────────────────────────

    def run(self) -> RunMetrics:
        """Run the ReAct loop synchronously. Returns final RunMetrics."""
        try:
            asyncio.run(self._loop())
        except KeyboardInterrupt:
            self._log("\n[agent] Interrupted by operator.")
            self._metrics.finish("abandoned")
        except Exception as exc:
            self._log(f"\n[agent] Fatal error: {exc}")
            self._metrics.finish("error")
        finally:
            slug = self._resolve_session_slug()
            path = self._metrics.save(self._runs_dir, slug)
            self._log(f"[agent] Metrics saved → {path}")
        return self._metrics

    # ── Internal loop ─────────────────────────────────────────────────────────

    async def _loop(self) -> None:
        messages: list[dict[str, Any]] = [
            {
                "role": "user",
                "content": self._initial_prompt(),
            }
        ]

        consecutive_no_progress = 0
        last_tool_names: list[str] = []

        for iteration in range(1, self.max_iterations + 1):
            self._metrics.iterations = iteration
            self._log(f"\n[agent] ── Iteration {iteration} "
                      f"(tokens used: {self._metrics.tokens_input + self._metrics.tokens_output}) ──")

            # Budget check
            tokens_used = self._metrics.tokens_input + self._metrics.tokens_output
            if tokens_used >= self.budget_tokens:
                self._log("[agent] Budget exceeded.")
                self._metrics.finish("budget_exceeded")
                return

            # Call Anthropic
            response = self._client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=_SYSTEM_BLIND if self.mode == "blind" else _SYSTEM_BLIND,
                tools=self._tools,
                messages=messages,
            )

            # Track token usage
            self._metrics.tokens_input += response.usage.input_tokens
            self._metrics.tokens_output += response.usage.output_tokens

            # Extract content blocks
            text_blocks = [b for b in response.content if b.type == "text"]
            tool_blocks = [b for b in response.content if b.type == "tool_use"]

            # Log agent reasoning
            for tb in text_blocks:
                self._log(f"[agent] {tb.text}")

            # Check for HITL in text blocks
            for tb in text_blocks:
                hitl = self._parse_inline_hitl(tb.text)
                if hitl:
                    answer = self._terminal_hitl(hitl)
                    # Inject answer back as user message continuation
                    messages.append({"role": "assistant", "content": response.content})
                    messages.append(
                        {
                            "role": "user",
                            "content": f"[Operator answer to '{hitl['gate']}' gate]: {answer}",
                        }
                    )
                    self._metrics.hitl_gates += 1
                    continue

            # If no tool calls — agent is done or stuck
            if not tool_blocks:
                stop_reason = response.stop_reason
                self._log(f"[agent] No tool calls (stop_reason={stop_reason}).")
                if stop_reason == "end_turn":
                    self._metrics.finish("abandoned")
                    return
                break

            # Execute tools
            tool_results: list[dict[str, Any]] = []
            iteration_tool_names: list[str] = []
            got_progress = False

            for tb in tool_blocks:
                self._metrics.tools_called += 1
                iteration_tool_names.append(tb.name)
                self._log(f"[agent] → {tb.name}({json.dumps(tb.input)[:120]})")

                result = await self._execute_tool(tb.name, tb.input)

                # Detect HITL in tool result
                if isinstance(result, dict) and result.get("_hitl"):
                    answer = self._terminal_hitl(result)
                    result = {"hitl_answered": True, "operator_response": answer}
                    self._metrics.hitl_gates += 1

                # Track flag submissions
                if tb.name == "htb_submit_flag":
                    flag_type = tb.input.get("flag_type", "root")
                    if isinstance(result, dict) and result.get("correct"):
                        self._metrics.record_flag(flag_type)
                        self._log(f"[agent] ✅ {flag_type.upper()} FLAG OWNED")

                # Track stuck events
                if tb.name == "stuck_check" and isinstance(result, dict):
                    if result.get("signals"):
                        self._metrics.stuck_events += 1

                # Track vector chosen
                if tb.name == "intel_classify_blind" and isinstance(result, dict):
                    ap = result.get("attack_plan", {})
                    if isinstance(ap, dict):
                        primary = ap.get("primary_chain", {})
                        cats = primary.get("categories", []) if isinstance(primary, dict) else []
                        if cats and not self._metrics.vector_chosen:
                            self._metrics.vector_chosen = cats[0]

                result_str = json.dumps(result, ensure_ascii=False, default=str)
                self._log(f"[agent]   ← {result_str[:200]}")
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tb.id,
                        "content": result_str,
                    }
                )
                got_progress = True

            # Append this turn to messages
            messages.append({"role": "assistant", "content": response.content})
            messages.append({"role": "user", "content": tool_results})

            # Progress tracking
            if not got_progress or iteration_tool_names == last_tool_names:
                consecutive_no_progress += 1
            else:
                consecutive_no_progress = 0
            last_tool_names = iteration_tool_names

            if consecutive_no_progress >= 3:
                self._log("[agent] No progress in 3 iterations — recommending stuck_check.")
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            f"[agent-system] 3 consecutive iterations with no new findings. "
                            f"Call stuck_check(machine='{self.machine}') now and act on recommendation."
                        ),
                    }
                )
                consecutive_no_progress = 0

            # Check owned
            if self._metrics.user_flag_at and self._metrics.root_flag_at:
                self._log("[agent] Both flags obtained — machine owned!")
                self._metrics.finish("owned")
                return

        # Fell through max iterations
        if not self._metrics.outcome:
            self._metrics.finish("max_iterations")

    # ── Tool execution ────────────────────────────────────────────────────────

    async def _execute_tool(self, name: str, args: dict[str, Any]) -> Any:
        from kestrel.mcp import registry

        spec = registry.get_tool(name)
        if spec is None:
            return {"error": f"unknown_tool: {name}"}
        try:
            result = await spec.handler(**args)
            return result
        except Exception as exc:
            return {"error": str(exc), "tool": name}

    # ── HITL ─────────────────────────────────────────────────────────────────

    def _parse_inline_hitl(self, text: str) -> dict[str, Any] | None:
        """Extract JSON HITL gate from text blocks (see _SYSTEM_BLIND)."""
        for line in text.splitlines():
            line = line.strip()
            if line.startswith('{"_agent_hitl"'):
                try:
                    parsed = json.loads(line)
                    if parsed.get("_agent_hitl"):
                        return parsed
                except json.JSONDecodeError:
                    pass
        return None

    def _terminal_hitl(self, gate: dict[str, Any]) -> str:
        """Block on terminal input for a HITL gate. Returns operator answer."""
        question = gate.get("question") or gate.get("instruction_to_llm", "Operator input required")
        options = gate.get("options", ["yes", "no"])
        gate_id = gate.get("gate", "unknown")

        print(f"\n{'='*60}")
        print(f"[HITL GATE: {gate_id}]")
        print(f"\n{question}\n")
        if options:
            for i, opt in enumerate(options, 1):
                print(f"  {i}. {opt}")
        print(f"{'='*60}")
        try:
            answer = input("Your response: ").strip()
        except EOFError:
            answer = options[0] if options else "yes"
        return answer

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _initial_prompt(self) -> str:
        state_summary = self._load_state_summary()
        return (
            f"Machine: {self.machine}\n"
            f"Mode: {self.mode}\n"
            f"Current state:\n{state_summary}\n\n"
            f"Begin the engagement. Start with the Kali gate (kali_vm_status), "
            f"then lifecycle protocol: session_open → phase_enter('p0_setup') → proceed."
        )

    def _load_state_summary(self) -> str:
        try:
            state = self._ctx.state_store.read()
            m = state.data.machines.get(self.machine)
            if m:
                return json.dumps(m.model_dump(mode="json", exclude_none=True), indent=2)
        except Exception:
            pass
        return "{}"

    def _resolve_session_slug(self) -> str:
        try:
            state = self._ctx.state_store.read()
            m = state.data.machines.get(self.machine)
            if m and m.session_slug:
                return m.session_slug
        except Exception:
            pass
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return f"htb-{ts}-{self.machine}"

    def _log(self, msg: str) -> None:
        if self.verbose:
            print(msg, file=sys.stderr, flush=True)
