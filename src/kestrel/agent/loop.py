"""Kestrel ReAct Agent -- autonomous HTB engagement loop via Anthropic SDK.

Loop: observe -> think -> act -> observe (repeat until owned / budget / max_iter).

Tool execution bridges the Anthropic tool_use protocol to the MCP tool Python
functions directly (no MCP transport -- functions are imported and called async).

HITL gates: when the agent needs operator input, the loop prints to terminal
and blocks on input() -- no MCP protocol involved.
"""

from __future__ import annotations

import asyncio
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import anthropic

from kestrel.agent.bridge import load_tools_for_anthropic
from kestrel.agent.metrics import RunMetrics


# Anthropic model for the agent (latest Sonnet by default)
DEFAULT_MODEL = "claude-sonnet-4-5"

# Hard limits
DEFAULT_BUDGET_TOKENS = 200_000
DEFAULT_MAX_ITERATIONS = 60

# Tools that signal flag submission (used to record timing)
_FLAG_SUBMIT_TOOLS = {"htb_submit_flag", "flag_validate"}

# Tool execution timeout table (seconds)  [FIX 1]
TOOL_TIMEOUT_S: dict[str, int] = {
    "creds_ssh_bruteforce": 600,
    "post_linpeas_run": 300,
    "post_winpeas_run": 300,
    "recon_nmap_scan": 300,
    "exploit_run_msf": 180,
    "recon_web_dirfuzz": 240,
    "creds_hash_crack": 300,
}
_DEFAULT_TOOL_TIMEOUT = 120  # 2 min default

# HITL JSON pattern -- matches {"_agent_hitl": true, ...} without nested braces  [FIX 5]
_HITL_JSON_RE = re.compile(r'{"_agent_hitl":.*?}', re.DOTALL)

# System prompt for blind agent mode
_SYSTEM_BLIND = """\
You are Kestrel, an autonomous HackTheBox engagement agent. Your only goal: own the target machine.

## Engagement Phases
p0_setup   -> pick target, classify surface, spawn machine, ping IP
p1_recon   -> nmap full scan, web fingerprint, service enum, intel_classify_blind
p2_vector  -> ranked attack vectors via intel_next_step + intel_cve_lookup; confirm with operator
p3_exploit -> run confirmed vector, get foothold (SSH session or web shell)
p4_privesc -> post_enum_system -> sudo/SUID/caps/kernel -> escalate to root
p5_close   -> extract flags, submit, writeup_kb_synthesize, session_close

## Mandatory protocol
1. Start every new machine with: kali_vm_status -> vpn_up -> phase_enter("p0_setup")
2. Call phase_enter BEFORE using tools in that phase.
3. Call narrate_emit for every significant finding or action.
4. Call state_write_machine after: IP found, vector chosen, foothold obtained, flag obtained.
5. Call session_close at the end.

## SSH credential attack flow
When SSH is open and web gives no foothold:
  1. creds_default_check(target, service="ssh") -> try known defaults first (fast)
  2. creds_themed_wordlist_gen(machine=<slug>, keywords=[<page_keywords>], staff=[<names_from_web>]) -> build wordlist
  3. creds_ssh_bruteforce(target=<ip>, users=[<candidates>], wordlist=<output_path>) -> hydra 1-user x N-pass
  4. If 0 hits: try rockyou.txt -- creds_ssh_bruteforce(wordlist="/usr/share/wordlists/rockyou.txt")

## SSH session flow (after creds found)
After creds_ssh_bruteforce returns hits=[{user, password}]:
  1. session_open(transport="ssh", params={host, user, password}) -> handle_id
  2. session_exec(handle_id, "id; whoami; hostname") -> confirm foothold
  3. session_exec(handle_id, "find /home -name 'user.txt' 2>/dev/null | xargs cat 2>/dev/null") -> user flag
  4. htb_submit_flag(slug, flag, flag_type="user") then phase_enter("p4_privesc")
  5. session_exec(handle_id, "sudo -l 2>&1") -> pipe to post_privesc_sudo
  6. session_exec(handle_id, "find / -perm -4000 -type f 2>/dev/null") -> SUID binaries
  7. lolbin_suggest or post_privesc_sudo for GTFOBins -> session_exec privesc command
  8. session_exec(handle_id, "cat /root/root.txt") -> root flag

## Web RCE / shell flow
After getting RCE:
  1. session_open(transport="ssh", params={...}) if SSH key dropped, OR use session_exec equivalent
  2. For reverse shells: session_upload + session_exec to run scripts on target

## HITL gates (operator confirmation required)
You CANNOT auto-answer these -- the loop will pause and ask the operator:
- machine_pick: after listing machines, before spawning
- vector_confirm: before running any exploit
- submit_flag: before htb_submit_flag
- debrief: before cleanup

To trigger a gate, output ONLY this JSON on a line by itself (no other text on that line):
  {"_agent_hitl": true, "gate": "<gate_id>", "question": "<question>", "options": ["yes","no"]}

## Intelligence loop
- If 3 consecutive tools return no new information -> call stuck_check; act on recommendation.
- If stuck_check.signals includes "rabbit_hole" -> pivot vector immediately, don't retry.
- When unsure what to do next -> intel_next_step(machine, current_phase, tried=[...], findings=[...])

## Blind mode
Do NOT use walkthroughs, writeups, or known solutions. Own it from first principles.
Leverage intel_kb_query and intel_cve_lookup for technique guidance -- that's fair.

## Output format
Think briefly (1-3 sentences), then call 1-3 tools. Don't dump long reasoning blocks.
After each tool result, update your mental model and proceed.
"""


def _result_has_new_findings(result: Any) -> bool:
    """Return True only when a tool result contains genuinely new information.

    Zero-hit results (spray with 0 successes, dirfuzz with 0 paths, etc.) are
    treated as no-progress so stuck_check fires after 3 such iterations.
    """
    if not isinstance(result, dict):
        return bool(result)
    if "error" in result:
        return False
    # Explicit zero-finding keys
    _ZERO_KEYS = {"success_count", "discovered_count", "hit_count", "finding_count"}
    for key in _ZERO_KEYS:
        if key in result and result[key] == 0:
            return False
    # Null-found patterns (e.g. creds_default_check returns {"found": null})
    if "found" in result and result["found"] is None:
        return False
    # Empty hit lists
    for key in ("hits", "successes", "findings", "shares_detected"):
        if key in result and result[key] == []:
            return False
    # nmap with 0 open ports across all hosts
    if "hosts" in result:
        hosts = result["hosts"]
        if isinstance(hosts, list) and all(
            not h.get("ports") or all(p.get("state") != "open" for p in h.get("ports", []))
            for h in hosts
        ):
            return False
    return True


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
        # Dedup tracking: call_key -> call count  [FIX 3]
        self._seen_calls: dict[str, int] = {}
        # Budget warning flags (injected once each)  [FIX 2]
        self._budget_warn_injected = False
        self._budget_critical_injected = False

    # -- Public ---------------------------------------------------------------

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
            self._log(f"[agent] Metrics saved -> {path}")
        return self._metrics

    # -- Internal loop --------------------------------------------------------

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
            self._log(
                f"\n[agent] -- Iteration {iteration} "
                f"(tokens used: {self._metrics.tokens_input + self._metrics.tokens_output}) --"
            )

            # Budget check
            tokens_used = self._metrics.tokens_input + self._metrics.tokens_output
            if tokens_used >= self.budget_tokens:
                self._log("[agent] Budget exceeded.")
                self._metrics.finish("budget_exceeded")
                return

            # Budget warnings (injected once each)  [FIX 2]
            budget_pct = tokens_used / self.budget_tokens if self.budget_tokens else 0
            if budget_pct >= 0.90 and not self._budget_critical_injected:
                messages.append({
                    "role": "user",
                    "content": (
                        f"[BUDGET CRITICAL] {tokens_used:,}/{self.budget_tokens:,} tokens ({budget_pct:.0%}). "
                        f"Iterations left: <={self.max_iterations - iteration}. "
                        "STOP all recon. If you have a shell: flag_extract NOW, then htb_submit_flag. "
                        "If no foothold: one last high-probability attempt then stop."
                    ),
                })
                self._budget_critical_injected = True
            elif budget_pct >= 0.75 and not self._budget_warn_injected:
                messages.append({
                    "role": "user",
                    "content": (
                        f"[BUDGET WARNING] {budget_pct:.0%} tokens used. "
                        "Prioritize: session_exec -> flag_extract -> htb_submit_flag over additional recon."
                    ),
                })
                self._budget_warn_injected = True

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

            # Check for HITL in text blocks -- one gate per turn max
            hitl_fired = False
            for tb in text_blocks:
                hitl = self._parse_inline_hitl(tb.text)
                if hitl:
                    answer = self._terminal_hitl(hitl)
                    messages.append({"role": "assistant", "content": response.content})
                    messages.append(
                        {
                            "role": "user",
                            "content": f"[Operator answer to '{hitl['gate']}' gate]: {answer}",
                        }
                    )
                    self._metrics.hitl_gates += 1
                    hitl_fired = True
                    break  # one HITL per iteration

            if hitl_fired:
                continue  # skip tool execution -- go to next iteration

            # If no tool calls -- agent is done or stuck
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
                self._log(f"[agent] -> {tb.name}({json.dumps(tb.input)[:120]})")

                # Dedup: warn and track if calling same tool+args 3+ times  [FIX 3]
                call_key = f"{tb.name}::{json.dumps(tb.input, sort_keys=True)}"
                self._seen_calls[call_key] = self._seen_calls.get(call_key, 0) + 1
                if self._seen_calls[call_key] >= 3:
                    messages.append({
                        "role": "user",
                        "content": (
                            f"[agent-system] '{tb.name}' called with identical args "
                            f"{self._seen_calls[call_key]} times. "
                            "You are cycling. DO NOT call this tool again with same args. "
                            "Pivot to a different approach."
                        ),
                    })
                    self._metrics.stuck_events = getattr(self._metrics, "stuck_events", 0) + 1

                result = await self._execute_tool(tb.name, tb.input)

                # Detect HITL in tool result
                if isinstance(result, dict) and result.get("_hitl"):
                    answer = self._terminal_hitl(result)
                    result = {"hitl_answered": True, "operator_response": answer}
                    self._metrics.hitl_gates += 1

                # Track flag submissions
                if tb.name == "htb_submit_flag":
                    flag_type = tb.input.get("flag_type", "root")
                    # HTB tool returns {"slug", "machine_id", "flag_type", "result":{...}}
                    # "correct" may be nested under "result" or absent; success = no error key
                    inner = result.get("result", {}) if isinstance(result, dict) else {}
                    flag_correct = (
                        result.get("correct")
                        or inner.get("correct")
                        or inner.get("success")
                        or (isinstance(result, dict) and "error" not in result and result.get("machine_id"))
                    )
                    if flag_correct:
                        self._metrics.record_flag(flag_type)
                        self._log(f"[agent] {flag_type.upper()} FLAG OWNED")

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
                self._log(f"[agent]   <- {result_str[:200]}")
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tb.id,
                        "content": result_str,
                    }
                )
                # Progress = at least one tool returned a non-empty, non-error result
                if _result_has_new_findings(result):
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
                self._log("[agent] No progress in 3 iterations -- recommending stuck_check.")
                self._metrics.stuck_events = getattr(self._metrics, "stuck_events", 0) + 1  # [FIX 4]
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
                self._log("[agent] Both flags obtained -- machine owned!")
                self._metrics.finish("owned")
                return

        # Fell through max iterations
        if not self._metrics.outcome:
            self._metrics.finish("max_iterations")

    # -- Tool execution -------------------------------------------------------

    async def _execute_tool(self, name: str, args: dict[str, Any]) -> Any:
        from kestrel.mcp import registry

        spec = registry.get_tool(name)
        if spec is None:
            return {"error": f"unknown_tool: {name}"}
        timeout = TOOL_TIMEOUT_S.get(name, _DEFAULT_TOOL_TIMEOUT)  # [FIX 1]
        try:
            result = await asyncio.wait_for(spec.handler(**args), timeout=timeout)
            return result
        except asyncio.TimeoutError:
            return {"error": f"timeout_after_{timeout}s", "tool": name, "timed_out": True}
        except Exception as exc:
            return {"error": str(exc), "tool": name}

    # -- HITL -----------------------------------------------------------------

    def _parse_inline_hitl(self, text: str) -> dict[str, Any] | None:
        """Extract JSON HITL gate from text blocks (see _SYSTEM_BLIND).

        Uses regex to handle markdown code fences and minor formatting variations.
        """
        # Strip markdown code fences  [FIX 5]
        clean = re.sub(r"```(?:json)?\s*", "", text)
        clean = clean.replace("```", "")
        match = _HITL_JSON_RE.search(clean)
        if match:
            try:
                parsed = json.loads(match.group(0))
                if parsed.get("_agent_hitl"):
                    return parsed
            except Exception:
                pass
        return None

    def _terminal_hitl(self, gate: dict[str, Any]) -> str:
        """Block on terminal input for a HITL gate. Returns operator answer.
        Auto-confirms first option when stdin is not a TTY (headless/piped mode).
        """
        question = gate.get("question") or gate.get("instruction_to_llm", "Operator input required")
        options = gate.get("options", ["yes", "no"])
        gate_id = gate.get("gate", "unknown")

        # Headless mode: auto-confirm first option
        if not sys.stdin.isatty():
            answer = options[0] if options else "yes"
            self._log(f"[agent] HITL gate '{gate_id}' auto-confirmed (headless): {answer}")
            return answer

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

    # -- Helpers --------------------------------------------------------------

    def _initial_prompt(self) -> str:
        state_summary = self._load_state_summary()
        return (
            f"Machine: {self.machine}\n"
            f"Mode: {self.mode}\n"
            f"Current state:\n{state_summary}\n\n"
            f"Begin the engagement. "
            f"Protocol: kali_vm_status -> vpn_up -> htb_spawn if needed -> phase_enter('p0_setup') -> kali_ping_target(ip). "
            f"DO NOT call session_open until you have confirmed SSH credentials."
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
