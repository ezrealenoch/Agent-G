"""ConversationRuntime — single ReAct loop for binary analysis.

Inspired by CLAW Code's conversation.rs, adapted for binary analysis tasks.

The loop:
  1. User message added to session
  2. LLM called with full session history + system prompt
  3. Response parsed for tool calls
  4. If no tool calls -> done (return final response)
  5. If tool calls -> execute each, append results to session, loop

This replaces OGhidra's three-tier orchestrator (planner -> worker -> synthesizer)
with a single LLM call per reasoning step. The model sees raw tool output, not
a lossy notebook summary.
"""

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

from src.runtime.session import (
    Session, Message, MessageRole, ContentBlock, TokenUsage,
)
from src.runtime.api_client import ApiClient
from src.runtime.tool_runner import ToolRunner
from src.runtime.compactor import should_compact, compact_session

logger = logging.getLogger("agent-g.conversation")


# Maximum tool calls to extract from a single LLM response
MAX_TOOLS_PER_RESPONSE = 4

# Maximum reasoning iterations per user turn
DEFAULT_MAX_ITERATIONS = 25

# Completion sentinels — model can signal "I'm done"
COMPLETION_MARKERS = (
    "INVESTIGATION COMPLETE",
    "ANALYSIS COMPLETE",
    "TASK COMPLETE",
)


@dataclass
class TurnSummary:
    """Result of a single user turn (input -> reasoning loop -> response)."""
    final_text: str = ""
    iterations: int = 0
    tool_calls: int = 0
    usage: TokenUsage = field(default_factory=TokenUsage)
    exit_reason: str = "complete"  # complete | max_iter | error | doom_loop


class ConversationRuntime:
    """Single-loop ReAct runtime for binary analysis.

    Construction::

        runtime = ConversationRuntime(
            api_client=ApiClient(ollama_client),
            tool_runner=ToolRunner(tool_executor, command_parser),
            command_parser=command_parser,
            system_prompt=build_vuln_hunting_prompt(),
        )

    Usage::

        result = runtime.run_turn("Find vulnerabilities in this binary")
        print(result.final_text)
    """

    def __init__(
        self,
        api_client: ApiClient,
        tool_runner: ToolRunner,
        command_parser,
        system_prompt: str,
        session: Optional[Session] = None,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        on_event=None,  # Optional callback(event_name, data) for terminal updates
        budget=None,    # Optional src.runtime.budget.Budget (hard caps)
        budget_tracker=None,  # Pre-built BudgetTracker (overrides budget)
        checkpoint_writer=None,  # Optional CheckpointWriter for crash-resume
        trace_writer=None,  # Optional TraceWriter for replay/audit
        trace_id: Optional[str] = None,
        binary_name: Optional[str] = None,
    ):
        self.api = api_client
        self.tools = tool_runner
        self.parser = command_parser
        self.system_prompt = system_prompt
        self.max_iterations = max_iterations
        self.on_event = on_event or (lambda *a, **k: None)

        # ── Budget / cost tracking ──
        # A BudgetTracker is always attached (unlimited by default) so
        # spend is tracked even when no caps are set. A Budget argument
        # wraps the tracker with hard caps that break the loop on exceed.
        from src.runtime.budget import Budget, BudgetTracker
        if budget_tracker is not None:
            self.budget_tracker = budget_tracker
        elif budget is not None:
            self.budget_tracker = budget.new_tracker()
        else:
            self.budget_tracker = Budget.unlimited().new_tracker()

        # ── Checkpoint writer ──
        # Opt-in; if set, state is serialized after every iteration so a
        # crashed or killed investigation can resume from the last save.
        self.checkpoint_writer = checkpoint_writer
        # ── Trace writer ──
        # Opt-in; captures llm_call + tool_call events to a JSONL file
        # for deterministic replay and post-run audit.
        self.trace_writer = trace_writer
        self.trace_id = trace_id or ""
        self.binary_name = binary_name or ""
        self._turn_started_at = 0.0

        # Initialize session with system message
        self.session = session or Session()
        if not self.session.system_messages():
            self.session.append(Message.system(system_prompt))

    def update_system_prompt(self, new_prompt: str) -> None:
        """Replace the system prompt (e.g., when switching tasks in REPL)."""
        self.system_prompt = new_prompt
        # Replace the first system message in-place via a new session
        new_session = Session(version=self.session.version,
                               metadata=dict(self.session.metadata))
        new_session.append(Message.system(new_prompt))
        for m in self.session.conversation_messages():
            new_session.append(m)
        self.session = new_session

    def append_preamble(self, role: MessageRole, text: str) -> None:
        """Inject a preamble message (e.g., bootstrap discovery results)."""
        self.session.append(Message(role=role, blocks=[ContentBlock.text_block(text)]))

    def run_turn(self, user_input: str) -> TurnSummary:
        """Execute one user turn through the ReAct loop.

        Returns when:
          - Model produces no tool calls (final response)
          - Model emits a completion marker
          - max_iterations reached
          - Same tool+params called twice in a row (doom loop guard)
        """
        # Append user message
        self.session.append(Message.user(user_input))

        summary = TurnSummary()
        last_tool_signature: Optional[str] = None
        repeat_count = 0
        final_text = ""
        self._turn_started_at = datetime.now().timestamp()

        for iteration in range(1, self.max_iterations + 1):
            summary.iterations = iteration

            # ── Runtime budget check ──
            # Evaluated at the top of every iteration so a budget breach
            # cleanly exits the loop before another LLM call is made.
            self.budget_tracker.add_iteration()
            reason = self.budget_tracker.check()
            if reason is not None:
                self.on_event("budget_exceeded", {"reason": reason})
                summary.exit_reason = "budget_exceeded"
                final_text = f"[Runtime: budget exceeded — {reason}. Investigation halted.]"
                break

            # Compact if needed
            if should_compact(self.session):
                self.on_event("compact", {"iteration": iteration})
                self.session = compact_session(self.session, api_client=None)

            # Call LLM
            self.on_event("step", {"iteration": iteration, "max": self.max_iterations})
            convo_msgs = self.session.conversation_messages()

            try:
                response_text, usage = self.api.call(
                    messages=convo_msgs,
                    system_prompt=self.system_prompt,
                )
            except Exception as e:
                logger.exception("LLM call failed")
                summary.exit_reason = "error"
                summary.final_text = f"LLM error: {e}"
                return summary

            summary.usage = summary.usage.add(usage)

            # Feed token usage to the budget tracker for cost + token caps
            self.budget_tracker.add_usage(
                input_tokens=getattr(usage, "input_tokens", 0) or 0,
                output_tokens=getattr(usage, "output_tokens", 0) or 0,
            )

            # Trace capture: record this LLM round-trip for replay/audit
            if self.trace_writer is not None:
                try:
                    import hashlib as _hl
                    self.trace_writer.llm_call(
                        model=getattr(self.api, "model_name", "") or "",
                        system_hash=_hl.sha256(
                            (self.system_prompt or "").encode("utf-8")
                        ).hexdigest()[:16],
                        messages_count=len(convo_msgs),
                        input_tokens=getattr(usage, "input_tokens", 0) or 0,
                        output_tokens=getattr(usage, "output_tokens", 0) or 0,
                        response_text=response_text or "",
                        elapsed_s=0.0,
                    )
                except Exception as e:
                    logger.debug("trace llm_call write skipped: %s", e)

            # ── Blank-response detection ──────────────────────────────
            # If the ExternalClient exhausted its thinking-model retries and
            # returned the sentinel, treat this as a distinct exit reason so
            # downstream code can distinguish "model ran out of thinking room"
            # from "model deliberately finished" or "model crashed".
            try:
                from src.external_client import BLANK_RESPONSE_SENTINEL
            except ImportError:
                BLANK_RESPONSE_SENTINEL = "[Model returned a blank response"  # prefix fallback

            if BLANK_RESPONSE_SENTINEL in (response_text or ""):
                self.on_event("blank_response", {"iteration": iteration})
                summary.exit_reason = "blank_response"
                final_text = (
                    "Model returned a blank response — thinking budget was "
                    "exhausted after retry escalation. No verdict produced."
                )
                # Record the blank-response marker in the session so later
                # analysis (e.g. verdict classifiers) can see this happened.
                self.session.append(Message.assistant(
                    [ContentBlock.text_block(final_text)], usage=usage
                ))
                break

            # Parse tool calls from response
            tool_calls = self.parser.extract_commands(response_text)
            tool_calls = tool_calls[:MAX_TOOLS_PER_RESPONSE]

            # Build assistant message blocks (text + tool_use blocks)
            blocks: List[ContentBlock] = []

            # Strip tool call syntax from text portion
            cleaned_text = _strip_tool_syntax(response_text)
            if cleaned_text.strip():
                blocks.append(ContentBlock.text_block(cleaned_text.strip()))

            for tool_name, params in tool_calls:
                blocks.append(ContentBlock.tool_use_block(tool_name, params))

            assistant_msg = Message.assistant(blocks, usage=usage)
            self.session.append(assistant_msg)

            # Check for completion.
            # GPT-5-family models (observed 2026-04-07) tend to write
            # "**INVESTIGATION COMPLETE**" as a transitional phrase BEFORE
            # producing the final `## Verdict` block. Previously the marker
            # fired, the runtime exited, and the harness classified the
            # response as UNKNOWN because no verdict was present. Require
            # BOTH the completion marker AND a verdict pattern in the same
            # response text before triggering the exit. If the marker
            # appears alone, treat it as a no-op and keep looping — the
            # model will either follow up with the verdict on the next
            # iteration or time out via max_iter.
            if _has_completion_marker(response_text):
                if _has_verdict_pattern(response_text):
                    self.on_event("complete", {"reason": "marker"})
                    summary.exit_reason = "complete"
                    final_text = cleaned_text
                    break
                else:
                    self.on_event("marker_without_verdict", {
                        "reason": "continuing",
                    })
                    # Fall through to the `if not tool_calls` branch which
                    # will either resume the loop (if tools were requested)
                    # or treat this as a text-only completion (which now
                    # also checks for verdict-presence before exiting).

            if not tool_calls:
                # Model produced text only — treat as final response.
                # If BOTH cleaned and raw are empty/whitespace, this is a
                # genuine blank response (small model truncation, thinking
                # budget exhaustion, etc.). Emit the BLANK_RESPONSE_SENTINEL
                # so the harness's verdict classifier can distinguish it
                # from a real text-only answer that just couldn't be parsed.
                if not (cleaned_text or "").strip() and not (response_text or "").strip():
                    from src.runtime.thinking_models import BLANK_RESPONSE_SENTINEL
                    self.on_event("complete", {"reason": "blank_response"})
                    summary.exit_reason = "blank_response"
                    final_text = BLANK_RESPONSE_SENTINEL
                    break

                self.on_event("complete", {"reason": "no_tools"})
                summary.exit_reason = "complete"
                final_text = cleaned_text if cleaned_text.strip() else response_text
                break

            # Doom loop detection: same tool+params twice in a row
            tool_signature = _signature(tool_calls[0])
            if tool_signature == last_tool_signature:
                repeat_count += 1
                if repeat_count >= 2:
                    self.on_event("doom_loop", {"signature": tool_signature})
                    final_text = cleaned_text + (
                        "\n\n[Runtime: detected repeated tool call, stopping.]"
                    )
                    summary.exit_reason = "doom_loop"
                    break
            else:
                repeat_count = 0
                last_tool_signature = tool_signature

            # Execute tool calls
            for tool_name, params in tool_calls:
                summary.tool_calls += 1
                self.budget_tracker.add_tool_call()
                self.on_event("tool_call", {"name": tool_name, "params": params})

                result_text, is_error = self.tools.execute(tool_name, params)

                self.on_event("tool_result", {
                    "name": tool_name,
                    "is_error": is_error,
                    "length": len(result_text),
                })
                if self.trace_writer is not None:
                    try:
                        self.trace_writer.tool_call(
                            name=tool_name,
                            params=params or {},
                            result_length=len(result_text or ""),
                            is_error=bool(is_error),
                        )
                    except Exception as e:
                        logger.debug("trace tool_call write skipped: %s", e)

                # Append tool result to session
                tool_msg = Message.tool_result(
                    tool_name=tool_name,
                    output=result_text,
                    is_error=is_error,
                )
                self.session.append(tool_msg)

            # Checkpoint at end of iteration (after the full
            # LLM-call + tool-execute cycle has committed to the session).
            self._save_checkpoint(summary)

            # Loop back for next reasoning step
        else:
            # Hit max iterations
            self.on_event("max_iter", {"iterations": self.max_iterations})
            summary.exit_reason = "max_iter"
            final_text = (
                f"[Runtime: reached maximum {self.max_iterations} iterations. "
                f"Investigation incomplete.]\n\n"
                + final_text
            )

        summary.final_text = final_text or "(no response)"
        # Final checkpoint so a post-run audit can see the terminal state.
        self._save_checkpoint(summary, final=True)
        # Final trace event so the audit log knows the run terminated cleanly.
        if self.trace_writer is not None:
            try:
                self.trace_writer.end(
                    exit_reason=summary.exit_reason,
                    final_text=summary.final_text or "",
                    iterations=summary.iterations,
                    tool_calls=summary.tool_calls,
                )
            except Exception as e:
                logger.debug("trace end write skipped: %s", e)
        return summary

    def _save_checkpoint(self, summary: "TurnSummary", final: bool = False) -> None:
        """Serialize current runtime state to disk if a writer is attached.

        Silent no-op when no writer was provided. Atomic via
        CheckpointWriter.save so a crash mid-write won't corrupt the file.
        """
        if self.checkpoint_writer is None:
            return
        try:
            from src.runtime.checkpoint import CheckpointData, session_to_dicts
            import hashlib
            snap = self.budget_tracker.snapshot()
            data = CheckpointData(
                trace_id=self.trace_id,
                binary_name=self.binary_name,
                task_kind="",  # BridgeLite can set this via subsystem_state
                system_prompt_hash=hashlib.sha256(
                    (self.system_prompt or "").encode("utf-8")
                ).hexdigest()[:16],
                started_at=datetime.fromtimestamp(self._turn_started_at).isoformat()
                    if self._turn_started_at else "",
                elapsed_s=snap["elapsed_s"],
                iterations_completed=summary.iterations,
                tool_calls_completed=summary.tool_calls,
                tokens_in_total=snap["input_tokens"],
                tokens_out_total=snap["output_tokens"],
                session_messages=session_to_dicts(self.session),
                exit_reason=summary.exit_reason if final else None,
                final_text=summary.final_text if final else None,
                subsystem_state={
                    "budget": snap,
                    "is_final": final,
                },
            )
            self.checkpoint_writer.save(data)
            if final:
                # Leave the final checkpoint on disk as a provenance artifact.
                # Callers who want to clean up post-success can do so explicitly.
                pass
        except Exception as e:
            logger.warning("checkpoint save skipped due to error: %s", e)

    def reset_session(self) -> None:
        """Clear conversation history but keep the system prompt."""
        self.session = Session()
        self.session.append(Message.system(self.system_prompt))


# ── Helpers ──────────────────────────────────────────────────────────────


def _strip_tool_syntax(text: str) -> str:
    """Remove tool call syntax from text so the assistant message has clean text."""
    # Strip standalone "EXECUTE: cmd(...)" lines (with optional surrounding whitespace)
    text = re.sub(
        r"^\s*EXECUTE:\s*[a-zA-Z_][a-zA-Z0-9_]*\([^\n]*\)\s*$",
        "",
        text,
        flags=re.MULTILINE,
    )
    # Strip ```execute ... ``` blocks
    text = re.sub(r"```execute\s*.*?\s*```", "", text, flags=re.DOTALL)
    # Strip ```tool_code ... ``` blocks
    text = re.sub(r"```tool_code\s*.*?\s*```", "", text, flags=re.DOTALL)
    # Collapse extra blank lines
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text


def _has_completion_marker(text: str) -> bool:
    """Check if the model signaled investigation completion."""
    upper = text.upper()
    return any(marker in upper for marker in COMPLETION_MARKERS)


# Verdict presence check — used to disambiguate a real completion from a
# transitional "INVESTIGATION COMPLETE" phrase that GPT-5-family models
# sometimes emit BEFORE producing the verdict block. We require at least
# one of these patterns to be present before treating the completion
# marker as a real exit signal.
_VERDICT_PRESENCE_PATTERNS = [
    re.compile(r"(?im)^[#*\s]*verdict[:\s]*\n+\s*\**\s*(?:VULNERABLE|NOT[ _-]VULNERABLE)"),
    re.compile(r"(?i)\*?\*?verdict\*?\*?\s*[:\-]+\s*\**\s*(?:VULNERABLE|NOT[ _-]VULNERABLE)"),
]


def _has_verdict_pattern(text: str) -> bool:
    """Return True if the text contains a parseable verdict block.

    Used to disambiguate genuine completion ("INVESTIGATION COMPLETE" +
    ``## Verdict VULNERABLE``) from transitional phrases where the model
    signals completion before actually producing the verdict block. The
    patterns here must match whatever ``classify_verdict`` in
    ``scripts/test_juliet.py`` accepts, so that ``_has_verdict_pattern``
    being True is a reliable predictor that the classifier will extract
    a real verdict later.
    """
    if not text:
        return False
    return any(pat.search(text) for pat in _VERDICT_PRESENCE_PATTERNS)


def _signature(tool_call) -> str:
    """Build a stable signature for a tool call (for doom loop detection)."""
    name, params = tool_call
    sorted_params = sorted((params or {}).items())
    return f"{name}:{sorted_params}"
