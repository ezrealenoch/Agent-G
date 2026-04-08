"""Regression tests for ``ConversationRuntime``.

These tests replay recorded traces against a stub LLM and a stub tool
runner, verifying that the orchestration loop issues the same tool calls
in the same order. Any change to ``conversation.py`` that silently breaks
the ReAct loop (re-ordering, double-dispatch, early exit, new completion
marker behavior, etc.) will surface here as a diff.

Run with::

    python -m pytest tests/ -v

Or without pytest::

    python tests/test_conversation_replay.py
"""
from __future__ import annotations
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Make src/ importable when run as a script
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.runtime.session import Session, Message, ContentBlock, TokenUsage
from src.runtime.conversation import (
    ConversationRuntime, _has_verdict_pattern, _has_completion_marker,
)
from src.runtime.budget import Budget, BudgetTracker, BudgetExceeded
from src.runtime.checkpoint import CheckpointWriter, CheckpointData
from src.runtime.trace import TraceWriter, StubLlmFromTrace, load_trace
from src.runtime.tool_schema import validate_tool_call, tool_schema_document
from src.runtime.prompt_library import render_prompt, get_prompt, list_prompts


# ── Stubs ──

class StubApiClient:
    """Minimal stand-in for ApiClient.

    Returns recorded responses in order. The ConversationRuntime calls
    ``self.api.call(messages=..., system_prompt=...)`` and expects a
    ``(response_text, usage)`` tuple, so that's what we return.
    """
    def __init__(self, responses: List[str], model_name: str = "stub-model"):
        self._responses = list(responses)
        self._index = 0
        self.model_name = model_name

    def call(self, messages, system_prompt=None):
        if self._index >= len(self._responses):
            return ("", TokenUsage(input_tokens=0, output_tokens=0))
        r = self._responses[self._index]
        self._index += 1
        return (r, TokenUsage(input_tokens=100, output_tokens=50))


class StubToolRunner:
    """Records every tool call for later assertion + returns canned results."""
    def __init__(self, canned: Dict[str, str] = None):
        self.canned = canned or {}
        self.calls: List[Tuple[str, Dict[str, Any]]] = []

    def execute(self, name: str, params: Dict[str, Any]) -> Tuple[str, bool]:
        self.calls.append((name, params))
        return (self.canned.get(name, f"[stub result for {name}]"), False)


class StubCommandParser:
    """Parses ``EXECUTE: tool_name(k=v, ...)`` lines out of LLM text.

    Matches whatever format Agent-G's real parser handles. For the purpose
    of these tests we accept both ``EXECUTE: foo(x=1)`` and JSON-ish shapes.
    """
    import re as _re
    _EXEC_RE = _re.compile(
        r"EXECUTE:\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\(([^)]*)\)",
        _re.IGNORECASE,
    )

    def extract_commands(self, text: str) -> List[Tuple[str, Dict[str, Any]]]:
        out: List[Tuple[str, Dict[str, Any]]] = []
        for m in self._EXEC_RE.finditer(text or ""):
            name = m.group(1)
            args_str = m.group(2).strip()
            params: Dict[str, Any] = {}
            if args_str:
                for piece in args_str.split(","):
                    if "=" not in piece:
                        continue
                    k, v = piece.split("=", 1)
                    v = v.strip().strip("\"'")
                    # Naive int coercion
                    if v.isdigit():
                        params[k.strip()] = int(v)
                    else:
                        params[k.strip()] = v
            out.append((name, params))
        return out


# ── Helper to build a runtime with stubs ──

def _make_runtime(
    responses: List[str],
    *,
    canned_tool_results: Dict[str, str] = None,
    budget: Budget = None,
    system_prompt: str = "You are a stub.",
    max_iterations: int = 5,
):
    api = StubApiClient(responses)
    tools = StubToolRunner(canned=canned_tool_results)
    parser = StubCommandParser()
    rt = ConversationRuntime(
        api_client=api,
        tool_runner=tools,
        command_parser=parser,
        system_prompt=system_prompt,
        max_iterations=max_iterations,
        budget=budget,
    )
    return rt, api, tools, parser


# ── Test cases ──

class TestVerdictPatterns(unittest.TestCase):
    def test_verdict_presence_predicate(self):
        self.assertTrue(_has_verdict_pattern("## Verdict\nVULNERABLE"))
        self.assertTrue(_has_verdict_pattern("## Verdict\nNOT VULNERABLE"))
        self.assertTrue(_has_verdict_pattern("Verdict: VULNERABLE"))
        self.assertTrue(_has_verdict_pattern("**Verdict**: NOT_VULNERABLE"))
        self.assertFalse(_has_verdict_pattern("## Verdict\n(incomplete)"))
        self.assertFalse(_has_verdict_pattern(""))

    def test_marker_without_verdict(self):
        self.assertTrue(_has_completion_marker("**INVESTIGATION COMPLETE**"))
        self.assertTrue(_has_completion_marker("ANALYSIS COMPLETE"))
        self.assertFalse(_has_completion_marker("investigation pending"))


class TestConversationLoop(unittest.TestCase):
    def test_single_tool_then_verdict(self):
        """Happy path: one tool call, then a verdict block."""
        rt, api, tools, _ = _make_runtime([
            "EXECUTE: list_imports(limit=10)",
            "## Verdict\nVULNERABLE\n\nINVESTIGATION COMPLETE",
        ])
        summary = rt.run_turn("find vulns")
        self.assertEqual(summary.exit_reason, "complete")
        self.assertEqual(summary.tool_calls, 1)
        self.assertEqual(tools.calls[0][0], "list_imports")
        self.assertEqual(tools.calls[0][1], {"limit": 10})
        self.assertIn("VULNERABLE", summary.final_text)

    def test_investigation_complete_without_verdict_continues(self):
        """Regression: GPT-5 bug fix — marker alone should not exit."""
        rt, api, tools, _ = _make_runtime([
            # First step: marker alone, no verdict — should KEEP looping
            "EXECUTE: list_imports(limit=10)\n\n**INVESTIGATION COMPLETE**",
            # Second step: real verdict
            "## Verdict\nNOT VULNERABLE\n\nINVESTIGATION COMPLETE",
        ])
        summary = rt.run_turn("check binary")
        self.assertEqual(summary.exit_reason, "complete")
        # First iteration should have dispatched list_imports; the marker
        # without verdict should not have short-circuited the loop
        self.assertEqual(summary.tool_calls, 1)
        self.assertEqual(tools.calls[0][0], "list_imports")
        self.assertIn("NOT VULNERABLE", summary.final_text)

    def test_blank_response_tagged(self):
        """Runtime should emit BLANK_RESPONSE sentinel on iteration-1 empty."""
        rt, _, _, _ = _make_runtime(["", ""])
        summary = rt.run_turn("hello")
        self.assertEqual(summary.exit_reason, "blank_response")
        self.assertIn("blank response", summary.final_text.lower())

    def test_budget_exceeded_on_tool_calls(self):
        """Budget cap on tool_calls cleanly breaks the loop."""
        rt, _, tools, _ = _make_runtime(
            [
                "EXECUTE: list_imports(limit=5)",
                "EXECUTE: list_exports(limit=5)",
                "EXECUTE: list_functions(limit=5)",
                "## Verdict\nVULNERABLE",
            ],
            budget=Budget(max_tool_calls=2),
        )
        summary = rt.run_turn("go")
        self.assertEqual(summary.exit_reason, "budget_exceeded")
        self.assertLessEqual(summary.tool_calls, 2 + 1)  # loose bound

    def test_checkpoint_and_trace_writers(self):
        """Checkpoint + trace writer capture the run end-to-end."""
        with tempfile.TemporaryDirectory() as d:
            runs = Path(d) / "run"
            runs.mkdir()
            cw = CheckpointWriter(runs / "checkpoint.json")
            tw = TraceWriter(runs / "trace.jsonl")
            api = StubApiClient(["## Verdict\nNOT VULNERABLE\n\nINVESTIGATION COMPLETE"])
            rt = ConversationRuntime(
                api_client=api,
                tool_runner=StubToolRunner(),
                command_parser=StubCommandParser(),
                system_prompt="test",
                max_iterations=3,
                checkpoint_writer=cw,
                trace_writer=tw,
                trace_id="abc123",
                binary_name="sample.bin",
            )
            summary = rt.run_turn("go")

            self.assertEqual(summary.exit_reason, "complete")
            self.assertTrue((runs / "checkpoint.json").exists())
            self.assertTrue((runs / "trace.jsonl").exists())
            ck = cw.load()
            self.assertEqual(ck.trace_id, "abc123")
            self.assertEqual(ck.exit_reason, "complete")
            records = load_trace(runs / "trace.jsonl")
            kinds = [r["kind"] for r in records]
            self.assertIn("llm_call", kinds)
            self.assertIn("end", kinds)


class TestToolSchema(unittest.TestCase):
    def test_valid_tool_call(self):
        ok, params, err = validate_tool_call("list_functions", {"limit": 10})
        self.assertTrue(ok)
        self.assertEqual(params["limit"], 10)
        self.assertIsNone(err)

    def test_int_coercion_from_string(self):
        ok, params, _ = validate_tool_call("list_functions", {"limit": "20"})
        self.assertTrue(ok)
        self.assertEqual(params["limit"], 20)

    def test_clamp_over_max(self):
        ok, params, _ = validate_tool_call("list_functions", {"limit": 1000})
        self.assertTrue(ok)
        self.assertEqual(params["limit"], 200)  # clamped

    def test_address_normalization(self):
        ok, params, _ = validate_tool_call(
            "decompile_function_by_address", {"address": "0x1012e0"})
        self.assertTrue(ok)
        self.assertEqual(params["address"], "001012e0")

    def test_required_param_missing(self):
        ok, _, err = validate_tool_call("decompile_function_by_address", {})
        self.assertFalse(ok)
        self.assertIn("address", err)

    def test_unknown_tool_passthrough(self):
        ok, _, _ = validate_tool_call("some_custom_tool", {"x": 1})
        self.assertTrue(ok)  # non-strict default

    def test_unknown_tool_strict(self):
        ok, _, err = validate_tool_call(
            "some_custom_tool", {"x": 1}, strict_unknown_tool=True)
        self.assertFalse(ok)
        self.assertIn("unknown tool", err)

    def test_unknown_param_strict(self):
        ok, _, err = validate_tool_call(
            "list_functions", {"limit": 10, "bogus": "value"})
        self.assertFalse(ok)
        self.assertIn("unknown params", err)

    def test_schema_document(self):
        doc = tool_schema_document()
        self.assertIn("tools", doc)
        self.assertGreater(doc["count"], 5)
        tool_names = [t["name"] for t in doc["tools"]]
        self.assertIn("list_functions", tool_names)
        self.assertIn("decompile_function_by_address", tool_names)


class TestPromptLibrary(unittest.TestCase):
    def test_render_known_prompt(self):
        text, version, prompt_hash = render_prompt(
            "vuln_hunt", binary_name="sample.bin", task_kind="CWE-78")
        self.assertIn("sample.bin", text)
        self.assertIn("CWE-78", text)
        self.assertEqual(version, "v1")
        self.assertEqual(len(prompt_hash), 64)

    def test_latest_version(self):
        p = get_prompt("vuln_hunt", "latest")
        self.assertEqual(p.version, "v1")

    def test_unknown_prompt_raises(self):
        with self.assertRaises(KeyError):
            get_prompt("nonexistent_prompt")

    def test_list_prompts(self):
        ps = list_prompts()
        names = [n for n, _ in ps]
        self.assertIn("vuln_hunt", names)
        self.assertIn("bootstrap_discovery", names)


if __name__ == "__main__":
    unittest.main(verbosity=2)
