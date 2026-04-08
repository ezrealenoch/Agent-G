"""Trace capture, deterministic replay, and provenance bundles.

Three things, one module because they share the same JSONL trace format:

1. **TraceWriter** captures every LLM round-trip and tool call into a
   ``runs/<trace_id>/trace.jsonl`` file in append-only mode. Each line is
   one event with enough fields to reconstruct the investigation later.

2. **StubLlmFromTrace** + ``replay_trace()`` replay a captured trace through
   a stub LLM that returns the recorded responses verbatim. The replay
   harness re-runs the ConversationRuntime against the stub and asserts
   that the same tool calls are issued in the same order — useful for
   regression testing the orchestration code itself.

3. **ProvenanceBundle** assembles a final, signed-able JSON document from
   the trace + checkpoint + budget tracker + binary metadata. This is the
   canonical "what did Agent-G do for this binary" artifact for
   downstream auditors.

All file writes are line-atomic (single ``f.write(line)`` call). The trace
file lives next to ``checkpoint.json`` and ``events.jsonl`` so a crash
leaves a coherent audit-ready set of files.
"""
from __future__ import annotations
import hashlib
import json
import logging
import os
import sys
import threading
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("agent-g.trace")

TRACE_SCHEMA_VERSION = 1


# ── Trace writer ─────────────────────────────────────────────────────

class TraceWriter:
    """Append-only JSONL trace writer.

    Each line records one event of interest:
      - ``llm_call``  — outgoing prompt + incoming response (truncated body)
      - ``tool_call`` — name + params + result_text length
      - ``budget``    — periodic snapshot
      - ``event``     — passthrough for runtime events (compact, no tools)
      - ``end``       — final summary at investigation close
    """
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._counter = 0

    def _emit(self, kind: str, payload: Dict[str, Any]) -> None:
        rec = {
            "schema": TRACE_SCHEMA_VERSION,
            "seq": self._next_seq(),
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
                  + f".{int((time.time() % 1) * 1000):03d}Z",
            "kind": kind,
            **payload,
        }
        try:
            line = json.dumps(rec, default=str) + "\n"
            with self._lock:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
        except Exception as e:
            logger.warning("trace write FAILED: %s", e)

    def _next_seq(self) -> int:
        with self._lock:
            self._counter += 1
            return self._counter

    # ── Convenience emitters ──

    def llm_call(self, *, model: str, system_hash: str, messages_count: int,
                 input_tokens: int, output_tokens: int, response_text: str,
                 elapsed_s: float) -> None:
        self._emit("llm_call", {
            "model": model,
            "system_prompt_hash": system_hash,
            "messages_count": messages_count,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "response_text": response_text,
            "elapsed_s": round(elapsed_s, 3),
        })

    def tool_call(self, *, name: str, params: Dict[str, Any],
                  result_length: int, is_error: bool) -> None:
        self._emit("tool_call", {
            "name": name,
            "params": params,
            "result_length": result_length,
            "is_error": is_error,
        })

    def event(self, name: str, data: Dict[str, Any]) -> None:
        self._emit("event", {"name": name, "data": data})

    def budget(self, snapshot: Dict[str, Any]) -> None:
        self._emit("budget", snapshot)

    def end(self, *, exit_reason: str, final_text: str,
            iterations: int, tool_calls: int) -> None:
        self._emit("end", {
            "exit_reason": exit_reason,
            "final_text": final_text,
            "iterations": iterations,
            "tool_calls": tool_calls,
        })


def load_trace(path: Path) -> List[Dict[str, Any]]:
    """Load every record from a JSONL trace file."""
    records: List[Dict[str, Any]] = []
    p = Path(path)
    if not p.exists():
        return records
    with open(p, "r", encoding="utf-8") as f:
        for ln in f:
            ln = ln.strip()
            if not ln:
                continue
            try:
                records.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
    return records


# ── Replay harness ───────────────────────────────────────────────────

@dataclass
class ReplayResult:
    matched_tool_calls: int = 0
    mismatched_tool_calls: int = 0
    extra_tool_calls: int = 0
    missing_tool_calls: int = 0
    final_text_match: bool = False
    notes: List[str] = field(default_factory=list)


def replay_trace(trace_path: Path, runtime_factory) -> ReplayResult:
    """Replay a captured trace against a freshly-built runtime.

    ``runtime_factory`` is a callable that takes ``(stub_llm, recorded_tool_results)``
    and returns a ``ConversationRuntime`` instance configured with the
    stubs. The harness then calls ``runtime.run_turn(<initial prompt>)``
    and compares the resulting tool-call sequence against the recorded one.

    Returns a ``ReplayResult`` describing the diff. Use this in regression
    tests for the orchestrator: any change to ``conversation.py`` that
    re-orders or adds tool calls will surface here.
    """
    records = load_trace(trace_path)
    if not records:
        result = ReplayResult()
        result.notes.append("trace is empty")
        return result

    # Extract recorded LLM responses (in order) and tool results (in order)
    llm_responses = [r["response_text"] for r in records if r["kind"] == "llm_call"]
    tool_calls = [(r["name"], r.get("params", {})) for r in records if r["kind"] == "tool_call"]

    if not llm_responses:
        result = ReplayResult()
        result.notes.append("no llm_call records found in trace")
        return result

    # Build the stub LLM
    stub = StubLlmFromTrace(llm_responses)
    # Recorded tool results aren't stored in the trace (we only store
    # length + is_error). Replay still validates that the SAME tool calls
    # are issued in the SAME order — that's the regression we care about.
    runtime = runtime_factory(stub, recorded_tool_calls=tool_calls)

    # Drive the runtime with whatever the recorded first user message was
    initial_user = ""
    for r in records:
        if r["kind"] == "event" and r.get("name") == "user_input":
            initial_user = r.get("data", {}).get("text", "")
            break
    if not initial_user:
        initial_user = "(replay)"

    runtime.run_turn(initial_user)

    # Compare what the runtime issued against the recorded sequence
    issued = getattr(runtime, "_replay_issued_tool_calls", [])
    return _diff_tool_calls(issued, tool_calls)


def _diff_tool_calls(issued, recorded) -> ReplayResult:
    r = ReplayResult()
    n = min(len(issued), len(recorded))
    for i in range(n):
        if issued[i] == recorded[i]:
            r.matched_tool_calls += 1
        else:
            r.mismatched_tool_calls += 1
            r.notes.append(
                f"step {i}: issued={issued[i]} recorded={recorded[i]}"
            )
    if len(issued) > n:
        r.extra_tool_calls = len(issued) - n
    if len(recorded) > n:
        r.missing_tool_calls = len(recorded) - n
    return r


class StubLlmFromTrace:
    """Stub LLM that returns recorded responses one at a time.

    Drop-in for any object exposing ``call(messages, system_prompt) ->
    (response_text, usage)``. Used by the replay harness.
    """
    def __init__(self, responses: List[str]):
        self._responses = list(responses)
        self._index = 0

    def call(self, messages, system_prompt=None):
        if self._index >= len(self._responses):
            return ("[STUB: out of recorded responses]", _StubUsage())
        r = self._responses[self._index]
        self._index += 1
        return (r, _StubUsage())

    def query(self, prompt, phase=None):
        # Compatibility shim for clients that use ApiClient.query()
        if self._index >= len(self._responses):
            return "[STUB: out of recorded responses]"
        r = self._responses[self._index]
        self._index += 1
        return r


class _StubUsage:
    input_tokens = 0
    output_tokens = 0
    def add(self, _other):
        return self


# ── Provenance bundle ────────────────────────────────────────────────

@dataclass
class ProvenanceBundle:
    """The canonical 'what Agent-G did' artifact for one investigation.

    Includes everything an auditor needs to verify the run end-to-end:
      - binary identity (path + sha256)
      - model identity (provider/model/version) and prompt hash
      - aggregate stats (iterations, tool calls, tokens, cost, wall time)
      - exit reason + final verdict text
      - tool-call digest (sha256 of the canonicalized trace events)
      - agent-g version
      - timestamps

    The hash digests let an external verifier check that the trace file
    on disk hasn't been tampered with after the bundle was published.
    """
    schema_version: int = 1
    trace_id: str = ""
    agent_g_version: str = "0.1.0-dev"

    binary_path: str = ""
    binary_sha256: str = ""
    binary_size_bytes: int = 0

    model_provider: str = ""
    model_id: str = ""
    model_version: str = ""

    system_prompt_hash: str = ""
    prompt_version: str = "v0"

    started_at: str = ""
    finished_at: str = ""
    elapsed_s: float = 0.0

    iterations: int = 0
    tool_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0

    exit_reason: str = ""
    final_text: str = ""
    verdict: str = ""

    trace_path: str = ""
    trace_sha256: str = ""
    checkpoint_path: str = ""
    checkpoint_sha256: str = ""
    events_path: str = ""

    @staticmethod
    def _file_sha256(path: Path) -> str:
        if not path or not Path(path).exists():
            return ""
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(64 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def write(self, out_path: Path) -> None:
        """Compute remaining hash digests and atomically write to disk."""
        Path(out_path).parent.mkdir(parents=True, exist_ok=True)
        # Compute hashes lazily so callers can populate trace_path /
        # checkpoint_path before writing
        if self.binary_path and not self.binary_sha256:
            self.binary_sha256 = self._file_sha256(Path(self.binary_path))
            try:
                self.binary_size_bytes = Path(self.binary_path).stat().st_size
            except Exception:
                pass
        if self.trace_path and not self.trace_sha256:
            self.trace_sha256 = self._file_sha256(Path(self.trace_path))
        if self.checkpoint_path and not self.checkpoint_sha256:
            self.checkpoint_sha256 = self._file_sha256(Path(self.checkpoint_path))
        if not self.finished_at:
            self.finished_at = datetime.now(timezone.utc).isoformat()
        payload = asdict(self)
        tmp = Path(str(out_path) + ".tmp")
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)
        os.replace(tmp, out_path)
        logger.info("provenance bundle written: %s", out_path)


def build_provenance_from_run(
    *,
    trace_id: str,
    runs_dir: Path,
    binary_path: str,
    model_id: str,
    provider: str,
    system_prompt: str,
    summary,  # TurnSummary or duck-typed equivalent
    budget_tracker=None,
    verdict: str = "",
    started_at: Optional[str] = None,
) -> ProvenanceBundle:
    """Construct a ``ProvenanceBundle`` from a finished investigation.

    ``runs_dir`` is the per-trace directory containing trace.jsonl,
    checkpoint.json, and events.jsonl. The bundle is written to
    ``runs_dir/provenance.json``.
    """
    runs_dir = Path(runs_dir)
    bundle = ProvenanceBundle(
        trace_id=trace_id,
        binary_path=str(binary_path),
        model_provider=provider,
        model_id=model_id,
        model_version=model_id,  # provider can override later if it has a version field
        system_prompt_hash=hashlib.sha256(
            (system_prompt or "").encode("utf-8")
        ).hexdigest(),
        started_at=started_at or "",
        iterations=getattr(summary, "iterations", 0) or 0,
        tool_calls=getattr(summary, "tool_calls", 0) or 0,
        exit_reason=getattr(summary, "exit_reason", "") or "",
        final_text=(getattr(summary, "final_text", "") or "")[:5000],
        verdict=verdict,
        trace_path=str(runs_dir / "trace.jsonl"),
        checkpoint_path=str(runs_dir / "checkpoint.json"),
        events_path=str(runs_dir / "events.jsonl"),
    )
    if budget_tracker is not None:
        snap = budget_tracker.snapshot()
        bundle.input_tokens = snap.get("input_tokens", 0)
        bundle.output_tokens = snap.get("output_tokens", 0)
        bundle.cost_usd = snap.get("cost_usd", 0.0)
        bundle.elapsed_s = snap.get("elapsed_s", 0.0)
    out = runs_dir / "provenance.json"
    bundle.write(out)
    return bundle
