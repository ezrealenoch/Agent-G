"""Human-readable + machine-parseable tool call logger.

Writes one JSON line per tool call to a persistent log file (default:
``logs/tool_calls.jsonl``). Each entry includes timestamp, tool name,
parameters, result preview, duration, and error status.

Usage::

    tool_log = ToolCallLogger(Path("logs/tool_calls.jsonl"))
    runtime.tools = LoggingToolRunner(runtime.tools, tool_log)

The ``LoggingToolRunner`` wraps any tool runner (including
``CompositeToolRunner``) and intercepts ``execute()`` to capture
timing and results without modifying the underlying tool system.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

logger = logging.getLogger(__name__)

# Max chars of tool result to include in the log entry
_RESULT_PREVIEW_LIMIT = 500


class ToolCallLogger:
    """Append-only JSONL logger for tool calls."""

    def __init__(self, path: Path, trace_id: str = ""):
        self._path = path
        self._trace_id = trace_id
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._call_count = 0

    def log(
        self,
        tool_name: str,
        params: Dict[str, Any],
        result_text: str,
        is_error: bool,
        elapsed_s: float,
        binary_name: str = "",
    ) -> None:
        self._call_count += 1
        preview = result_text[:_RESULT_PREVIEW_LIMIT]
        if len(result_text) > _RESULT_PREVIEW_LIMIT:
            preview += f"... ({len(result_text)} chars total)"

        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "trace_id": self._trace_id,
            "call_no": self._call_count,
            "binary": binary_name,
            "tool": tool_name,
            "params": params,
            "result_preview": preview,
            "result_length": len(result_text),
            "is_error": is_error,
            "elapsed_s": round(elapsed_s, 3),
        }
        try:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, default=str) + "\n")
        except Exception as e:
            logger.debug("tool log write failed: %s", e)

    @property
    def call_count(self) -> int:
        return self._call_count


class LoggingToolRunner:
    """Transparent wrapper that logs every tool call with timing.

    Drop-in replacement for ToolRunner or CompositeToolRunner —
    delegates ``execute()`` to the inner runner and logs the result.
    """

    def __init__(
        self,
        inner,
        tool_logger: ToolCallLogger,
        binary_name_fn: Optional[callable] = None,
    ):
        self._inner = inner
        self._log = tool_logger
        self._binary_name_fn = binary_name_fn or (lambda: "")

    def execute(self, tool_name: str, params: dict) -> Tuple[str, bool]:
        t0 = time.perf_counter()
        result_text, is_error = self._inner.execute(tool_name, params)
        elapsed = time.perf_counter() - t0

        self._log.log(
            tool_name=tool_name,
            params=params,
            result_text=result_text,
            is_error=is_error,
            elapsed_s=elapsed,
            binary_name=self._binary_name_fn(),
        )
        return result_text, is_error

    # Forward attribute access to the inner runner so CompositeToolRunner's
    # delegate attribute remains accessible.
    def __getattr__(self, name):
        return getattr(self._inner, name)
