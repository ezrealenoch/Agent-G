"""Observability: structured JSON logging + trace_id propagation + alert sinks.

Three responsibilities in one module because they share the contextvar
trace_id and a common configure-at-startup pattern:

1. **Structured JSON logs** — a ``logging.Formatter`` that emits one JSON
   object per record with the current ``trace_id`` attached. Drop-in
   replacement for the default stderr formatter; SIEM-friendly.

2. **Trace ID contextvar** — a ``contextvars.ContextVar`` holding the current
   investigation's trace_id. Every log record pulls from this automatically,
   so callers don't need to thread the id through function signatures.

3. **Alert sinks** — a plugin pattern for escalating "this needs a human"
   events (BLANK_RESPONSE, circuit open, budget exceeded, etc.) to external
   channels. Built-in sinks: console, file (JSONL), generic webhook (POST
   JSON to a URL, fire-and-forget).

Usage::

    from src.runtime.observability import (
        configure_structured_logging, new_trace_id, set_trace_id,
        AlertSink, ConsoleAlertSink, WebhookAlertSink, alert_all,
    )

    configure_structured_logging(level="INFO", json=True)
    tid = new_trace_id()
    set_trace_id(tid)
    logger.info("started investigation")  # JSON record has trace_id=tid

    sinks = [ConsoleAlertSink(), WebhookAlertSink("https://slack.example/hook")]
    alert_all(sinks, "warning", "blank_response", {"model": "gpt-5.4", "binary": "sample_xxx.bin"})
"""
from __future__ import annotations
import contextvars
import json
import logging
import os
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol

# ── Trace ID contextvar ──────────────────────────────────────────────

_trace_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar(
    "agent_g_trace_id", default=None,
)


def new_trace_id() -> str:
    """Generate a fresh trace_id. 12 chars is enough for a single deployment."""
    return uuid.uuid4().hex[:12]


def set_trace_id(tid: Optional[str]) -> contextvars.Token:
    """Set the current trace_id and return a token for later reset."""
    return _trace_id_var.set(tid)


def get_trace_id() -> Optional[str]:
    return _trace_id_var.get()


def reset_trace_id(token: contextvars.Token) -> None:
    _trace_id_var.reset(token)


# ── JSON formatter ───────────────────────────────────────────────────

# Fields we intentionally drop because they're noisy or duplicate.
_DROP_FIELDS = {"args", "msg", "exc_info", "exc_text", "stack_info"}


class JsonFormatter(logging.Formatter):
    """Log formatter that emits one JSON object per record.

    Includes:
      - timestamp (ISO-8601 UTC)
      - level
      - logger name
      - message (rendered)
      - trace_id (from contextvar if set)
      - any ``extra=`` fields passed to the log call

    Exceptions are rendered into ``exc_info_text``. Unknown non-serializable
    objects are coerced to ``repr()``.
    """

    def format(self, record: logging.LogRecord) -> str:  # noqa: D401
        data: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(record.created))
                  + f".{int(record.msecs):03d}Z",
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        tid = get_trace_id()
        if tid:
            data["trace_id"] = tid
        # Attach any extra attributes the caller set via ``logger.info(..., extra={...})``.
        standard_attrs = {
            "name", "msg", "args", "levelname", "levelno", "pathname",
            "filename", "module", "exc_info", "exc_text", "stack_info",
            "lineno", "funcName", "created", "msecs", "relativeCreated",
            "thread", "threadName", "processName", "process", "taskName",
        }
        for k, v in record.__dict__.items():
            if k in standard_attrs or k in _DROP_FIELDS or k.startswith("_"):
                continue
            try:
                json.dumps(v)  # serializable?
                data[k] = v
            except (TypeError, ValueError):
                data[k] = repr(v)
        if record.exc_info:
            data["exc_info_text"] = self.formatException(record.exc_info)
        try:
            return json.dumps(data, default=str)
        except Exception:
            # Last-ditch: drop unserializable and try again
            safe = {k: repr(v) for k, v in data.items()}
            return json.dumps(safe)


def configure_structured_logging(
    level: str = "INFO",
    json_output: bool = True,
    stream=None,
    logfile: Optional[str] = None,
) -> None:
    """Configure root logging with JSON output + optional log file.

    Call this once at process startup. Idempotent — replaces any previously
    attached handlers by the same class.
    """
    root = logging.getLogger()
    root.setLevel(level.upper())

    # Remove prior agent-g handlers so re-configuration is clean
    for h in list(root.handlers):
        if getattr(h, "_agent_g", False):
            root.removeHandler(h)

    formatter = JsonFormatter() if json_output else logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    stream_handler = logging.StreamHandler(stream or sys.stderr)
    stream_handler.setFormatter(formatter)
    stream_handler._agent_g = True  # type: ignore[attr-defined]
    root.addHandler(stream_handler)

    if logfile:
        Path(logfile).parent.mkdir(parents=True, exist_ok=True)
        fh = logging.FileHandler(logfile, encoding="utf-8")
        fh.setFormatter(formatter)
        fh._agent_g = True  # type: ignore[attr-defined]
        root.addHandler(fh)


# ── Alert sinks ──────────────────────────────────────────────────────

class AlertSink(Protocol):
    """An alert destination. Implementations should be fire-and-forget and
    MUST NOT raise — failures are logged but never propagate."""
    def emit(self, severity: str, event: str, context: Dict[str, Any]) -> None: ...


class ConsoleAlertSink:
    """Print alerts to stderr in a human-readable format."""
    def emit(self, severity: str, event: str, context: Dict[str, Any]) -> None:
        try:
            tid = get_trace_id() or "-"
            sys.stderr.write(
                f"[ALERT/{severity.upper()}] event={event} trace={tid} ctx={json.dumps(context, default=str)}\n"
            )
        except Exception as e:
            sys.stderr.write(f"[ALERT_SINK_ERROR] {e}\n")


class FileAlertSink:
    """Append alerts to a JSONL file. Safe for shared writes (line-atomic)."""
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def emit(self, severity: str, event: str, context: Dict[str, Any]) -> None:
        record = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "severity": severity,
            "event": event,
            "trace_id": get_trace_id(),
            "context": context,
        }
        try:
            line = json.dumps(record, default=str) + "\n"
            with self._lock:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
        except Exception as e:
            sys.stderr.write(f"[FILE_ALERT_SINK_ERROR] {e}\n")


class WebhookAlertSink:
    """POST alerts to a generic webhook URL (Slack-style payload)."""
    def __init__(self, url: str, timeout: float = 5.0):
        self.url = url
        self.timeout = timeout

    def emit(self, severity: str, event: str, context: Dict[str, Any]) -> None:
        try:
            import requests  # local import so this module stays lightweight
        except ImportError:
            sys.stderr.write("[WEBHOOK_ALERT_SINK] 'requests' not installed, skipping\n")
            return
        payload = {
            "text": f"[{severity.upper()}] Agent-G alert: {event}",
            "severity": severity,
            "event": event,
            "trace_id": get_trace_id(),
            "context": context,
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        try:
            requests.post(self.url, json=payload, timeout=self.timeout)
        except Exception as e:
            sys.stderr.write(f"[WEBHOOK_ALERT_SINK_ERROR] {e}\n")


def alert_all(sinks: List[AlertSink], severity: str, event: str, context: Dict[str, Any]) -> None:
    """Fire an alert across every configured sink. Swallows sink errors."""
    for s in sinks:
        try:
            s.emit(severity, event, context)
        except Exception as e:
            sys.stderr.write(f"[ALERT_DISPATCH_ERROR] sink={type(s).__name__} err={e}\n")


# ── Persistent event stream ──────────────────────────────────────────

class EventJsonlSink:
    """Append runtime events to a JSONL stream file.

    Wraps the existing ``on_event`` callback pattern used by
    ConversationRuntime / EventEmitter. Attach via::

        jl = EventJsonlSink("runs/<trace_id>/events.jsonl")
        runtime = ConversationRuntime(..., on_event=jl.emit)

    Each line is a single JSON object with ``ts``, ``trace_id``, ``event``,
    and the event data dict.
    """
    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def emit(self, event_name: str, data: Dict[str, Any]) -> None:
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime())
                  + f".{int((time.time() % 1) * 1000):03d}Z",
            "trace_id": get_trace_id(),
            "event": event_name,
            "data": data,
        }
        try:
            line = json.dumps(rec, default=str) + "\n"
            with self._lock:
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line)
        except Exception as e:
            sys.stderr.write(f"[EVENT_SINK_ERROR] {e}\n")
