"""Simplified event emitter for headless terminal output.

Replaces OGhidra's thread-safe UI-dispatching EventEmitter with
direct terminal printing. No tkinter, no thread dispatch, no callbacks.
"""

import logging
from datetime import datetime

logger = logging.getLogger("agent-g.events")


class EventEmitter:
    """Minimal event emitter that prints chain-of-thought to terminal."""

    def emit_cot(self, source: str, message: str):
        """Print chain-of-thought reasoning to terminal."""
        ts = datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] [{source}] {message}")

    def emit_agent_event(self, event_type: str, data: dict = None):
        """Log structured agent events (debug level)."""
        logger.debug("event: %s %s", event_type, data or {})

    def on(self, event_type: str, callback):
        """No-op: headless mode has no event subscribers."""
        pass

    def off(self, event_type: str, callback=None):
        """No-op: headless mode has no event subscribers."""
        pass
