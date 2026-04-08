"""Checkpointing for Agent-G investigations.

Periodically serializes the in-progress investigation state to disk so that
a crashed or killed investigation can be resumed without losing work. The
checkpoint captures the ``Session`` conversation history, the coverage
tracker, the notebook, the lead queue, and a minimal summary of the
ConversationSummary in flight.

Design goals:
  - Atomic writes (write .tmp → os.replace → final)
  - Opt-in via ``BridgeLite(checkpoint_path=...)``
  - Language-independent JSON format (no pickle) so humans can inspect the
    state and other tools can consume it
  - Idempotent resume: loading a checkpoint on startup populates the runtime
    as if the earlier process had just finished the last recorded iteration

Scope:
  This first version checkpoints the conversation session + iteration count
  + exit state. Blackboard state, coverage tracker snapshots, and lead queue
  serialization are stubbed out — they can be added as those subsystems grow
  serialize() hooks.
"""
from __future__ import annotations
import json
import logging
import os
import tempfile
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("agent-g.checkpoint")

CHECKPOINT_SCHEMA_VERSION = 1


@dataclass
class CheckpointData:
    """Serializable investigation state. Kept intentionally minimal.

    New fields should be added with sane defaults so older checkpoints
    remain loadable after a schema bump.
    """
    schema_version: int = CHECKPOINT_SCHEMA_VERSION
    trace_id: str = ""
    binary_name: str = ""
    task_kind: str = ""
    system_prompt_hash: str = ""

    # Timestamps
    started_at: str = ""
    last_checkpoint_at: str = ""
    elapsed_s: float = 0.0

    # Runtime counters
    iterations_completed: int = 0
    tool_calls_completed: int = 0
    tokens_in_total: int = 0
    tokens_out_total: int = 0

    # Conversation session (list of message dicts)
    session_messages: List[Dict[str, Any]] = field(default_factory=list)

    # Exit state (set once the runtime terminates or is mid-loop)
    exit_reason: Optional[str] = None  # None means "still running"
    final_text: Optional[str] = None

    # Free-form metadata pouch for subsystem snapshots that don't yet have
    # a first-class schema (blackboard, coverage, leads, notebook, etc.)
    subsystem_state: Dict[str, Any] = field(default_factory=dict)


def _atomic_write_json(path: Path, data: dict) -> None:
    """Atomically write JSON to ``path`` (write .tmp in same dir, then rename).

    Using os.replace for atomicity on all platforms. Preserves a single
    corruption boundary: if the process dies mid-write the old checkpoint
    remains intact.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path_str = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp_path_str, str(path))
    except Exception:
        try:
            os.unlink(tmp_path_str)
        except OSError:
            pass
        raise


class CheckpointWriter:
    """Writes checkpoints to disk at the caller's request.

    Usage:
        cw = CheckpointWriter(path=Path("runs/trace_abc/checkpoint.json"))
        cw.save(CheckpointData(...))
        ...
        cw.save(CheckpointData(...))  # updates in place, atomic

    The writer remembers the last save timestamp so rate-limited checkpoint
    strategies (save no more than once every N seconds) can be layered on top.
    """

    def __init__(self, path: Path):
        self.path = Path(path)

    def save(self, data: CheckpointData) -> None:
        """Atomically save the checkpoint data to disk."""
        data.last_checkpoint_at = datetime.now(timezone.utc).isoformat()
        payload = asdict(data)
        try:
            _atomic_write_json(self.path, payload)
            logger.debug(
                "checkpoint saved: trace=%s iter=%d tools=%d path=%s",
                data.trace_id, data.iterations_completed,
                data.tool_calls_completed, self.path,
            )
        except Exception as e:
            logger.warning(
                "checkpoint save FAILED path=%s err=%s", self.path, e,
            )

    def exists(self) -> bool:
        return self.path.exists()

    def load(self) -> Optional[CheckpointData]:
        """Load the checkpoint from disk, or return None if missing/corrupt.

        Forward-compatible: unknown keys are dropped, missing keys get the
        dataclass default, and schema version mismatches emit a warning but
        do not raise. Callers decide whether to resume or restart.
        """
        if not self.path.exists():
            return None
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            logger.warning("checkpoint load FAILED path=%s err=%s", self.path, e)
            return None

        if raw.get("schema_version", 0) != CHECKPOINT_SCHEMA_VERSION:
            logger.warning(
                "checkpoint schema mismatch: on-disk=%s expected=%s",
                raw.get("schema_version"), CHECKPOINT_SCHEMA_VERSION,
            )

        # Build dataclass with only known fields
        known = {f: raw.get(f) for f in CheckpointData.__dataclass_fields__}
        known["session_messages"] = known.get("session_messages") or []
        known["subsystem_state"] = known.get("subsystem_state") or {}
        return CheckpointData(**{k: v for k, v in known.items() if v is not None})

    def clear(self) -> None:
        """Remove the checkpoint file (e.g. after successful completion)."""
        try:
            if self.path.exists():
                self.path.unlink()
                logger.debug("checkpoint cleared: %s", self.path)
        except OSError as e:
            logger.warning("checkpoint clear FAILED path=%s err=%s", self.path, e)


def session_to_dicts(session) -> List[Dict[str, Any]]:
    """Best-effort conversion of a ``Session`` object to plain dicts.

    Handles both the current ``Session`` in src/runtime/conversation.py and
    any other shape with a ``.messages`` iterable of ``Message`` objects that
    expose ``.role`` and ``.content``. Attributes that can't be serialized
    are coerced to string repr.
    """
    out: List[Dict[str, Any]] = []
    messages = getattr(session, "messages", None) or []
    for m in messages:
        try:
            d = {
                "role": getattr(m, "role", "unknown"),
                "content": getattr(m, "content", None),
            }
            # Normalize content to str-ish
            if d["content"] is not None and not isinstance(d["content"], (str, list, dict)):
                d["content"] = repr(d["content"])
            out.append(d)
        except Exception:
            out.append({"role": "unknown", "content": repr(m)})
    return out
