"""Multi-binary session manager for interactive chat mode.

Tracks multiple loaded binaries, each with its own Ghidra instance,
tool executor, and decompilation cache. One binary is "active" at a
time — all tool calls route to the active binary's Ghidra instance.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from src.command_parser import CommandParser
from src.config import GhidraMCPConfig
from src.ghidra_client import GhidraMCPClient
from src.runtime.bootstrap import run_discovery_bootstrap
from src.runtime.ghidra_pool import GhidraHandle, GhidraPool
from src.runtime.tool_runner import ToolRunner
from src.tool_executor import ToolExecutor

logger = logging.getLogger(__name__)


@dataclass
class BinarySession:
    """One loaded binary with its own Ghidra instance and tool plumbing."""
    name: str
    binary_path: Path
    handle: GhidraHandle
    tool_executor: ToolExecutor
    tool_runner: ToolRunner
    bootstrap_text: str = ""
    notes_dir: Optional[Path] = None

    def ensure_notes_dir(self) -> Path:
        """Create and return the notes directory for this binary."""
        if self.notes_dir is None:
            raise ValueError("notes_dir not set")
        self.notes_dir.mkdir(parents=True, exist_ok=True)
        return self.notes_dir


class SessionManager:
    """Manages multiple loaded binaries for interactive chat sessions."""

    def __init__(
        self,
        pool: GhidraPool,
        ghidra_config: GhidraMCPConfig,
        command_parser: CommandParser,
        runs_dir: Optional[Path] = None,
    ):
        self._pool = pool
        self._ghidra_config = ghidra_config
        self._parser = command_parser
        self._runs_dir = runs_dir or Path("runs")
        self._sessions: Dict[str, BinarySession] = {}
        self._active_name: Optional[str] = None

    @property
    def active(self) -> Optional[BinarySession]:
        if self._active_name is None:
            return None
        return self._sessions.get(self._active_name)

    @property
    def active_name(self) -> Optional[str]:
        return self._active_name

    def _unique_name(self, base: str) -> str:
        if base not in self._sessions:
            return base
        for i in range(2, 100):
            candidate = f"{base}-{i}"
            if candidate not in self._sessions:
                return candidate
        return f"{base}-{id(base)}"

    def load_binary(self, path: str, name: Optional[str] = None) -> BinarySession:
        """Load a binary, spin up a Ghidra instance, run bootstrap.

        Sets the new binary as the active session.
        """
        binary_path = Path(path).expanduser().resolve()
        if not binary_path.exists():
            raise FileNotFoundError(f"Path not found: {binary_path}")
        if binary_path.is_dir():
            raise ValueError(
                f"'{binary_path}' is a directory, not a binary file. "
                f"Please provide a path to a specific executable or binary."
            )

        session_name = self._unique_name(name or binary_path.stem)

        logger.info("Loading binary %s as '%s'...", binary_path, session_name)
        handle = self._pool.acquire(str(binary_path))

        # Build a GhidraMCPClient pointing at this instance's port.
        # Auth token resolves via sidecar file automatically.
        cfg = self._ghidra_config.model_copy(
            update={"base_url": handle.base_url}
        )
        ghidra_client = GhidraMCPClient(cfg)

        tool_executor = ToolExecutor(ghidra_client, self._parser)
        tool_runner = ToolRunner(tool_executor, self._parser)

        # Run bootstrap discovery
        bootstrap_text = run_discovery_bootstrap(
            tool_runner, binary_name=binary_path.name,
        )

        notes_dir = self._runs_dir / "notes" / session_name
        notes_dir.mkdir(parents=True, exist_ok=True)

        session = BinarySession(
            name=session_name,
            binary_path=binary_path,
            handle=handle,
            tool_executor=tool_executor,
            tool_runner=tool_runner,
            bootstrap_text=bootstrap_text,
            notes_dir=notes_dir,
        )
        self._sessions[session_name] = session
        self._active_name = session_name
        logger.info("Binary '%s' loaded and active (port %s)", session_name, handle.port)
        return session

    def switch(self, name: str) -> BinarySession:
        """Switch the active binary. Raises KeyError if not found."""
        if name not in self._sessions:
            available = list(self._sessions.keys())
            raise KeyError(
                f"No session named '{name}'. Available: {available}"
            )
        self._active_name = name
        return self._sessions[name]

    def close_session(self, name: str) -> None:
        """Release a binary's Ghidra instance back to the pool."""
        session = self._sessions.pop(name, None)
        if session is None:
            return
        self._pool.release(session.handle)
        if self._active_name == name:
            # Switch to another session if available, else None
            self._active_name = next(iter(self._sessions), None)

    def list_sessions(self) -> List[Tuple[str, str, bool]]:
        """Return [(name, binary_path, is_active), ...]."""
        return [
            (name, str(s.binary_path), name == self._active_name)
            for name, s in self._sessions.items()
        ]

    def close_all(self) -> None:
        """Release all Ghidra instances."""
        for name in list(self._sessions):
            self.close_session(name)
