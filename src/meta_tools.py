"""Meta-tools and CompositeToolRunner for interactive chat mode.

Meta-tools (load_binary, switch_binary, list_sessions) operate on the
SessionManager rather than on Ghidra. The CompositeToolRunner dispatches
these locally and delegates all other tool calls to the active binary's
ToolRunner.
"""
from __future__ import annotations

import logging
from typing import Callable, Dict, Optional, Tuple

from src.session_manager import SessionManager

logger = logging.getLogger(__name__)


class CompositeToolRunner:
    """Dispatches meta-tools locally, delegates Ghidra tools to the active binary."""

    def __init__(self, meta_handlers: Dict[str, Callable]):
        self._meta = meta_handlers
        self.delegate: Optional[object] = None  # ToolRunner, swapped on load/switch

    def execute(self, tool_name: str, params: dict) -> Tuple[str, bool]:
        if tool_name in self._meta:
            return self._meta[tool_name](params)
        if self.delegate is None:
            return (
                "[ERROR] No binary loaded. Use load_binary(path=\"...\") "
                "to load a binary first, or ask the user for a file path.",
                True,
            )
        return self.delegate.execute(tool_name, params)


# ── Meta-tool handler factories ──────────────────────────────────


def make_load_binary_handler(
    session_mgr: SessionManager,
    composite: CompositeToolRunner,
) -> Callable:
    """Handler for EXECUTE: load_binary(path="...")"""

    def handler(params: dict) -> Tuple[str, bool]:
        path = params.get("path", "")
        if not path:
            return "[ERROR] path is required.", True
        name = params.get("name") or None
        try:
            print(f"[loading binary: {path}...]", flush=True)
            bs = session_mgr.load_binary(path, name=name)
            composite.delegate = bs.tool_runner
            result = (
                f"Binary '{bs.name}' loaded from {bs.binary_path}. "
                f"It is now the active binary.\n\n"
                f"{bs.bootstrap_text}"
            )
            return result, False
        except FileNotFoundError as e:
            return f"[ERROR] {e}", True
        except Exception as e:
            logger.exception("Failed to load binary")
            return f"[ERROR] Failed to load binary: {e}", True

    return handler


def make_switch_binary_handler(
    session_mgr: SessionManager,
    composite: CompositeToolRunner,
) -> Callable:
    """Handler for EXECUTE: switch_binary(name="...")"""

    def handler(params: dict) -> Tuple[str, bool]:
        name = params.get("name", "")
        if not name:
            return "[ERROR] name is required.", True
        try:
            bs = session_mgr.switch(name)
            composite.delegate = bs.tool_runner
            return (
                f"Switched to binary '{name}' ({bs.binary_path}). "
                f"All tool calls now target this binary."
            ), False
        except KeyError as e:
            return f"[ERROR] {e}", True

    return handler


def make_list_sessions_handler(
    session_mgr: SessionManager,
) -> Callable:
    """Handler for EXECUTE: list_sessions()"""

    def handler(params: dict) -> Tuple[str, bool]:
        sessions = session_mgr.list_sessions()
        if not sessions:
            return (
                "No binaries loaded. Use load_binary(path=\"...\") "
                "to load one."
            ), False
        lines = ["Loaded binaries:"]
        for name, path, is_active in sessions:
            marker = " << active" if is_active else ""
            lines.append(f"  {name}: {path}{marker}")
        return "\n".join(lines), False

    return handler


def make_list_directory_handler() -> Callable:
    """Handler for EXECUTE: list_directory(path="...")"""

    def handler(params: dict) -> Tuple[str, bool]:
        import os
        from pathlib import Path

        raw = params.get("path", "").strip()
        if not raw:
            raw = "."
        target = Path(raw).expanduser().resolve()

        if not target.exists():
            return f"[ERROR] Path not found: {target}", True
        if not target.is_dir():
            # It's a file — show info about it instead
            size = target.stat().st_size
            return (
                f"'{target.name}' is a file ({size:,} bytes), not a directory.\n"
                f"Full path: {target}\n"
                f"To analyze it, use: load_binary(path=\"{target}\")"
            ), False

        try:
            entries = sorted(target.iterdir(), key=lambda p: (p.is_file(), p.name.lower()))
            lines = [f"Contents of {target}:\n"]
            dirs = []
            files = []
            for e in entries:
                if e.name.startswith("."):
                    continue  # skip hidden
                if e.is_dir():
                    dirs.append(f"  [dir]  {e.name}/")
                else:
                    size = e.stat().st_size
                    files.append(f"  [file] {e.name}  ({size:,} bytes)")
            lines.extend(dirs[:50])
            lines.extend(files[:50])
            total = len(dirs) + len(files)
            if total > 100:
                lines.append(f"  ... and {total - 100} more entries")
            if total == 0:
                lines.append("  (empty directory)")
            return "\n".join(lines), False
        except PermissionError:
            return f"[ERROR] Permission denied: {target}", True

    return handler


def make_file_info_handler() -> Callable:
    """Handler for EXECUTE: file_info(path="...")"""

    def handler(params: dict) -> Tuple[str, bool]:
        from pathlib import Path
        import time as _time

        raw = params.get("path", "").strip()
        if not raw:
            return "[ERROR] path is required.", True
        target = Path(raw).expanduser().resolve()

        if not target.exists():
            return f"[ERROR] Path not found: {target}", True
        if target.is_dir():
            count = sum(1 for _ in target.iterdir())
            return (
                f"'{target.name}' is a directory with {count} entries.\n"
                f"Use list_directory(path=\"{target}\") to browse it."
            ), False

        st = target.stat()
        modified = _time.strftime("%Y-%m-%d %H:%M:%S", _time.localtime(st.st_mtime))

        # Read first 4 bytes for magic detection
        magic = ""
        try:
            with open(target, "rb") as f:
                header = f.read(4)
            if header[:2] == b"MZ":
                magic = "PE executable (Windows)"
            elif header[:4] == b"\x7fELF":
                magic = "ELF executable (Linux)"
            elif header[:4] == b"\xfe\xed\xfa\xce" or header[:4] == b"\xce\xfa\xed\xfe":
                magic = "Mach-O executable (macOS)"
            elif header[:4] == b"\xca\xfe\xba\xbe":
                magic = "Mach-O universal binary / Java class"
            elif header[:2] == b"PK":
                magic = "ZIP archive (or APK/JAR)"
            else:
                magic = f"unknown (magic: {header.hex()})"
        except Exception:
            magic = "unreadable"

        return (
            f"File: {target.name}\n"
            f"Path: {target}\n"
            f"Size: {st.st_size:,} bytes\n"
            f"Modified: {modified}\n"
            f"Type: {magic}\n"
            f"\nTo analyze: load_binary(path=\"{target}\")"
        ), False

    return handler


def make_web_search_handler() -> Callable:
    """Handler for EXECUTE: web_search(query="...")

    Uses DuckDuckGo via the ``ddgs`` package (no API key required).
    Falls back gracefully if the package is not installed.
    """

    def handler(params: dict) -> Tuple[str, bool]:
        query = params.get("query", "").strip()
        if not query:
            return "[ERROR] query is required.", True
        max_results = int(params.get("max_results", 5))
        try:
            from ddgs import DDGS
        except ImportError:
            return (
                "[ERROR] Web search requires the 'ddgs' package. "
                "Install with: pip install agent-g[search]"
            ), True
        try:
            results = DDGS().text(query, max_results=max_results)
            if not results:
                return f"No results found for: {query}", False
            lines = []
            for i, r in enumerate(results, 1):
                body = r.get("body", "")[:300]
                lines.append(
                    f"{i}. {r.get('title', '(no title)')}\n"
                    f"   {body}\n"
                    f"   URL: {r.get('href', '')}"
                )
            return "\n\n".join(lines), False
        except Exception as e:
            return f"[ERROR] Search failed: {e}", True

    return handler


def build_composite_runner(session_mgr: SessionManager) -> CompositeToolRunner:
    """Wire up the CompositeToolRunner with all meta-tool handlers."""
    composite = CompositeToolRunner({})
    composite._meta = {
        "load_binary": make_load_binary_handler(session_mgr, composite),
        "switch_binary": make_switch_binary_handler(session_mgr, composite),
        "list_sessions": make_list_sessions_handler(session_mgr),
        "list_directory": make_list_directory_handler(),
        "file_info": make_file_info_handler(),
        "web_search": make_web_search_handler(),
    }
    return composite
