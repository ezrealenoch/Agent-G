"""Driver-mode primitives: provision a Ghidra HTTP server for one binary,
hold the session open across many external curl-style queries, then tear
down cleanly.

This is the library that ``agent-g drive`` and ``agent-g g`` build on. The
mode is intended for cases where Claude Code (or any external orchestrator)
wants to be the analyst — querying Ghidra via authenticated HTTP — instead
of using Agent-G's internal LLM loop.

Public API
----------
  start_drive(binary_path, *, port=None, ready_timeout=None,
              session_file=None) -> SessionInfo
      Provision a Ghidra instance, write the session file, return info.

  stop_drive(*, session_file=None, force=False) -> bool
      Kill the provisioner, clean orphan JVMs and stale token sidecars,
      remove the session file. Idempotent — returns True if anything was
      cleaned, False if nothing was running.

  status_drive(*, session_file=None) -> Optional[SessionInfo]
      Read the session file and verify the JVM is still alive. Returns
      None if nothing is running.

  query(endpoint, params=None, *, session_file=None, timeout=120) -> str
      Authenticated GET against the running Ghidra. Returns response body
      as a string; raises on missing session, dead JVM, or HTTP errors.

Lifecycle invariant
-------------------
At most one drive session per host at a time. start_drive() refuses to
start if the session file exists and the PID it names is still alive.
The error message points the user at ``agent-g drive stop``. This
sidesteps the concurrent-pool-spawn race that produced 401 storms in the
prior multi-binary investigation work.
"""
from __future__ import annotations

import json
import logging
import os
import signal
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("agent-g.drive")


DEFAULT_SESSION_FILENAME = "ghidra_session.json"


# ── Session info ────────────────────────────────────────────────────


@dataclass
class SessionInfo:
    """The contents of ghidra_session.json."""
    binary_path: str
    binary_name: str
    base_url: str
    auth_token: str
    port: int
    pid: int
    started_at: float


def _resolve_session_file(session_file: Optional[Path]) -> Path:
    """Resolve the session file path with the standard precedence.

    1. Explicit ``session_file`` argument
    2. ``AGENT_G_SESSION_FILE`` env var
    3. ``./ghidra_session.json`` in the current working directory
    """
    if session_file is not None:
        return Path(session_file).resolve()
    env = os.environ.get("AGENT_G_SESSION_FILE")
    if env:
        return Path(env).resolve()
    return Path.cwd() / DEFAULT_SESSION_FILENAME


def _read_session(session_file: Path) -> Optional[SessionInfo]:
    if not session_file.exists():
        return None
    try:
        data = json.loads(session_file.read_text(encoding="utf-8"))
        return SessionInfo(
            binary_path=str(data["binary_path"]),
            binary_name=str(data["binary_name"]),
            base_url=str(data["base_url"]),
            auth_token=str(data["auth_token"]),
            port=int(data["port"]),
            pid=int(data["pid"]),
            started_at=float(data["started_at"]),
        )
    except (json.JSONDecodeError, KeyError, ValueError) as exc:
        logger.warning("session file %s is unreadable (%s); treating as stale", session_file, exc)
        return None


def _write_session(session_file: Path, info: SessionInfo) -> None:
    session_file.parent.mkdir(parents=True, exist_ok=True)
    session_file.write_text(json.dumps(asdict(info), indent=2), encoding="utf-8")


def _is_alive(pid: int) -> bool:
    """Cross-platform check: is the process with this PID still running?"""
    if pid <= 0:
        return False
    if sys.platform == "win32":
        try:
            import ctypes  # noqa: PLC0415
            kernel32 = ctypes.windll.kernel32
            PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
            STILL_ACTIVE = 259
            handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
            if not handle:
                return False
            try:
                exit_code = ctypes.c_ulong()
                if kernel32.GetExitCodeProcess(handle, ctypes.byref(exit_code)):
                    return exit_code.value == STILL_ACTIVE
                return False
            finally:
                kernel32.CloseHandle(handle)
        except Exception:
            return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        # Process exists but we can't signal it — still alive
        return True


def _kill(pid: int) -> None:
    """Best-effort kill of the named PID. Cross-platform."""
    if pid <= 0:
        return
    if sys.platform == "win32":
        subprocess.run(
            ["taskkill", "/F", "/PID", str(pid)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            check=False,
        )
        return
    try:
        os.kill(pid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError):
        return
    # Give it a moment to handle SIGTERM gracefully
    for _ in range(20):
        if not _is_alive(pid):
            return
        time.sleep(0.25)
    try:
        os.kill(pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass


def _purge_token_sidecars() -> int:
    """Delete any agent_g_ghidra_token_<port>.txt files left in TEMP.

    These are how the Java side communicates the bearer token back to
    Python. Stale sidecars from crashed prior runs cause 401s on the
    next provisioner if a port number is reused. Returns the number of
    files removed.
    """
    tmp = Path(tempfile.gettempdir())
    removed = 0
    for f in tmp.glob("agent_g_ghidra_token_*.txt"):
        try:
            f.unlink()
            removed += 1
        except OSError:
            pass
    return removed


# ── start ───────────────────────────────────────────────────────────


def start_drive(
    binary_path: str,
    *,
    port: Optional[int] = None,
    ready_timeout: Optional[float] = None,
    session_file: Optional[Path] = None,
) -> SessionInfo:
    """Provision a Ghidra HTTP server for ``binary_path``.

    Blocks until the JVM reports ready (Ghidra ingest can take 30 s for
    small binaries up to several minutes for large stripped daemons).
    Writes ``ghidra_session.json`` with the URL + bearer token, then
    returns. The JVM stays alive until ``stop_drive`` is called.

    Raises:
      FileNotFoundError: if ``binary_path`` doesn't exist.
      RuntimeError: if a session is already active (mutex guard).
                    The caller should run ``stop_drive`` first.
    """
    bp = Path(binary_path).resolve()
    if not bp.exists():
        raise FileNotFoundError(f"binary not found: {bp}")

    sess_file = _resolve_session_file(session_file)

    # Mutex: if a session file exists and the PID it names is alive,
    # refuse to start. This is the structural fix for the concurrent-
    # pool-spawn race that produced 401 storms when two parallel
    # provisioners both tried to claim port 19000.
    existing = _read_session(sess_file)
    if existing is not None and _is_alive(existing.pid):
        raise RuntimeError(
            f"another drive session is already active "
            f"(pid={existing.pid}, binary={existing.binary_name}, "
            f"url={existing.base_url}). Run 'agent-g drive stop' first, "
            f"or delete {sess_file} if you're certain it's stale."
        )

    # If we got here with a stale session file (pid dead, or unreadable),
    # nuke it and continue.
    if existing is not None:
        logger.info("removing stale session file (pid=%d not alive)", existing.pid)
        try:
            sess_file.unlink()
        except FileNotFoundError:
            pass

    # Also clear any stale token sidecars that might still be in TEMP
    purged = _purge_token_sidecars()
    if purged:
        logger.info("purged %d stale token sidecar(s) from TEMP", purged)

    # Honor caller-supplied or env-configured timeout
    if ready_timeout is not None:
        os.environ["AGENT_G_GHIDRA_READY_TIMEOUT_S"] = str(ready_timeout)

    # Import GhidraPool lazily so this module stays importable in tests
    # that don't have GHIDRA_INSTALL_DIR configured.
    from src.runtime.ghidra_pool import GhidraPool, PoolConfig  # noqa: PLC0415

    cfg = PoolConfig()
    if port is not None:
        cfg.port_start = port
        cfg.port_end = port  # restrict to the requested port
    if ready_timeout is not None:
        cfg.ready_timeout_s = ready_timeout

    pool = GhidraPool(config=cfg)
    handle = pool.acquire(str(bp))

    info = SessionInfo(
        binary_path=str(bp),
        binary_name=bp.name,
        base_url=handle.base_url,
        auth_token=handle.auth_token,
        port=handle.port,
        pid=os.getpid(),
        started_at=handle.started_at,
    )
    _write_session(sess_file, info)
    return info


# ── stop ────────────────────────────────────────────────────────────


def stop_drive(
    *,
    session_file: Optional[Path] = None,
    force: bool = False,
) -> bool:
    """Tear down the active drive session, if any.

    With ``force=True``, also scan for and kill any orphan Java processes
    that might be holding ports 19000-19999, and purge all stale token
    sidecars from TEMP. This is the recovery escape hatch when a previous
    provisioner crashed and left orphaned state.

    Returns True if anything was cleaned, False if nothing was running
    and there was nothing to clean.
    """
    sess_file = _resolve_session_file(session_file)
    cleaned = False

    info = _read_session(sess_file)
    if info is not None:
        if _is_alive(info.pid):
            logger.info("killing drive provisioner pid=%d", info.pid)
            _kill(info.pid)
            cleaned = True
        try:
            sess_file.unlink()
            cleaned = True
        except FileNotFoundError:
            pass

    purged = _purge_token_sidecars()
    if purged:
        cleaned = True
        logger.info("purged %d token sidecar(s)", purged)

    if force:
        # Hunt orphan Java processes listening on the Ghidra port range.
        # We don't try to be precise (no PID filtering by command line);
        # the user opted into this with --force.
        if sys.platform == "win32":
            # Find java.exe processes and kill them all. Risky if user has
            # other Java workloads — that's why this is opt-in.
            r = subprocess.run(
                ["taskkill", "/F", "/IM", "java.exe"],
                capture_output=True, text=True, check=False,
            )
            if r.returncode == 0:
                logger.info("killed orphan java.exe processes (force=True)")
                cleaned = True
        else:
            # On POSIX, look for "ghidra" in command line and kill those only.
            r = subprocess.run(
                ["pkill", "-f", "ghidra"],
                capture_output=True, text=True, check=False,
            )
            if r.returncode in (0, 1):  # 0 = killed, 1 = no match
                if r.returncode == 0:
                    logger.info("killed orphan ghidra-related processes (force=True)")
                    cleaned = True

    return cleaned


# ── status ──────────────────────────────────────────────────────────


def status_drive(
    *,
    session_file: Optional[Path] = None,
) -> Optional[SessionInfo]:
    """Return the active session info, or None if nothing is running.

    Verifies that the PID in the session file is still alive. A stale
    session file (PID not alive) returns None — the caller can detect
    "nothing running but file exists" by reading the file directly if
    they care about that distinction.
    """
    sess_file = _resolve_session_file(session_file)
    info = _read_session(sess_file)
    if info is None:
        return None
    if not _is_alive(info.pid):
        return None
    return info


# ── query ───────────────────────────────────────────────────────────


def query(
    endpoint: str,
    params: Optional[Dict[str, Any]] = None,
    *,
    session_file: Optional[Path] = None,
    timeout: float = 120.0,
) -> str:
    """Authenticated GET against the running Ghidra.

    ``params`` is a flat mapping of query-string keys to values. Values
    are coerced to strings; nothing is JSON-encoded. This matches the
    g.sh helper's contract.

    Raises:
      RuntimeError: if no drive session is active, or the JVM is dead.
      requests.HTTPError: on 4xx / 5xx responses.
    """
    import requests  # local import: drive module is otherwise stdlib-only

    info = status_drive(session_file=session_file)
    if info is None:
        sess_file = _resolve_session_file(session_file)
        if sess_file.exists():
            raise RuntimeError(
                f"drive session file exists at {sess_file} but the JVM is "
                f"not alive. Run 'agent-g drive stop' to clean up, then "
                f"'agent-g drive <binary>' to re-provision."
            )
        raise RuntimeError(
            "no drive session is active. Run 'agent-g drive <binary>' "
            "first (in another terminal, or with --detach)."
        )

    url = f"{info.base_url}/{endpoint.lstrip('/')}"
    headers = {"Authorization": f"Bearer {info.auth_token}"}
    r = requests.get(url, params=params or {}, headers=headers, timeout=timeout)
    r.raise_for_status()
    return r.text
