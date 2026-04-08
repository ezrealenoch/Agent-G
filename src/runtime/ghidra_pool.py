"""Stateless Ghidra instance pool.

Meta-agents asking Agent-G "give me 10 concurrent investigations on these
10 binaries" should not have to know about ports, temp directories, or
JVM lifecycles. This module wraps all of that behind a single API:

    with GhidraPool(size=10) as pool:
        handles = [pool.acquire(binary_path=p) for p in binaries]
        # ... do work against each handle.base_url ...
        for h in handles:
            pool.release(h)

Or as a context manager per handle::

    with GhidraPool() as pool:
        with pool.session(binary_path=p) as handle:
            bridge = BridgeLite(config=cfg.with_ghidra(handle.base_url))
            summary = bridge.runtime.run_turn(prompt)

Design
------
  - Ports are assigned from a configurable pool range (default 19000-19999)
  - Each acquire() spawns a fresh headless Ghidra with a unique project
    directory under a pool-owned temp root
  - The pool generates and injects a per-instance bearer token, fulfilling
    the auth contract in ``OGhidraHeadlessServer.java``
  - Handles are ref-counted: release() shuts down the JVM, cleans the temp
    dir, frees the port
  - The pool is thread-safe; concurrent acquire()s get distinct ports
  - On pool shutdown (close(), __exit__, or process exit via atexit), every
    outstanding instance is force-killed and its temp dir scrubbed

This is NOT a long-lived Ghidra cache. Each handle is scoped to one
investigation; Ghidra's own project store is ephemeral. If you want to
cache analyzed databases across runs, that's a separate concern (the
result store handles "cache of verdicts", not "cache of Ghidra state").
"""
from __future__ import annotations
import atexit
import logging
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set

logger = logging.getLogger("agent-g.ghidra_pool")


# ── Configuration defaults ───────────────────────────────────────────

DEFAULT_PORT_START = 19000
DEFAULT_PORT_END = 19999
DEFAULT_READY_TIMEOUT_S = 180.0
DEFAULT_SHUTDOWN_TIMEOUT_S = 15.0


@dataclass
class GhidraHandle:
    """A live Ghidra HTTP server owned by the pool.

    The only fields a caller needs are ``base_url`` and ``auth_token``.
    The rest are pool-internal bookkeeping.
    """
    port: int
    base_url: str
    auth_token: str
    project_dir: Path
    proc: subprocess.Popen
    binary_path: Path
    started_at: float
    _released: bool = False


@dataclass
class PoolConfig:
    """Pool-wide configuration. All fields optional with sane defaults."""
    # Honor $GHIDRA_INSTALL_DIR; if unset, leave as an empty Path and let
    # the preflight check surface a clear error rather than guessing a
    # platform-specific default path that would silently break elsewhere.
    ghidra_install: Path = field(default_factory=lambda: Path(
        os.environ.get("GHIDRA_INSTALL_DIR", "")))
    script_dir: Path = field(default_factory=lambda: Path(
        __file__).resolve().parent.parent.parent / "ghidra" / "scripts")
    port_start: int = DEFAULT_PORT_START
    port_end: int = DEFAULT_PORT_END
    max_concurrent: int = 16        # soft cap on simultaneous instances
    ready_timeout_s: float = DEFAULT_READY_TIMEOUT_S
    shutdown_timeout_s: float = DEFAULT_SHUTDOWN_TIMEOUT_S
    # Temp workspace root. Pool creates a per-run subdirectory under this.
    workspace_root: Path = field(default_factory=lambda: Path(tempfile.gettempdir()) / "agent_g_pool")


# ── Port allocation ─────────────────────────────────────────────────

def _port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", port))
            return True
        except OSError:
            return False


# ── Pool ────────────────────────────────────────────────────────────

class GhidraPool:
    """Thread-safe pool manager for stateless Ghidra instances.

    Usage::

        with GhidraPool() as pool:
            with pool.session("/path/to/binary") as handle:
                requests.get(f"{handle.base_url}/list_functions",
                             headers={"Authorization": f"Bearer {handle.auth_token}"})

    Concurrency::

        pool = GhidraPool(PoolConfig(max_concurrent=10))
        handles = [pool.acquire(p) for p in binaries]
        try:
            # ... parallel work ...
        finally:
            for h in handles:
                pool.release(h)
        pool.close()

    The pool pre-claims ports from its configured range using a mutex so
    two concurrent acquire() calls never collide. If a picked port turns
    out to be actually-used on the host, the pool falls through to the
    next free one.
    """

    def __init__(self, config: Optional[PoolConfig] = None):
        self.config = config or PoolConfig()
        self._lock = threading.RLock()
        self._allocated_ports: Set[int] = set()
        self._live_handles: Dict[int, GhidraHandle] = {}
        self._next_port_hint = self.config.port_start
        self._semaphore = threading.Semaphore(self.config.max_concurrent)
        self._closed = False
        self._workspace_root = self.config.workspace_root
        self._workspace_root.mkdir(parents=True, exist_ok=True)
        # Always clean up on exit so a CTRL-C doesn't leave orphan JVMs
        atexit.register(self._atexit_cleanup)
        logger.info(
            "GhidraPool ready: port_range=%d-%d max_concurrent=%d workspace=%s",
            self.config.port_start, self.config.port_end,
            self.config.max_concurrent, self._workspace_root,
        )

    # ── Public API ──

    def acquire(self, binary_path, *, project_name: str = "PoolProj") -> GhidraHandle:
        """Spin up a Ghidra instance for a binary and return a live handle.

        Blocks until the JVM's HTTP server reports ``ready``. Raises
        ``TimeoutError`` if the server never becomes ready, or
        ``RuntimeError`` if the subprocess dies during startup.
        """
        if self._closed:
            raise RuntimeError("GhidraPool is closed")

        binary_path = Path(binary_path)
        if not binary_path.exists():
            raise FileNotFoundError(f"binary not found: {binary_path}")

        # Block if we're at the concurrency cap; release decrements.
        self._semaphore.acquire()
        try:
            port = self._claim_port()
            token = secrets.token_urlsafe(32)
            proj_dir = Path(tempfile.mkdtemp(
                prefix=f"ghidra_pool_{port}_",
                dir=str(self._workspace_root),
            ))
            # Write the token sidecar so the GhidraMCPClient's default
            # resolver picks it up.
            self._write_sidecar(port, token)

            proc = self._launch_ghidra(
                port=port,
                binary_path=binary_path,
                project_dir=proj_dir,
                project_name=project_name,
                auth_token=token,
            )

            try:
                self._wait_ready(port, token, proc)
            except Exception:
                # Failed startup: kill the subprocess and clean up before
                # re-raising so the pool state stays consistent.
                self._terminate_proc(proc)
                self._cleanup_workspace(proj_dir)
                self._release_port(port)
                self._delete_sidecar(port)
                raise

            handle = GhidraHandle(
                port=port,
                base_url=f"http://localhost:{port}",
                auth_token=token,
                project_dir=proj_dir,
                proc=proc,
                binary_path=binary_path,
                started_at=time.time(),
            )
            with self._lock:
                self._live_handles[port] = handle
            logger.info(
                "acquired Ghidra instance: port=%d binary=%s",
                port, binary_path.name,
            )
            return handle
        except Exception:
            self._semaphore.release()
            raise

    def release(self, handle: GhidraHandle) -> None:
        """Tear down a previously-acquired instance. Idempotent."""
        if handle is None or handle._released:
            return
        try:
            logger.info(
                "releasing Ghidra instance: port=%d uptime=%.1fs",
                handle.port, time.time() - handle.started_at,
            )
            self._request_shutdown(handle)
            self._terminate_proc(handle.proc)
            self._cleanup_workspace(handle.project_dir)
            self._delete_sidecar(handle.port)
        finally:
            self._release_port(handle.port)
            with self._lock:
                self._live_handles.pop(handle.port, None)
            handle._released = True
            self._semaphore.release()

    @contextmanager
    def session(self, binary_path, *, project_name: str = "PoolProj") -> Iterator[GhidraHandle]:
        """Context-managed acquire/release for a single investigation."""
        h = self.acquire(binary_path, project_name=project_name)
        try:
            yield h
        finally:
            self.release(h)

    def close(self) -> None:
        """Release every outstanding instance and mark the pool closed."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            handles = list(self._live_handles.values())
        for h in handles:
            try:
                self.release(h)
            except Exception as e:
                logger.warning("release during close failed: %s", e)
        logger.info("GhidraPool closed")

    def __enter__(self) -> "GhidraPool":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self.close()

    def snapshot(self) -> dict:
        """Return pool state for observability endpoints / health checks."""
        with self._lock:
            return {
                "closed": self._closed,
                "live_instances": len(self._live_handles),
                "max_concurrent": self.config.max_concurrent,
                "allocated_ports": sorted(self._allocated_ports),
                "live_ports": sorted(self._live_handles.keys()),
            }

    # ── Internals ──

    def _claim_port(self) -> int:
        """Pick the next free port in the configured range."""
        with self._lock:
            start = self._next_port_hint
            span = self.config.port_end - self.config.port_start + 1
            for i in range(span):
                candidate = self.config.port_start + (
                    (start - self.config.port_start + i) % span)
                if candidate in self._allocated_ports:
                    continue
                if not _port_is_free(candidate):
                    continue
                self._allocated_ports.add(candidate)
                self._next_port_hint = candidate + 1
                return candidate
        raise RuntimeError(
            f"GhidraPool: no free port in range {self.config.port_start}-"
            f"{self.config.port_end} (allocated={len(self._allocated_ports)})"
        )

    def _release_port(self, port: int) -> None:
        with self._lock:
            self._allocated_ports.discard(port)

    def _launch_ghidra(
        self,
        *,
        port: int,
        binary_path: Path,
        project_dir: Path,
        project_name: str,
        auth_token: str,
    ) -> subprocess.Popen:
        headless = self.config.ghidra_install / "support" / "analyzeHeadless.bat"
        if not headless.exists():
            # Fallback for Unix install layouts
            alt = self.config.ghidra_install / "support" / "analyzeHeadless"
            if alt.exists():
                headless = alt
            else:
                raise FileNotFoundError(
                    f"analyzeHeadless not found at {headless} or {alt}"
                )

        script_path = str(self.config.script_dir)
        cmd = [
            str(headless),
            str(project_dir),
            project_name,
            "-import", str(binary_path),
            "-scriptPath", script_path,
            "-postScript", "OGhidraHeadlessServer.java", str(port), auth_token,
        ]
        logger.debug("launching: %s", " ".join(cmd))

        # Drain stdout in a background thread so the buffer never blocks
        env = os.environ.copy()
        env["AGENT_G_GHIDRA_AUTH_TOKEN"] = auth_token
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            env=env,
        )

        def _drain():
            try:
                for line in proc.stdout:  # type: ignore[union-attr]
                    logger.debug("[ghidra:%d] %s", port, line.rstrip())
            except Exception:
                pass

        threading.Thread(target=_drain, daemon=True).start()
        return proc

    def _wait_ready(self, port: int, token: str, proc: subprocess.Popen) -> None:
        """Poll /health until ``ready`` appears or timeout expires."""
        import requests  # local import so the pool module stays importable in tests
        headers = {"Authorization": f"Bearer {token}"}
        t0 = time.time()
        while time.time() - t0 < self.config.ready_timeout_s:
            if proc.poll() is not None:
                raise RuntimeError(
                    f"Ghidra subprocess on port {port} exited during startup "
                    f"(rc={proc.returncode})"
                )
            try:
                # /health is auth-exempt in the Java server so no header is
                # strictly required here, but we send it anyway to verify
                # the full auth path is healthy end-to-end.
                r = requests.get(
                    f"http://localhost:{port}/health",
                    headers=headers,
                    timeout=2,
                )
                if r.status_code == 200 and "ready" in r.text:
                    return
            except Exception:
                pass
            time.sleep(2)
        raise TimeoutError(
            f"Ghidra on port {port} did not become ready within "
            f"{self.config.ready_timeout_s:.0f}s"
        )

    def _request_shutdown(self, handle: GhidraHandle) -> None:
        """Politely ask the Ghidra HTTP server to stop."""
        import requests
        try:
            requests.post(
                f"{handle.base_url}/shutdown",
                headers={"Authorization": f"Bearer {handle.auth_token}"},
                timeout=5,
            )
        except Exception:
            # Server may already be gone; escalate to kill.
            pass

    def _terminate_proc(self, proc: subprocess.Popen) -> None:
        try:
            proc.wait(timeout=self.config.shutdown_timeout_s)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait(timeout=5)
            except Exception as e:
                logger.warning("hard kill failed: %s", e)
        except Exception as e:
            logger.debug("wait failed: %s", e)

    def _cleanup_workspace(self, project_dir: Path) -> None:
        try:
            shutil.rmtree(project_dir, ignore_errors=True)
        except Exception as e:
            logger.debug("workspace cleanup failed: %s", e)

    def _write_sidecar(self, port: int, token: str) -> None:
        try:
            sidecar = Path(tempfile.gettempdir()) / f"agent_g_ghidra_token_{port}.txt"
            sidecar.write_text(token, encoding="utf-8")
        except Exception as e:
            logger.debug("sidecar write failed: %s", e)

    def _delete_sidecar(self, port: int) -> None:
        try:
            sidecar = Path(tempfile.gettempdir()) / f"agent_g_ghidra_token_{port}.txt"
            if sidecar.exists():
                sidecar.unlink()
        except Exception:
            pass

    def _atexit_cleanup(self) -> None:
        if not self._closed:
            try:
                self.close()
            except Exception:
                pass


# ── Module-level default pool ─────────────────────────────────────

_default_pool: Optional[GhidraPool] = None
_default_pool_lock = threading.Lock()


def get_default_pool(config: Optional[PoolConfig] = None) -> GhidraPool:
    """Return a process-wide singleton pool. Useful for meta-agent shells
    that don't want to own pool lifetime explicitly."""
    global _default_pool
    with _default_pool_lock:
        if _default_pool is None or _default_pool._closed:
            _default_pool = GhidraPool(config)
        return _default_pool
