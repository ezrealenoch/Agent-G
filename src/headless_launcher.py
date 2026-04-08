"""Headless Ghidra process launcher and lifecycle manager.

Launches Ghidra's ``analyzeHeadless`` CLI with the OGhidraHeadlessServer
script, waits for the HTTP server to become ready, and provides clean
shutdown and temp-project cleanup.
"""

import atexit
import glob
import logging
import os
import re
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Optional

import httpx

logger = logging.getLogger("agent-g.launcher")


class HeadlessGhidraLauncher:
    """Manage a headless Ghidra instance with an embedded HTTP server.

    Usage::

        with HeadlessGhidraLauncher("path/to/binary.exe") as launcher:
            # Ghidra HTTP server is ready at localhost:launcher.port
            ...
        # Ghidra process killed, temp project cleaned up
    """

    def __init__(
        self,
        binary_path: str,
        ghidra_install: Optional[str] = None,
        port: int = 8080,
        max_wait: int = 300,
    ):
        self.binary_path = Path(binary_path).resolve()
        if not self.binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {self.binary_path}")

        self._ghidra_install = self._find_ghidra(ghidra_install)
        self._requested_port = port
        self._max_wait = max_wait

        self.port: int = port  # actual port (may differ after auto-select)
        self._process: Optional[subprocess.Popen] = None
        self._temp_dir: Optional[tempfile.TemporaryDirectory] = None
        self._stdout_thread: Optional[threading.Thread] = None
        self._ready_event = threading.Event()
        self._output_lines: list = []
        self._shutdown_called = False

    # ── Ghidra discovery ────────────────────────────────────────────

    @staticmethod
    def _find_ghidra(explicit_path: Optional[str] = None) -> Path:
        """Locate the Ghidra installation directory."""
        # 1. Explicit parameter
        if explicit_path:
            p = Path(explicit_path)
            if (p / "support" / "analyzeHeadless.bat").exists() or \
               (p / "support" / "analyzeHeadless").exists():
                return p
            raise RuntimeError(
                f"Ghidra installation not found at {explicit_path} "
                f"(missing support/analyzeHeadless)"
            )

        # 2. Environment variable
        env_dir = os.environ.get("GHIDRA_INSTALL_DIR")
        if env_dir:
            p = Path(env_dir)
            if (p / "support").exists():
                return p

        # 3. Auto-detect: scan sibling directories of the OGhidra project
        oghidra_root = Path(__file__).resolve().parent.parent.parent  # Agent-G/../
        candidates = sorted(
            glob.glob(str(oghidra_root / "ghidra_*_PUBLIC")),
            reverse=True,  # prefer newest version
        )
        for c in candidates:
            p = Path(c)
            if (p / "support").exists():
                logger.info("Auto-detected Ghidra at %s", p)
                return p

        raise RuntimeError(
            "Ghidra installation not found. Set GHIDRA_INSTALL_DIR or "
            "pass --ghidra-install. Checked:\n"
            f"  - GHIDRA_INSTALL_DIR env var\n"
            f"  - {oghidra_root / 'ghidra_*_PUBLIC'}"
        )

    # ── Script path ─────────────────────────────────────────────────

    @staticmethod
    def _script_dir() -> Path:
        """Return the directory containing OGhidraHeadlessServer.java."""
        return Path(__file__).resolve().parent.parent / "ghidra" / "scripts"

    # ── Lifecycle ───────────────────────────────────────────────────

    def start(self):
        """Launch the headless Ghidra process and wait for HTTP readiness."""
        self._temp_dir = tempfile.TemporaryDirectory(prefix="agent_g_")
        project_dir = self._temp_dir.name

        # Build analyzeHeadless command
        if os.name == "nt":
            headless_bin = self._ghidra_install / "support" / "analyzeHeadless.bat"
        else:
            headless_bin = self._ghidra_install / "support" / "analyzeHeadless"

        script_dir = self._script_dir()
        if not (script_dir / "OGhidraHeadlessServer.java").exists():
            raise FileNotFoundError(
                f"OGhidraHeadlessServer.java not found in {script_dir}"
            )

        cmd = [
            str(headless_bin),
            project_dir,
            "HeadlessProject",
            "-import", str(self.binary_path),
            "-scriptPath", str(script_dir),
            "-postScript", "OGhidraHeadlessServer.java", str(self._requested_port),
        ]

        logger.info("Starting headless Ghidra: %s", " ".join(cmd))
        print(f"[Launcher] Starting Ghidra headless analysis of {self.binary_path.name}...")
        print(f"[Launcher] This may take a moment while Ghidra auto-analyzes the binary...")

        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )

        # Register cleanup
        atexit.register(self.shutdown)

        # Start stdout reader thread
        self._stdout_thread = threading.Thread(
            target=self._read_stdout, daemon=True, name="ghidra-stdout"
        )
        self._stdout_thread.start()

        # Wait for server readiness
        self._wait_for_ready()

    def _read_stdout(self):
        """Background thread: read Ghidra stdout and watch for ready signal."""
        ready_pattern = re.compile(r"OGhidra HTTP server ready on port (\d+)")
        for line in self._process.stdout:
            line = line.rstrip()
            self._output_lines.append(line)
            logger.debug("[Ghidra] %s", line)

            match = ready_pattern.search(line)
            if match:
                self.port = int(match.group(1))
                self._ready_event.set()

        # Process exited without ready signal
        if not self._ready_event.is_set():
            self._ready_event.set()  # unblock waiter so it can check process state

    def _wait_for_ready(self):
        """Block until the HTTP server is ready or timeout."""
        start = time.time()

        # Wait for the ready message in stdout
        while time.time() - start < self._max_wait:
            if self._ready_event.wait(timeout=2.0):
                break

            # Check if process died
            if self._process.poll() is not None:
                tail = "\n".join(self._output_lines[-20:])
                raise RuntimeError(
                    f"Ghidra process exited with code {self._process.returncode} "
                    f"before server was ready.\nLast output:\n{tail}"
                )
        else:
            self.shutdown()
            raise TimeoutError(
                f"Ghidra HTTP server did not become ready within {self._max_wait}s"
            )

        # Verify with HTTP health check
        try:
            resp = httpx.get(f"http://localhost:{self.port}/health", timeout=10)
            if resp.status_code == 200:
                print(f"[Launcher] Ghidra HTTP server ready on port {self.port}")
                return
        except Exception:
            pass

        # Fallback: server printed ready but health check failed
        logger.warning("Server printed ready but /health check failed; proceeding anyway")

    def shutdown(self):
        """Stop the headless Ghidra process and clean up."""
        if self._shutdown_called:
            return
        self._shutdown_called = True

        if self._process and self._process.poll() is None:
            # Try graceful shutdown via HTTP
            try:
                httpx.post(
                    f"http://localhost:{self.port}/shutdown",
                    timeout=5,
                )
            except Exception:
                pass

            # Wait for process to exit
            try:
                self._process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                logger.warning("Ghidra process did not exit; killing")
                self._process.kill()
                self._process.wait(timeout=5)

            print("[Launcher] Ghidra process stopped")

        # Clean up temp project
        if self._temp_dir:
            try:
                self._temp_dir.cleanup()
            except Exception as e:
                logger.warning("Temp dir cleanup failed: %s", e)

    # ── Context manager ─────────────────────────────────────────────

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc):
        self.shutdown()
