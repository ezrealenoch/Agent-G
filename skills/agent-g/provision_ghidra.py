"""Provision a Ghidra HTTP instance for one binary, then keep it alive.

Usage:
    python provision_ghidra.py <binary_path>

Writes connection info to ./ghidra_session.json with shape:
    {
        "binary_path": "...",
        "binary_name": "...",
        "base_url":   "http://localhost:<port>",
        "auth_token": "<bearer>",
        "port":       <int>,
        "pid":        <provisioner pid>,
        "started_at": <unix_ts>
    }

Blocks until killed. On exit (SIGTERM, Ctrl+C, or session end), Agent-G's
GhidraPool atexit handler tears down the Ghidra JVM and cleans up the temp
project dir.

The g.sh / g.ps1 helpers in this directory auto-discover the session file
and authenticate every curl request with the bearer token.

If `AGENT_G_HOME` is set in the environment, the provisioner uses that to
locate Agent-G's Python package; otherwise it walks up two directory levels
from this file (the standard layout when this script lives at
<agent-g>/skills/agent-g/provision_ghidra.py).
"""
from __future__ import annotations

import json
import logging
import os
import signal
import sys
import time
from pathlib import Path


def _resolve_agent_g_root() -> Path:
    """Find Agent-G's repo root so we can import src.runtime.ghidra_pool."""
    env = os.environ.get("AGENT_G_HOME")
    if env:
        return Path(env).resolve()
    # Walk up: <agent-g>/skills/agent-g/provision_ghidra.py -> <agent-g>
    return Path(__file__).resolve().parent.parent.parent


def _load_agent_g_env(agent_g_root: Path) -> None:
    """Load <agent-g>/.env so GHIDRA_INSTALL_DIR is set before pool import."""
    env_path = agent_g_root / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, _, v = line.partition("=")
        os.environ.setdefault(k.strip(), v.strip())


def main(binary_path: str) -> int:
    bp = Path(binary_path).resolve()
    if not bp.exists():
        print(json.dumps({"error": f"binary not found: {bp}"}))
        return 1

    agent_g_root = _resolve_agent_g_root()
    sys.path.insert(0, str(agent_g_root))
    _load_agent_g_env(agent_g_root)

    logging.basicConfig(
        level=logging.WARNING,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        from src.runtime.ghidra_pool import GhidraPool  # noqa: E402
    except ImportError as exc:
        print(json.dumps({
            "error": f"could not import GhidraPool: {exc}",
            "hint": (
                "Run `pip install -e .` from the Agent-G repo root, or set "
                "AGENT_G_HOME to the cloned repo path."
            ),
        }))
        return 2

    sess_file = Path.cwd() / "ghidra_session.json"
    pool = GhidraPool()

    try:
        handle = pool.acquire(str(bp))
    except Exception as exc:
        print(json.dumps({"error": f"pool.acquire failed: {exc}"}), flush=True)
        pool.close()
        return 3

    info = {
        "binary_path": str(bp),
        "binary_name": bp.name,
        "base_url":    handle.base_url,
        "auth_token":  handle.auth_token,
        "port":        handle.port,
        "pid":         os.getpid(),
        "started_at":  handle.started_at,
    }
    sess_file.write_text(json.dumps(info, indent=2), encoding="utf-8")
    print(json.dumps({"status": "ready", **info}), flush=True)

    def _shutdown(signum: int, _frame) -> None:  # noqa: ANN001
        print(json.dumps({"status": "shutting_down", "signal": signum}), flush=True)
        try:
            pool.release(handle)
        finally:
            pool.close()
            try:
                sess_file.unlink()
            except FileNotFoundError:
                pass
        sys.exit(0)

    signal.signal(signal.SIGTERM, _shutdown)
    try:
        signal.signal(signal.SIGINT, _shutdown)
    except (ValueError, AttributeError):
        pass

    while True:
        time.sleep(60)
        try:
            sess_file.touch()
        except FileNotFoundError:
            sess_file.write_text(json.dumps(info, indent=2), encoding="utf-8")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(json.dumps({
            "error": "usage: provision_ghidra.py <binary_path>",
        }))
        sys.exit(64)
    sys.exit(main(sys.argv[1]))
