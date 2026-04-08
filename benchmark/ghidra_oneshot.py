#!/usr/bin/env python3
"""Tiny CLI for sub-agents: start/stop one anonymized Ghidra HTTP server.

Subcommands:
  start --id <juliet_id> --port <P>
      Launches headless Ghidra with JulietAnonymizer + OGhidraHeadlessServer for
      the binary with that manifest id. Polls /health until ready, then prints
      a JSON line: {"port":P, "pid":<pid>, "tmp":<temp_dir>}. Stays running.
      Sub-agents should run this with run_in_background=true.

  stop --port <P>
      Sends POST /shutdown to gracefully stop the server, then kills any
      lingering analyzeHeadless process bound to it. Cleans up the temp dir.
"""
import argparse, json, os, signal, subprocess, sys, tempfile, threading, time
from pathlib import Path
import httpx, ijson

# Platform / install paths come from env vars with sensible fallbacks so
# this script runs on Windows, Linux, and macOS without edits.
GHIDRA = Path(os.environ.get("GHIDRA_INSTALL_DIR", ""))
# Pick the right analyzeHeadless binary for the current platform
_headless_candidates = [
    GHIDRA / "support" / "analyzeHeadless.bat",  # Windows
    GHIDRA / "support" / "analyzeHeadless",       # Linux/macOS
]
HEADLESS = next((c for c in _headless_candidates if c.exists()), _headless_candidates[0])
AGENT_G = Path(__file__).resolve().parent.parent
SCRIPT_DIR = AGENT_G / "ghidra" / "scripts"
BENCH_SCRIPT_DIR = AGENT_G / "benchmark" / "ghidra"
JULIET_ROOT = Path(os.environ.get(
    "JULIET_CORPUS_ROOT",
    str(Path.home() / "juliet-corpus"),
))
MANIFEST = JULIET_ROOT / "manifest_juliet_full.json"
STATE_DIR = AGENT_G / "logs" / "ghidra_oneshot_state"
STATE_DIR.mkdir(parents=True, exist_ok=True)

def resolve_id(jid):
    with open(MANIFEST, "rb") as f:
        for e in ijson.items(f, "samples.item"):
            if e["id"] == jid:
                return JULIET_ROOT / e["path"]
    return None

def cmd_start(args):
    bin_path = resolve_id(args.id)
    if not bin_path or not bin_path.exists():
        print(json.dumps({"error": f"binary not found for id {args.id}"}))
        sys.exit(2)
    tmp = tempfile.mkdtemp(prefix=f"oneshot_{args.port}_")
    script_path_arg = f"{SCRIPT_DIR}{os.pathsep}{BENCH_SCRIPT_DIR}"
    cmd = [str(HEADLESS), tmp, "OneShot",
           "-import", str(bin_path),
           "-scriptPath", script_path_arg,
           "-postScript", "JulietAnonymizer.java",
           "-postScript", "OGhidraHeadlessServer.java", str(args.port)]
    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    state_path = STATE_DIR / f"port_{args.port}.json"
    state_path.write_text(json.dumps({"pid": proc.pid, "tmp": tmp, "id": args.id}))

    # Wait for /health to return ready
    t0 = time.time()
    ready = False
    while time.time() - t0 < 180:
        try:
            r = httpx.get(f"http://localhost:{args.port}/health", timeout=2)
            if r.status_code == 200 and "ready" in r.text:
                ready = True
                break
        except Exception:
            pass
        if proc.poll() is not None:
            print(json.dumps({"error": "ghidra exited", "port": args.port}))
            sys.exit(3)
        time.sleep(2)
    if not ready:
        print(json.dumps({"error": "timeout waiting for ready", "port": args.port}))
        sys.exit(4)
    print(json.dumps({"port": args.port, "pid": proc.pid, "tmp": tmp, "ready": True}), flush=True)
    # Stay alive so the caller can use the server. Block until killed.
    try:
        proc.wait()
    except KeyboardInterrupt:
        pass

def cmd_stop(args):
    state_path = STATE_DIR / f"port_{args.port}.json"
    state = {}
    if state_path.exists():
        try: state = json.loads(state_path.read_text())
        except: pass
    try:
        httpx.post(f"http://localhost:{args.port}/shutdown", timeout=5)
    except Exception:
        pass
    time.sleep(2)
    pid = state.get("pid")
    if pid:
        try: os.kill(pid, signal.SIGTERM)
        except Exception: pass
    tmp = state.get("tmp")
    if tmp and Path(tmp).exists():
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)
    if state_path.exists():
        state_path.unlink()
    print(json.dumps({"stopped": True, "port": args.port}))

def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    s1 = sub.add_parser("start"); s1.add_argument("--id", required=True); s1.add_argument("--port", type=int, required=True)
    s2 = sub.add_parser("stop"); s2.add_argument("--port", type=int, required=True)
    args = ap.parse_args()
    if args.cmd == "start": cmd_start(args)
    elif args.cmd == "stop": cmd_stop(args)

if __name__ == "__main__":
    main()
