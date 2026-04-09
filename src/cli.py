"""Agent-G top-level CLI.

After ``pip install -e .`` this is invoked as the ``agent-g`` command via
the ``[project.scripts]`` entry point in ``pyproject.toml``.

Subcommands
-----------
  agent-g version     — print the installed version
  agent-g doctor      — run preflight checks, print red/green report
  agent-g analyze     — run an investigation on a single binary
  agent-g replay      — replay a captured trace against a stub LLM
  agent-g pool        — manage the Ghidra pool (status, stop-all)
  agent-g store       — query the SQLite result store

Each subcommand is a thin wrapper that delegates to its module so the
CLI surface stays shallow. See ``agent-g <command> --help`` for details.
"""
from __future__ import annotations
import argparse
import json
import os
import sys
from pathlib import Path
from typing import List, Optional

# Allow ``python src/cli.py`` as well as ``agent-g`` (installed script).
# When run directly the repo root isn't on sys.path, so we add it here.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def _load_env_file() -> None:
    """Best-effort .env loader shared by every subcommand."""
    env_path = _repo_root() / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


# ── version ──────────────────────────────────────────────────────

def cmd_version(args: argparse.Namespace) -> int:
    from src import __version__
    print(f"agent-g {__version__}")
    print(f"python {sys.version.split()[0]} on {sys.platform}")
    return 0


# ── doctor ──────────────────────────────────────────────────────

def cmd_doctor(args: argparse.Namespace) -> int:
    """Delegate to scripts/preflight.py."""
    sys.path.insert(0, str(_repo_root() / "scripts"))
    try:
        import preflight  # type: ignore
    except ImportError as e:
        print(f"error: could not import preflight: {e}", file=sys.stderr)
        return 1
    report = preflight.run_all_checks()
    print(report.render())
    if not report.required_pass:
        return 1
    if any(r.status == "warn" for r in report.results):
        return 2
    return 0


# ── analyze ─────────────────────────────────────────────────────

def cmd_analyze(args: argparse.Namespace) -> int:
    """Run a single investigation on a binary and print the verdict.

    This is the happy-path entry point a first-time user runs after
    ``agent-g doctor`` passes. It wires up the full production stack
    (pool + budget + checkpoint + trace + provenance + store) with
    sensible defaults and streams progress events to stderr.
    """
    from src import __version__
    from src.runtime.observability import (
        configure_structured_logging, new_trace_id, set_trace_id, EventJsonlSink,
    )
    from src.runtime.budget import Budget
    from src.runtime.checkpoint import CheckpointWriter
    from src.runtime.trace import TraceWriter, build_provenance_from_run
    from src.runtime.ghidra_pool import GhidraPool, PoolConfig
    from src.runtime.result_store import ResultStore, record_from_provenance
    from src.runtime.prompt_library import render_prompt

    binary_path = Path(args.binary).expanduser().resolve()
    if not binary_path.exists():
        print(f"error: binary not found: {binary_path}", file=sys.stderr)
        return 1

    configure_structured_logging(
        level=args.log_level,
        json_output=args.json_logs,
        logfile=args.log_file,
    )
    trace_id = new_trace_id()
    set_trace_id(trace_id)

    runs_dir = Path(args.runs_dir).expanduser() / trace_id
    runs_dir.mkdir(parents=True, exist_ok=True)

    # Try to find the binary hash early so we can consult the store
    import hashlib
    h = hashlib.sha256()
    with open(binary_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    sha = h.hexdigest()

    # Store cache hit?
    store = ResultStore(Path(args.store).expanduser())
    if not args.no_cache:
        hit = store.find_latest(
            sha,
            task_kind=args.task,
            model_id=args.model or None,
            prompt_version=args.prompt_version,
        )
        if hit is not None:
            print(f"[cache] prior run {hit.trace_id} found — "
                  f"verdict={hit.verdict} model={hit.model_id}", file=sys.stderr)
            if args.format == "json":
                print(json.dumps({
                    "cached": True,
                    "trace_id": hit.trace_id,
                    "verdict": hit.verdict,
                    "model_id": hit.model_id,
                    "finished_at": hit.finished_at,
                    "final_text": hit.final_text,
                }, indent=2))
            else:
                print(f"verdict: {hit.verdict}")
                print(f"cached from run: {hit.trace_id}")
            return 0

    # Build budget from CLI overrides or default-production
    budget = Budget(
        wall_time_s=args.max_wall_time_s,
        max_total_tokens=args.max_tokens,
        max_tool_calls=args.max_tool_calls,
        max_iterations=args.max_iterations,
        max_cost_usd=args.max_cost_usd,
    )

    # Build prompt
    try:
        prompt_text, prompt_ver, prompt_hash = render_prompt(
            args.prompt_name,
            version=args.prompt_version,
            binary_name=binary_path.name,
            task_kind=args.task,
        )
    except KeyError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1

    print(f"[agent-g v{__version__}] trace_id={trace_id}", file=sys.stderr)
    print(f"  binary: {binary_path}", file=sys.stderr)
    print(f"  sha256: {sha[:16]}...", file=sys.stderr)
    print(f"  model : {args.model or '(from .env)'}", file=sys.stderr)
    print(f"  prompt: {args.prompt_name} {prompt_ver}", file=sys.stderr)
    print(f"  runs  : {runs_dir}", file=sys.stderr)

    # Build runtime. We use BridgeLite's existing construction path so we
    # don't re-derive all the config plumbing here; analyze() is a façade.
    try:
        from src.config import get_config
        from src.bridge_lite import BridgeLite
    except Exception as e:
        print(f"error: BridgeLite not importable ({e}). "
              f"Run 'agent-g doctor' to diagnose.", file=sys.stderr)
        return 1

    cfg = get_config()
    pool = GhidraPool()
    try:
        with pool.session(str(binary_path)) as handle:
            cfg.ghidra.base_url = handle.base_url
            os.environ["AGENT_G_GHIDRA_AUTH_TOKEN"] = handle.auth_token

            bridge = BridgeLite(config=cfg, binary_name=binary_path.name)

            # start_task() constructs the ConversationRuntime — must be
            # called before we can attach writers to it.
            bridge.start_task(args.task)
            runtime = bridge.runtime
            runtime.budget_tracker = budget.new_tracker(
                model_name=args.model or getattr(runtime.api, "model_name", "") or ""
            )
            runtime.checkpoint_writer = CheckpointWriter(runs_dir / "checkpoint.json")
            runtime.trace_writer = TraceWriter(runs_dir / "trace.jsonl")
            runtime.trace_id = trace_id
            runtime.binary_name = binary_path.name
            event_sink = EventJsonlSink(runs_dir / "events.jsonl")
            runtime.on_event = event_sink.emit

            # Wrap tool runner with logging
            from src.runtime.tool_logger import ToolCallLogger, LoggingToolRunner
            tool_log = ToolCallLogger(Path("logs/tool_calls.jsonl"), trace_id=trace_id)
            runtime.tools = LoggingToolRunner(
                runtime.tools, tool_log,
                binary_name_fn=lambda: binary_path.name,
            )

            summary = runtime.run_turn(prompt_text)
    finally:
        pool.close()

    verdict = _parse_verdict(summary.final_text or "")

    # Persist
    bundle = build_provenance_from_run(
        trace_id=trace_id,
        runs_dir=runs_dir,
        binary_path=str(binary_path),
        model_id=args.model or getattr(runtime.api, "model_name", "") or "",
        provider=getattr(cfg, "llm_provider", "unknown"),
        system_prompt=prompt_text,
        summary=summary,
        budget_tracker=runtime.budget_tracker,
        verdict=verdict,
    )
    bundle.prompt_version = prompt_ver
    bundle.system_prompt_hash = prompt_hash
    bundle.agent_g_version = __version__
    bundle.write(runs_dir / "provenance.json")
    record_from_provenance(store, bundle, task_kind=args.task)

    if args.format == "json":
        print(json.dumps({
            "trace_id": trace_id,
            "verdict": verdict,
            "exit_reason": summary.exit_reason,
            "iterations": summary.iterations,
            "tool_calls": summary.tool_calls,
            "runs_dir": str(runs_dir),
        }, indent=2))
    else:
        print()
        print(f"verdict : {verdict}")
        print(f"exit    : {summary.exit_reason}")
        print(f"iters   : {summary.iterations}")
        print(f"tools   : {summary.tool_calls}")
        print(f"runs    : {runs_dir}")

    return 0 if summary.exit_reason == "complete" else 3


def _parse_verdict(text: str) -> str:
    """Minimal verdict parser — mirrors benchmark/test_juliet.classify_verdict."""
    import re
    if not text or not text.strip():
        return "UNKNOWN"
    if "Model returned a blank response" in text:
        return "BLANK_RESPONSE"
    m = re.search(
        r"(?im)^[#*\s]*verdict[:\s]*\n+\s*\**\s*([A-Z][A-Z _-]+?)(?:\s*\(|\s*\**\s*$)",
        text,
    )
    if not m:
        m = re.search(
            r"(?i)\*?\*?verdict\*?\*?\s*[:\-]+\s*\**\s*([a-zA-Z _-]+?)\s*(?:\(|\**(?:\s|$|\.))",
            text,
        )
    if m:
        v = m.group(1).strip().upper()
        if any(k in v for k in ("NOT VULN", "BENIGN", "SAFE")):
            return "NOT_VULNERABLE"
        if any(k in v for k in ("VULNERABLE", "EXPLOIT", "MALICIOUS")):
            return "VULNERABLE"
    return "UNKNOWN"


# ── chat ────────────────────────────────────────────────────────

def cmd_chat(args: argparse.Namespace) -> int:
    """Interactive multi-session REPL for long-form investigations.

    Optionally takes a binary path as argument (auto-loads it). If no
    binary is given, drops into the REPL immediately — the user can
    load binaries via ``/load <path>`` or the LLM can call
    ``EXECUTE: load_binary(path="...")``.

    Multiple binaries can be loaded simultaneously. Each gets its own
    Ghidra instance from the pool. Switch with ``/switch <name>``.

    Commands inside the REPL:
      /help              — list commands
      /load <path> [name] — load a binary
      /switch <name>     — switch active binary
      /sessions          — list loaded binaries
      /close <name>      — close a binary session
      /reset             — clear conversation history (keep system prompt)
      /budget            — show current spend
      /exit, /quit       — leave the session
    """
    from src import __version__
    from src.runtime.observability import (
        configure_structured_logging, new_trace_id, set_trace_id, EventJsonlSink,
    )
    from src.runtime.budget import Budget
    from src.runtime.checkpoint import CheckpointWriter
    from src.runtime.trace import TraceWriter
    from src.runtime.ghidra_pool import GhidraPool
    from src.runtime.prompts import build_freeform_prompt
    from src.runtime.conversation import ConversationRuntime
    from src.command_parser import CommandParser
    from src.session_manager import SessionManager
    from src.meta_tools import build_composite_runner

    configure_structured_logging(level=args.log_level, json_output=False)
    trace_id = new_trace_id()
    set_trace_id(trace_id)
    runs_dir = Path(args.runs_dir).expanduser() / trace_id
    runs_dir.mkdir(parents=True, exist_ok=True)

    budget = Budget(
        wall_time_s=args.max_wall_time_s,
        max_total_tokens=args.max_tokens,
        max_tool_calls=args.max_tool_calls,
        max_iterations=args.max_iterations,
        max_cost_usd=args.max_cost_usd,
    )

    try:
        from src.config import get_config
        from src.runtime.api_client import ApiClient
    except Exception as e:
        print(f"error: imports failed ({e}). "
              f"Run 'agent-g doctor' to diagnose.", file=sys.stderr)
        return 1

    cfg = get_config()
    pool = GhidraPool()
    parser = CommandParser()

    # SessionManager tracks loaded binaries; CompositeToolRunner
    # dispatches meta-tools locally, delegates Ghidra tools to active binary.
    session_mgr = SessionManager(pool, cfg.ghidra, parser)
    composite = build_composite_runner(session_mgr)

    # Build the LLM client directly — do NOT use BridgeLite here because
    # BridgeLite.start_task() runs a bootstrap that connects to Ghidra,
    # which doesn't exist yet when no binary is loaded.
    provider = getattr(cfg, "llm_provider", "ollama")
    if provider in ("google", "external"):
        from src.external_client import ExternalClient
        llm_client = ExternalClient(config=cfg.external)
    elif provider == "custom_api":
        from src.custom_api_client import CustomAPIClient
        llm_client = CustomAPIClient(config=cfg.custom_api)
    else:
        from src.ollama_client import OllamaClient
        llm_client = OllamaClient(config=cfg.ollama)
    api_client = ApiClient(llm_client, phase="investigation")

    # Wrap the composite tool runner with logging.
    from src.runtime.tool_logger import ToolCallLogger, LoggingToolRunner
    tool_log = ToolCallLogger(Path("logs/tool_calls.jsonl"), trace_id=trace_id)
    logged_runner = LoggingToolRunner(
        composite, tool_log,
        binary_name_fn=lambda: session_mgr.active_name or "(none)",
    )

    # Create the single shared ConversationRuntime.
    system_prompt = build_freeform_prompt()
    runtime = ConversationRuntime(
        api_client=api_client,
        tool_runner=logged_runner,
        command_parser=parser,
        system_prompt=system_prompt,
    )
    runtime.budget_tracker = budget.new_tracker(
        model_name=args.model or getattr(api_client, "model_name", "") or ""
    )
    runtime.checkpoint_writer = CheckpointWriter(runs_dir / "checkpoint.json")
    runtime.trace_writer = TraceWriter(runs_dir / "trace.jsonl")
    runtime.trace_id = trace_id
    runtime.binary_name = "(chat)"
    event_sink = EventJsonlSink(runs_dir / "events.jsonl")
    runtime.on_event = event_sink.emit

    print(f"Agent-G v{__version__} | Interactive Binary Analysis")
    print(f"trace: {trace_id}")
    print("Type /help for commands, /exit to quit.")
    print("Load a binary with /load <path> or just tell me what to analyze.")

    # If binary was passed on the command line, auto-load it.
    if args.binary:
        binary_path = Path(args.binary).expanduser().resolve()
        if not binary_path.exists():
            print(f"error: binary not found: {binary_path}", file=sys.stderr)
            session_mgr.close_all()
            pool.close()
            return 1
        try:
            bs = session_mgr.load_binary(str(binary_path))
            composite.delegate = bs.tool_runner
            runtime.binary_name = bs.name
            # Inject bootstrap as a user message so the LLM sees it
            from src.runtime.session import Message
            runtime.session.append(Message.user(
                f"[Binary loaded: {bs.name}]\n{bs.bootstrap_text}"
            ))
            print(f"  binary: {bs.name} ({binary_path})")
        except Exception as e:
            print(f"error loading binary: {e}", file=sys.stderr)
            session_mgr.close_all()
            pool.close()
            return 1
    else:
        print("  no binary loaded — use /load <path> or ask the agent to load one")

    print()

    try:
        turn_no = 0
        while True:
            try:
                line = input(">>> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[session ended]")
                break
            if not line:
                continue

            # ── Exit ──
            if line.lower() in ("/exit", "/quit", "exit", "quit"):
                break

            if line == "/help":
                print("  /help              show this help")
                print("  /load <path> [name] load a binary for analysis")
                print("  /switch <name>     switch active binary")
                print("  /sessions          list loaded binaries")
                print("  /close <name>      close a binary session")
                print("  /reset             clear history, keep system prompt")
                print("  /budget            show current spend")
                print("  /exit              leave the session")
                continue

            if line.startswith("/load "):
                parts = line[6:].strip().split(None, 1)
                load_path = parts[0] if parts else ""
                load_name = parts[1] if len(parts) > 1 else None
                if not load_path:
                    print("usage: /load <path> [name]")
                    continue
                try:
                    bs = session_mgr.load_binary(load_path, name=load_name)
                    composite.delegate = bs.tool_runner
                    runtime.binary_name = bs.name
                    from src.runtime.session import Message
                    runtime.session.append(Message.user(
                        f"[Binary loaded: {bs.name}]\n{bs.bootstrap_text}"
                    ))
                    print(f"[loaded '{bs.name}' from {bs.binary_path}]")
                except Exception as e:
                    print(f"[error: {e}]")
                continue

            if line.startswith("/switch "):
                name = line[8:].strip()
                try:
                    bs = session_mgr.switch(name)
                    composite.delegate = bs.tool_runner
                    runtime.binary_name = bs.name
                    from src.runtime.session import Message
                    runtime.session.append(Message.user(
                        f"[Switched active binary to '{name}']"
                    ))
                    print(f"[switched to '{name}']")
                except KeyError as e:
                    print(f"[error: {e}]")
                continue

            if line == "/sessions":
                sessions = session_mgr.list_sessions()
                if not sessions:
                    print("  no binaries loaded")
                else:
                    for name, path, is_active in sessions:
                        marker = " << active" if is_active else ""
                        print(f"  {name}: {path}{marker}")
                continue

            if line.startswith("/close "):
                name = line[7:].strip()
                session_mgr.close_session(name)
                active = session_mgr.active
                if active:
                    composite.delegate = active.tool_runner
                    runtime.binary_name = active.name
                else:
                    composite.delegate = None
                    runtime.binary_name = "(chat)"
                print(f"[closed '{name}']")
                continue

            if line == "/reset":
                runtime.reset_session()
                print("[history cleared]")
                continue

            if line == "/budget":
                t = runtime.budget_tracker
                print(f"  iterations : {t.iterations}")
                print(f"  tool_calls : {t.tool_calls}")
                print(f"  tokens_in  : {t.input_tokens}")
                print(f"  tokens_out : {t.output_tokens}")
                print(f"  cost_usd   : {t.cost_usd:.4f}")
                continue

            # ── Normal turn ──
            turn_no += 1
            try:
                summary = runtime.run_turn(line)
            except Exception as e:
                print(f"[error during turn: {e}]", file=sys.stderr)
                continue

            print()
            print("Agent-G:", summary.final_text or "(no reply)")
            print(f"  [{summary.iterations} iters, "
                  f"{summary.tool_calls} tools]")
            print()
    finally:
        session_mgr.close_all()
        pool.close()

    t = runtime.budget_tracker
    print(f"Session ended. {t.tool_calls} tool calls, "
          f"{t.input_tokens + t.output_tokens} tokens.")
    print(f"Trace: {runs_dir}")
    return 0


# ── replay ──────────────────────────────────────────────────────

def cmd_replay(args: argparse.Namespace) -> int:
    """Replay a captured trace against a stub LLM."""
    from src.runtime.trace import load_trace, StubLlmFromTrace

    path = Path(args.trace).expanduser()
    if not path.exists():
        print(f"error: trace not found: {path}", file=sys.stderr)
        return 1

    records = load_trace(path)
    llm_calls = [r for r in records if r.get("kind") == "llm_call"]
    tool_calls = [r for r in records if r.get("kind") == "tool_call"]
    end_record = next((r for r in records if r.get("kind") == "end"), {})

    print(f"trace      : {path}")
    print(f"records    : {len(records)}")
    print(f"llm_calls  : {len(llm_calls)}")
    print(f"tool_calls : {len(tool_calls)}")
    print(f"exit_reason: {end_record.get('exit_reason', '?')}")
    print(f"iterations : {end_record.get('iterations', '?')}")
    if args.verbose:
        for i, tc in enumerate(tool_calls, 1):
            print(f"  {i:3d}. {tc.get('name')}({tc.get('params', {})})")
    return 0


# ── pool ────────────────────────────────────────────────────────

def cmd_pool(args: argparse.Namespace) -> int:
    """Inspect / manage the Ghidra pool. Currently reports the snapshot
    of the in-process default pool, which is only meaningful if Agent-G
    is running as a long-lived service (future: attach to a daemon)."""
    from src.runtime.ghidra_pool import get_default_pool
    if args.pool_action == "status":
        pool = get_default_pool()
        print(json.dumps(pool.snapshot(), indent=2))
        return 0
    if args.pool_action == "stop-all":
        pool = get_default_pool()
        pool.close()
        print("pool closed")
        return 0
    return 1


# ── store ───────────────────────────────────────────────────────

def cmd_store(args: argparse.Namespace) -> int:
    """Query the result store."""
    from src.runtime.result_store import ResultStore
    store = ResultStore(Path(args.store).expanduser())

    if args.store_action == "recent":
        rows = store.list_recent(limit=args.limit)
        if args.format == "json":
            print(json.dumps(
                [{
                    "trace_id": r.trace_id,
                    "binary_name": r.binary_name,
                    "model_id": r.model_id,
                    "verdict": r.verdict,
                    "finished_at": r.finished_at,
                } for r in rows], indent=2))
        else:
            for r in rows:
                print(f"  {r.finished_at}  {r.trace_id}  "
                      f"{r.model_id:30}  {r.verdict:14}  {r.binary_name}")
        return 0
    if args.store_action == "get":
        row = store.get(args.trace_id)
        if row is None:
            print(f"no investigation with trace_id={args.trace_id}", file=sys.stderr)
            return 1
        if args.format == "json":
            print(json.dumps(row.__dict__, indent=2, default=str))
        else:
            for k, v in row.__dict__.items():
                print(f"  {k}: {v}")
        return 0
    if args.store_action == "count":
        print(store.count())
        return 0
    return 1


# ── argparse plumbing ───────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="agent-g",
        description="Standalone headless binary-analysis agent powered by Ghidra + LLMs.",
    )
    p.add_argument("--version", action="store_true",
                   help="print version and exit")

    sub = p.add_subparsers(dest="command")

    # version
    sub.add_parser("version", help="print the installed agent-g version")

    # doctor
    sub.add_parser("doctor", help="run preflight self-check")

    # analyze
    ana = sub.add_parser("analyze", help="analyze a single binary")
    ana.add_argument("binary", help="path to the binary to analyze")
    ana.add_argument("--task", default="vuln",
                     help="task kind (default: vuln)")
    ana.add_argument("--model", default=None,
                     help="override the model name (else uses .env)")
    ana.add_argument("--prompt-name", default="vuln_hunt",
                     help="registered prompt name (default: vuln_hunt)")
    ana.add_argument("--prompt-version", default="latest",
                     help="prompt version (default: latest)")
    ana.add_argument("--runs-dir", default="runs",
                     help="root directory for per-run artifacts")
    ana.add_argument("--store", default="runs/results.sqlite",
                     help="SQLite result store path")
    ana.add_argument("--no-cache", action="store_true",
                     help="skip result-store cache lookup")
    ana.add_argument("--format", choices=("text", "json"), default="text",
                     help="output format")
    ana.add_argument("--log-level", default="INFO",
                     help="log level (DEBUG/INFO/WARNING/ERROR)")
    ana.add_argument("--log-file", default=None,
                     help="also log to this file (JSON lines)")
    ana.add_argument("--json-logs", action="store_true",
                     help="emit structured JSON logs to stderr")
    # Budget overrides
    ana.add_argument("--max-wall-time-s", type=float, default=600.0)
    ana.add_argument("--max-tokens", type=int, default=200_000)
    ana.add_argument("--max-tool-calls", type=int, default=80)
    ana.add_argument("--max-iterations", type=int, default=30)
    ana.add_argument("--max-cost-usd", type=float, default=1.00)

    # chat
    chat = sub.add_parser("chat", help="interactive multi-turn session (binary optional)")
    chat.add_argument("binary", nargs="?", default=None,
                     help="path to a binary (optional; can load later with /load)")
    chat.add_argument("--model", default=None)
    chat.add_argument("--runs-dir", default="runs")
    chat.add_argument("--log-level", default="INFO")
    chat.add_argument("--max-wall-time-s", type=float, default=3600.0)
    chat.add_argument("--max-tokens", type=int, default=1_000_000)
    chat.add_argument("--max-tool-calls", type=int, default=500)
    chat.add_argument("--max-iterations", type=int, default=200)
    chat.add_argument("--max-cost-usd", type=float, default=5.00)

    # replay
    rep = sub.add_parser("replay", help="inspect / replay a captured trace")
    rep.add_argument("trace", help="path to trace.jsonl")
    rep.add_argument("-v", "--verbose", action="store_true")

    # pool
    pool = sub.add_parser("pool", help="manage the Ghidra pool")
    pool.add_argument("pool_action", choices=("status", "stop-all"))

    # store
    sto = sub.add_parser("store", help="query the result store")
    sto.add_argument("store_action", choices=("recent", "get", "count"))
    sto.add_argument("--store", default="runs/results.sqlite")
    sto.add_argument("--limit", type=int, default=20)
    sto.add_argument("--trace-id", default=None)
    sto.add_argument("--format", choices=("text", "json"), default="text")

    return p


def main(argv: Optional[List[str]] = None) -> int:
    _load_env_file()
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.version or args.command == "version":
        return cmd_version(args)
    if args.command is None:
        parser.print_help()
        return 0
    if args.command == "doctor":
        return cmd_doctor(args)
    if args.command == "analyze":
        return cmd_analyze(args)
    if args.command == "chat":
        return cmd_chat(args)
    if args.command == "replay":
        return cmd_replay(args)
    if args.command == "pool":
        return cmd_pool(args)
    if args.command == "store":
        if args.store_action == "get" and not args.trace_id:
            parser.error("store get requires --trace-id")
        return cmd_store(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
