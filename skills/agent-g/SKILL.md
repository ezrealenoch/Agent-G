---
name: agent-g
description: Drive Agent-G's Ghidra HTTP server directly from a Claude Code session, with Claude Code as the analyst (no internal LLM, no API key). Use when the user wants to investigate, decompile, vulnerability-scan, or generally reverse-engineer a binary file (PE, ELF, Mach-O) — phrases like "investigate this binary", "analyze this exe", "find vulns in", "run agent-g on", "decompile this", "use Ghidra on" should trigger this skill. Also handles "install agent-g for me" / "set it up and run it on this file" from a fresh clone.
---

# Agent-G — Claude Code as the driver

Agent-G is a headless binary-analysis runtime: it spins up Ghidra in a sandbox,
exposes Ghidra's analysis tools over an authenticated HTTP API, and ships
two CLI subcommands so a Claude Code session can drive the analysis directly:

  - `agent-g drive <binary>` — provision Ghidra for one binary, hold the
    session open until interrupted
  - `agent-g g <endpoint> [k=v ...]` — authenticated query against the
    running session

**This is the recommended mode** for serious vulnerability hunting. Agent-G
also supports an "internal LLM driver" mode (point `.env` at any provider via
`agent-g analyze`), but that mode has produced hallucinated decompile output
on small models in benchmark runs. Driving Ghidra from Claude Code via `bash`
makes hallucinated tool calls structurally impossible — every claim about the
binary must be backed by an actual `agent-g g` invocation in the transcript.

## Use this skill when

- The user asks to **investigate / analyze / decompile / vuln-scan a binary**
  ("investigate this installer", "find vulns in this daemon", "decompile this DLL")
- The user says **"install agent-g for me"** or **"set up Agent-G and run it on …"**
- The user references **"drive Agent-G"**, **"the Ghidra HTTP server"**, or
  **"`agent-g drive`"** / **"`agent-g g`"**

## The headline workflow (post `pip install -e .`)

```bash
# 1. Provision (foreground; blocks until Ctrl+C)
agent-g drive /path/to/binary
# Or, to fork into the background and return immediately:
agent-g drive /path/to/binary --detach

# 2. Query (in another terminal, or after --detach)
agent-g g plugin-version                 # health check
agent-g g imports limit=100
agent-g g strings filter=http
agent-g g decompile_function address=0x180001000
agent-g g xrefs_to address=0x180001000

# 3. Tear down (only needed if --detach was used)
agent-g drive stop
```

When you run `drive` in the background and then make `g` calls, write each
command + a one-line response summary to a markdown file in the user's
working directory (`investigation_log.md`). This is the audit trail —
the whole point of this driver pattern is that every claim is backed by a
real bash invocation.

## Endpoints

| Endpoint | Params | Purpose |
|---|---|---|
| `plugin-version` | — | health check (run this first) |
| `imports` | `offset`, `limit` | list dynamically-imported symbols |
| `exports` | `offset`, `limit` | list exported symbols |
| `segments` | — | section / segment table |
| `list_functions` | `offset`, `limit` | all defined functions |
| `searchFunctions` | `query`, `offset`, `limit` | name-substring search |
| `strings` | `offset`, `limit`, `filter` | extracted strings (with optional substring filter) |
| `decompile_function` | `address` | decompiled C for one function |
| `disassemble_function` | `address` | raw x86/ARM/RISC-V disassembly for one function |
| `xrefs_to` / `xrefs_from` | `address`, `offset`, `limit` | references in / out of address |
| `function_xrefs` | `name` | all xrefs touching a named function |
| `get_function_by_address` | `address` | function metadata at address |
| `read_bytes` | `address`, `length`, `format=hex\|ascii\|raw` | raw bytes |

## Discipline

1. **One binary at a time.** `agent-g drive` enforces this with a mutex —
   it refuses to start if another session is active. To switch targets:
   `agent-g drive stop && agent-g drive <new_binary>`.
2. **Log every `g` query.** Write each command to a markdown file in the
   user's working directory (`investigation_log.md`) with a one-line
   response summary. This is the audit trail.
3. **Quote real curl output.** When you describe a function's behavior in
   your final report, paste the actual `decompile_function` response. Do
   NOT paraphrase. The whole point of this driver pattern is unfakeable
   evidence.
4. **Wait for ingest.** Ghidra needs to do auto-analysis before any tool
   query works. Small binaries (<5 MB): ~30 s. Mid (5-50 MB): ~2 min.
   Large (>100 MB): can be 5-10+ min. The `drive` command blocks until
   Ghidra is ready; you don't need to poll. If your binary is huge and
   the default 600 s timeout might be hit, set `--ready-timeout 3600`
   (or export `AGENT_G_GHIDRA_READY_TIMEOUT_S=3600` for the same effect).

## Recovery from common failures

| Symptom | Recovery |
|---|---|
| `agent-g g` returns 401 | Stale session/sidecar. `agent-g drive stop --force && agent-g drive <binary>` |
| `agent-g drive` says "another drive session is already active" | `agent-g drive stop` |
| `agent-g drive` exits with a Ghidra-ready timeout | `agent-g drive <binary> --ready-timeout 3600` (or use a smaller binary) |
| `agent-g g` says "no drive session is active" | You forgot `--detach`. Either run `drive` in another terminal/background, or use `&` |
| Orphan Java processes hanging around | `agent-g drive stop --force` |

## If `agent-g doctor` fails or the CLI isn't on PATH

The colleague hit this. Fix is one command from the cloned repo:

```bash
./install.sh        # Linux / macOS
.\install.ps1       # Windows PowerShell
```

The installer does `pip install --force-reinstall --no-deps -e .`, links
`skills/agent-g/` into `~/.claude/skills/agent-g/`, and exports an
`AGENT_G_HOME` env var. Both are idempotent — re-run anytime an install
gets stale.

## "Download this repo, install it, and run it on `<binary>`" — full bootstrap

```bash
git clone https://github.com/ezrealenoch/Agent-G.git
cd Agent-G
./install.sh                                    # or .\install.ps1 on Windows
# (no .env required for Claude-Code-as-driver mode — only needed for `agent-g analyze`)

# Now provision and analyze:
agent-g drive /path/to/binary --detach
agent-g g plugin-version                        # smoke test
agent-g g imports limit=100                     # start the investigation
# ... many g calls ...
agent-g drive stop
```

If the user asks Claude Code to do the bootstrap, do all of the above in
one turn — no need to ask them to confirm each step. The install scripts
are side-effect-bounded (pip install + symlink under `~/.claude/skills/`).

## Fallback: shell-only (no `agent-g` CLI on PATH)

If `pip install -e .` hasn't run and the `agent-g` CLI isn't on PATH, the
skill still ships standalone helper scripts in this directory:

```bash
python "$AGENT_G_HOME/skills/agent-g/provision_ghidra.py" /path/to/binary &
"$AGENT_G_HOME/skills/agent-g/g.sh" plugin-version
"$AGENT_G_HOME/skills/agent-g/g.sh" imports limit=100
kill %1
```

Same Ghidra pool, same HTTP API. The CLI subcommands are a thin wrapper
around these scripts; both work without modification. Prefer the CLI
when available.

## What this skill is not

- **Not a wrapper around `agent-g analyze`.** The internal-LLM driver
  mode is a separate path. This skill is specifically about Claude Code
  calling `agent-g g` directly.
- **Not a replacement for `agent-g chat`.** Use `chat` when you want
  conversational state across multiple binaries with an internal LLM.
  Use `drive`/`g` when you want Claude Code to be the analyst with full
  control over every Ghidra query.
