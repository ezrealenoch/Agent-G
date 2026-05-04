---
name: agent-g
description: Drive Agent-G's Ghidra HTTP server directly from a Claude Code session, with Claude Code as the analyst (no internal LLM, no API key). Use when the user wants to investigate, decompile, vulnerability-scan, or generally reverse-engineer a binary file (PE, ELF, Mach-O) — phrases like "investigate this binary", "analyze this exe", "find vulns in", "run agent-g on", "decompile this", "use Ghidra on" should trigger this skill. Also handles "install agent-g for me" / "set it up and run it on this file" from a fresh clone.
---

# Agent-G — Claude Code as the driver

Agent-G is a headless binary-analysis runtime: it spins up Ghidra in a sandbox,
exposes Ghidra's analysis tools over an authenticated HTTP API, and ships
helper scripts so a Claude Code session can drive the analysis directly via
`curl` calls in `bash`.

**This is the recommended mode** for serious vulnerability hunting. Agent-G
also supports an "internal LLM driver" mode (point `.env` at any provider via
`agent-g analyze`), but that mode has produced hallucinated decompile output
on small models in benchmark runs. Driving Ghidra from Claude Code via `bash`
makes hallucinated tool calls structurally impossible — every claim you make
about the binary must be backed by an actual `g.sh` invocation in the
transcript.

## Use this skill when

- The user asks to **investigate / analyze / decompile / vuln-scan a binary**
  ("investigate `WarpSetup.exe`", "find vulns in `babeld`", "decompile this DLL")
- The user says **"install agent-g for me"** or **"set up Agent-G and run it on …"**
- The user references **"drive Agent-G"**, **"the Ghidra HTTP server"**,
  **"`g.sh`"**, or **"`provision_ghidra.py`"**

## The headline workflow

```bash
# 1. Provision a Ghidra instance for the target binary (background)
python "$AGENT_G_HOME/skills/agent-g/provision_ghidra.py" "/path/to/binary" &
# Wait for ghidra_session.json to appear (Ghidra ingest = 30 s for small ELFs,
# can be 5-10 min for 100+ MB binaries). Poll the file, don't sleep blindly.

# 2. Query Ghidra. The g.sh helper auto-reads the auth token from the session file.
"$AGENT_G_HOME/skills/agent-g/g.sh" plugin-version
"$AGENT_G_HOME/skills/agent-g/g.sh" imports limit=100
"$AGENT_G_HOME/skills/agent-g/g.sh" strings filter=http
"$AGENT_G_HOME/skills/agent-g/g.sh" decompile_function address=0x180001000

# 3. Tear down when done
kill %1   # or kill the provisioner PID
```

## Endpoints (all GET, all bearer-token-authenticated by g.sh)

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

1. **One binary at a time.** The provisioner spawns one Ghidra JVM per binary.
   Tear down before starting a new one (concurrent provisioners race the pool's
   port-claim and produce 401s). If you need to switch targets:
   `kill <provisioner_pid> && rm ghidra_session.json && python provision_ghidra.py <new_binary> &`
2. **Log every `g.sh` query.** Write each command to a markdown file in the
   user's working directory (`investigation_log.md`) with a one-line response
   summary. This is the audit trail.
3. **Quote real curl output.** When you describe a function's behaviour in your
   final report, paste the actual `decompile_function` response. Do NOT
   paraphrase. The whole point of this driver pattern is unfakeable evidence.
4. **Wait for ingest.** Ghidra needs to do auto-analysis before any tool query
   works. Small binaries (<5 MB): ~30 s. Mid (5-50 MB): ~2 min. Large
   (>100 MB): can be 5-10+ min, sometimes failing if the pool's ready-timeout
   is hit. Poll `ghidra_session.json` until it appears; a stale provisioner
   can leave `Ghidra_session.json` empty if the JVM crashed mid-ingest.

## If `agent-g doctor` fails or the CLI isn't on PATH

The colleague hit this. Fix is one command from the cloned repo:

```bash
./install.sh        # Linux / macOS
.\install.ps1       # Windows PowerShell
```

The installer does `pip install --force-reinstall --no-deps -e .`, links
`skills/agent-g/` into `~/.claude/skills/agent-g/`, and exports an
`AGENT_G_HOME` env var for this skill's scripts to find. Both are idempotent —
re-run anytime an install gets stale.

## "Download this repo, install it, and run it on `<binary>`" — full bootstrap

```bash
git clone https://github.com/ezrealenoch/Agent-G.git
cd Agent-G
./install.sh                                    # or .\install.ps1 on Windows
# (no .env required for Claude-Code-as-driver mode — only needed for `agent-g analyze`)

# Now provision and analyze:
python skills/agent-g/provision_ghidra.py "/path/to/binary" &
# wait for ghidra_session.json
./skills/agent-g/g.sh plugin-version            # smoke test
./skills/agent-g/g.sh imports limit=100         # start the investigation
```

If the user asks Claude Code to do the bootstrap, do all of the above in one
turn — no need to ask them to confirm each step. The install scripts are
side-effect-bounded (pip install + symlink under `~/.claude/skills/`).

## What this skill is not

- **Not a wrapper around `agent-g analyze`.** The internal-LLM driver mode is
  a separate path. This skill is specifically about Claude Code calling
  `g.sh` directly. They share Agent-G's Ghidra pool and HTTP server, but the
  reasoning loop is different: this skill's loop is your assistant turn, not
  a Gemini/Claude API call inside Agent-G's process.
- **Not a replacement for `agent-g chat` or `agent-g analyze`.** Use those
  when you want batch automation, when you want a third-party LLM as the
  driver, or when you need Agent-G's `trace.jsonl` / `provenance.json` audit
  bundle. Use this skill when you want Claude Code to be the analyst.

## Common pitfalls

- **Stale `ghidra_session.json`.** If a previous provisioner crashed, the
  session file may be there but the JVM is gone. `g.sh` will hang or 401.
  Check with `ps -ef | grep provision_ghidra` (Linux/Mac) or
  `tasklist | findstr java` (Windows); kill any orphan and remove the file.
- **Concurrent provisioners.** Don't run two `provision_ghidra.py` at once.
  The Ghidra pool's `_claim_port` races and you'll get 401 mismatches. If you
  need to investigate two binaries, do them sequentially or use
  `--port` (see `provision_ghidra.py --help`).
- **`agent-g doctor` says everything is fine but `g.sh` 401s.** Stale token
  sidecar in `$TEMP/agent_g_ghidra_token_*.txt`. Delete and re-provision.
