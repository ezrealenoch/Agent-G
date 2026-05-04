# Driving Agent-G from Claude Code

> **Pattern**: provisioner-as-daemon + stateless authenticated HTTP + analyst-as-orchestrator. Agent-G acts as the Ghidra sandbox manager; Claude Code is the analyst making decisions about what to query next.

This document covers the *strategic* patterns that produce credible results — when to use which mode, how to dispatch sub-agents, how to maintain auditable evidence trails. The CLI subcommands (`agent-g drive`, `agent-g g`) take care of the operational details. This document tells you how to use them well.

---

## Why driver mode exists

Agent-G has two operating modes that share the same Ghidra pool:

| Mode | Driver | Trust model |
|---|---|---|
| `agent-g analyze` / `chat` | LLM provider configured in `.env` (Claude / GPT / Gemini / Ollama) | The model is given tools; the runtime validates each tool call against `tool_schema`. |
| `agent-g drive` + `agent-g g` | Claude Code (or any external bash-capable orchestrator) via authenticated HTTP | Every claim is backed by a real `agent-g g` invocation in the bash transcript. Hallucinated tool calls are structurally impossible. |

Driver mode was added after multi-binary benchmark runs revealed that small models (Gemini Flash Lite, sometimes even Opus under verdict pressure) fabricate `Tool [...]:` blocks in `response_text` without issuing real `EXECUTE:` directives. The runtime now strips those (see `_strip_hallucinated_tool_results`), but driver mode sidesteps the failure mode entirely: there is no model-authored response text to fabricate from. There's just bash, with curl invocations that either ran or didn't.

---

## When to use which mode

| Use case | Mode |
|---|---|
| Interactive investigation, want full audit trail of every Ghidra query | `drive` + `g` |
| Vulnerability hunt with the strongest available reasoning model | `drive` + `g` (drives Claude Code's session) |
| Need unfakeable evidence (regulatory, customer report, public disclosure) | `drive` + `g` |
| Batch / CI / unattended scanning of many binaries | `analyze` |
| Benchmarking a specific LLM provider on Juliet | `analyze --model <name>` |
| Need the structured `provenance.json` audit bundle | `analyze` |
| Conversational state across multiple binaries with an internal LLM | `chat` |

The two modes share Ghidra's pool, the same HTTP API, and the same security model. They differ only in who's holding the prompt loop — your Claude Code terminal vs. an LLM API call inside Agent-G's process.

---

## The lifecycle pattern

```
agent-g drive <binary> --detach        # 1. Provision (5 s for small ELFs, ~6 min for 144 MB Rust)
                                       #    Returns once Ghidra is ingested + ready.

agent-g g plugin-version               # 2. Verify
agent-g g imports limit=100            # 3. Query many times
agent-g g strings filter=http
agent-g g decompile_function address=0x401000
# ... 30-100 more queries ...

agent-g drive stop                     # 4. Tear down (kills JVM, removes session,
                                       #    purges stale token sidecars)
```

The efficiency comes from one fact: **Ghidra ingest is the only slow step**. Once it's ingested, every query is fast (<100 ms) because Ghidra is just walking its in-memory program database. The provisioner's job is to keep the JVM alive across a long sequence of cheap queries.

---

## Pre-stage Ghidra, then dispatch focused sub-agents

The single biggest efficiency gain in multi-binary investigations is the dispatch order:

**Don't do this:**
```
1. Spawn sub-agent
2. Sub-agent spends 5 minutes waiting for Ghidra to ingest
3. Sub-agent has 25 minutes of analysis time left
```

**Do this:**
```
1. You (foreground) run `agent-g drive <binary>` (5 minutes)
2. You verify with `agent-g g plugin-version` (200 ms)
3. You spawn the sub-agent with the binary already provisioned
4. Sub-agent has the full 30 minutes for analysis
```

This nearly doubles per-binary throughput. The sub-agent's prompt should mention that Ghidra is already provisioned and they should start querying immediately via `agent-g g`.

---

## Run sub-agents serially across binaries

The `drive` mutex prevents this from being a footgun, but it's worth understanding *why* the mutex exists.

Two parallel `drive` invocations would both try to claim port 19000 from `GhidraPool._claim_port`. Each pool maintains its own `_claimed_ports` set in-memory, so they both think 19000 is free; they both try to bind; one wins; the other's bearer token is for a port the Java side never listened on. Result: 401 on every `agent-g g` call from the loser's perspective, with no obvious failure signal.

The fix in this codebase is the mutex: `drive` refuses to start if a session file with a live PID already exists. To investigate multiple binaries:

```bash
agent-g drive bin1 --detach
# ... investigate bin1 ...
agent-g drive stop
agent-g drive bin2 --detach
# ... investigate bin2 ...
agent-g drive stop
```

Or wrap that in a loop. Don't try to parallelize the driver itself.

---

## Why `g` is intentionally dumb

`agent-g g <endpoint> [k=v ...]` is the simplest possible authenticated HTTP wrapper:

```python
url = f"{base_url}/{endpoint}"
headers = {"Authorization": f"Bearer {auth_token}"}
return requests.get(url, params=params, headers=headers, timeout=120)
```

That's it. No state, no caching, no session management. Each call is independent. If the JVM dies between calls, the next `g` fails fast with a clean error. If you want to switch binaries, you `drive stop && drive <new>` — no stale connections to clean up because there are no connections, just stateless HTTPGETs.

This deliberate dumb-ness is what makes the audit trail work. Every claim about a binary corresponds to one bash line that either succeeded or didn't. Nothing else.

---

## Audit trail discipline

The driver pattern's selling point is unfakeable evidence. To preserve that property, write a markdown log alongside your investigation:

```markdown
# investigation_log_<binary>.md

## Reconnaissance
$ agent-g g imports limit=20
... (paste real output) ...

$ agent-g g segments
... (paste real output) ...

## Functions of interest
$ agent-g g searchFunctions query=parse
... (real output) ...

$ agent-g g decompile_function address=0x401234
... (real output, 5-30 lines) ...

## Findings
- LOW: foo() at 0x401234 missing bounds check
  Evidence: see decompile output above lines 5-12
```

Two rules:

1. **Quote real output.** Every claim about a function's behavior cites the actual `decompile_function` response. Don't paraphrase. Paste.
2. **Don't claim a tool call you didn't make.** This is what Claude Code's bash transcript already enforces — but writing the log preserves the property even after the session ends.

---

## Recovery from common failures

| Symptom | What happened | Recovery |
|---|---|---|
| `agent-g g` returns 401 on every call | Stale token sidecar in `$TEMP` from a crashed prior session | `agent-g drive stop --force && agent-g drive <binary>` |
| `agent-g drive <binary>` says "another drive session is already active" | A previous session is still running OR crashed leaving a stale session file | If you intentionally have one running: that's the mutex working. Otherwise: `agent-g drive stop` |
| `agent-g drive` exits with a Ghidra-ready timeout | Binary too large for the default 600 s ingest budget | `agent-g drive <binary> --ready-timeout 3600`, or set `AGENT_G_GHIDRA_READY_TIMEOUT_S=3600` |
| `agent-g g` says "no drive session is active" | You forgot `--detach` and the foreground `drive` is in another terminal | Either run `drive` with `&` to background it, use `--detach`, or open another terminal |
| Orphan `java.exe` processes in `tasklist` | Provisioner crashed mid-flight | `agent-g drive stop --force` |
| `agent-g drive --detach` returns immediately but `agent-g g plugin-version` 404s | Ghidra ingest hasn't finished yet (`--detach` returns when the *provisioner* is forked, not when ingest is done) | Re-run without `--detach` so you see the ready signal, or poll `plugin-version` until it returns 200 |

See [`TROUBLESHOOTING.md`](./TROUBLESHOOTING.md) for the full failure catalog.

---

## Comparison to the bridge-based driver (`analyze` / `chat`)

| Property | Bridge mode | Driver mode |
|---|---|---|
| Driver model | LLM API call inside Agent-G's process | Your Claude Code session |
| Tool dispatch | `EXECUTE: ...` directives parsed from response_text | `agent-g g` calls in bash |
| Hallucination guard | Runtime strips fabricated `Tool [...]:` blocks (commit 017e65d) | Structurally impossible — no response_text to fabricate from |
| Audit format | `runs/<trace>/trace.jsonl` + `provenance.json` | Bash transcript + your investigation_log.md |
| Resume after interrupt | Checkpoint replay via `agent-g replay` | Re-run last `agent-g g` calls; state was on the Ghidra side |
| Cost | LLM API tokens | Your Claude Code session budget |
| Verdict format | Structured `verdict=VULNERABLE/NOT_VULNERABLE` block | Whatever you write in your final summary |

Both modes have legitimate uses. Driver mode is preferred when the *act* of generating evidence matters — when you need to be able to say, weeks later, "here's the bash command that produced this decompile, here's the bytes it returned." Bridge mode is preferred when you need a structured verdict bundle for a CI pipeline.
