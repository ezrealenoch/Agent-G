# Troubleshooting Agent-G

A by-symptom guide to the failure modes encountered most often in real investigations. For the architectural patterns themselves, see [`DRIVING.md`](./DRIVING.md).

---

## Driver mode (`agent-g drive` / `agent-g g`)

### Symptom: `agent-g g` returns 401 Unauthorized on every call

**Cause:** Stale token sidecar in `$TEMP/agent_g_ghidra_token_<port>.txt`. The Python side resolved the token from a leftover sidecar from a prior crashed run; the Java side is using a different token.

**Recovery:**
```bash
agent-g drive stop --force        # nukes session file + sidecars + orphan java
agent-g drive <binary>            # re-provision
```

**Why it happens:** When a provisioner crashes mid-flight (kill -9, OOM, host reboot), the Java JVM exits and Python's atexit handler doesn't run. The sidecar file in TEMP is left behind. On the next provisioner launch, if the OS happens to recycle the same port, the Python client reads the stale sidecar and gets the wrong token.

**Prevention:** Always use `agent-g drive stop` (not `kill -9`) to tear down. The CLI's clean shutdown path removes the sidecar.

---

### Symptom: `agent-g drive <binary>` says "another drive session is already active"

**Cause:** The mutex is working as designed — there's a `ghidra_session.json` in the cwd whose PID is still alive.

**If you intended to start a fresh session:**
```bash
agent-g drive stop
agent-g drive <binary>
```

**If you have a session in another terminal you forgot about:**
That's the running one. `agent-g drive status` will show its details. Use `agent-g g` from any cwd that has access to the session file to query it.

---

### Symptom: `agent-g drive` hangs at "waiting for Ghidra to become ready"

**Cause:** Ghidra's auto-analysis is taking longer than the timeout. Default is 600 s, which is enough for binaries up to ~50 MB but can be hit on large stripped daemons or 100+ MB Rust monoliths.

**Recovery:**
```bash
# Option 1: per-invocation flag
agent-g drive <binary> --ready-timeout 3600

# Option 2: persistent env var
export AGENT_G_GHIDRA_READY_TIMEOUT_S=3600
agent-g drive <binary>
```

**Diagnostic check:** Is the JVM actually making progress, or is it stuck?
- Linux/macOS: `top -p $(pgrep java)` and watch CPU%. If 100%, it's working.
- Windows: open Task Manager and watch java.exe CPU. Same logic.
- If CPU is 0% and there are no errors in `logs/`, the JVM is hung — kill and retry with a smaller binary or different Ghidra version.

---

### Symptom: `agent-g g` says "no drive session is active" but you just ran `drive`

**Cause:** You ran `agent-g drive <binary>` in the foreground (no `--detach`). The CLI is blocking. There's no session file written until ingest finishes, and even then the foreground process owns the terminal.

**Recovery:** Pick one:
- Run `drive` with `--detach` (returns once Ghidra is ready, then your terminal is free)
- Run `drive` in another terminal
- Run `drive` with `&` to background it: `agent-g drive <binary> &`

---

### Symptom: orphan `java.exe` / `java` processes after a crash

**Cause:** Provisioner died without running its atexit handler. Common after Ctrl+C with `--detach` (the bg process loses its parent), kill -9, or OS-level termination.

**Recovery:**
```bash
agent-g drive stop --force
```

`--force` runs `taskkill /F /IM java.exe` (Windows) or `pkill -f ghidra` (POSIX). On Windows this is broad — it'll kill all java.exe processes, so don't use `--force` if you have other Java workloads running.

**Manual recovery if `--force` is too broad:**
```bash
# Windows
tasklist | findstr java
taskkill /F /PID <pid_of_orphan>

# Linux/macOS
ps -ef | grep ghidra | grep -v grep
kill <pid_of_orphan>
```

Then `rm ghidra_session.json` and `rm $TEMP/agent_g_ghidra_token_*.txt`.

---

## Bridge mode (`agent-g analyze` / `chat`)

### Symptom: Result is recorded as `VULNERABLE` but the model emitted `Verdict: NOT_VULNERABLE`

**Cause:** Pre-`017e65d`, the verdict parser had a substring bug — `"NOT VULN" in "NOT_VULNERABLE"` is False (space vs underscore), so the next check `"VULNERABLE" in "NOT_VULNERABLE"` matched and the result was misclassified.

**Status:** Fixed in commit `017e65d`. If you're seeing this on a recent build, double-check you're on `main` and have re-run `pip install -e .`.

---

### Symptom: Model claims to have decompiled functions but `trace.jsonl` shows fewer / different addresses

**Cause:** The model is fabricating `Tool [decompile_function_by_address]: ...` blocks inline in its response without ever issuing real `EXECUTE:` directives. Common with smaller models under verdict pressure.

**Status:** Mitigated in commit `017e65d` — `_strip_hallucinated_tool_results` removes those blocks before they enter session history, and emits a `hallucinated_tool_block_stripped` event to `events.jsonl`. To check whether your run was affected:

```bash
grep hallucinated_tool_block_stripped runs/<trace_id>/events.jsonl
```

If you see hits, the model was fabricating. **Recommended action:** switch to a stronger model (Opus / GPT-5 Pro / Gemini 3.5+) or use driver mode (`agent-g drive`) instead.

---

### Symptom: Sub-agents in parallel hit 401 on every Ghidra call

**Cause:** Pre-`2b80ee3`, two `agent-g analyze` processes spawned simultaneously raced `GhidraPool._claim_port` and produced token mismatch.

**Status:** The driver-mode mutex prevents this for `drive` runs. For `analyze`, the underlying race still exists at the pool level — fix in flight. For now: serialize parallel analyze jobs in your runner.

---

### Symptom: `agent-g doctor` reports everything OK but `analyze` fails immediately with "Ghidra HTTP 401"

**Cause:** Same as the driver-mode 401 case. Stale token sidecar.

**Recovery:**
```bash
# Linux/macOS
rm /tmp/agent_g_ghidra_token_*.txt

# Windows (PowerShell)
Remove-Item $env:TEMP\agent_g_ghidra_token_*.txt
```

Then re-run.

---

## Install / setup

### Symptom: `pip install -e .` succeeds but `agent-g` is not on PATH

**Cause:** Your pip user-site bin directory isn't on PATH.

**Recovery:**
- Linux/macOS: ensure `$HOME/.local/bin` (or your venv's bin) is on PATH.
- Windows: ensure `%APPDATA%\Python\PythonXY\Scripts` is on PATH, or use `python -m src.cli` as a fallback.

**Diagnostic:**
```bash
python -c "import agent_g; print(agent_g.__file__)"
# Should print the installed location. If ImportError, pip install didn't run.
```

---

### Symptom: `agent-g doctor` reports `analyzeHeadless not found`

**Cause:** `GHIDRA_INSTALL_DIR` is wrong or unset.

**Recovery:** edit `.env` and set:
```
GHIDRA_INSTALL_DIR=C:\path\to\ghidra_12.0.2_PUBLIC
```
(or the equivalent path on your system). The directory must contain `support/analyzeHeadless` (POSIX) or `support\analyzeHeadless.bat` (Windows).

---

### Symptom: Docker mode `docker compose up` fails

**Cause:** Common: Docker Desktop not running, or BuildKit not enabled.

**Recovery:** start Docker Desktop, ensure `docker version` succeeds, then re-run.

---

## Other

### Symptom: `events.jsonl` is empty after a long run

**Cause:** A prior crash left a stale file handle, and your shell happened to be the writer.

**Recovery:** kill the orphaned shell, retry. If reproducible, file a bug.

---

### Symptom: `runs/<trace>/trace.jsonl` shows tool calls but the verdict is `UNKNOWN`

**Cause:** Either the model never produced a `## Verdict` block, or the model emitted it but in a format the parser doesn't recognize. Check the `final_text` field of `provenance.json`.

**Recovery:** if the model is consistently failing to emit a verdict, the prompt needs a tighter "you MUST emit a `## Verdict` block" instruction. Look at `vuln_followup` v1 in `prompt_library.py` for an example.

---

## When in doubt

```bash
agent-g doctor                    # full self-check
agent-g pool status               # is anything provisioned right now?
agent-g drive status              # is a driver session active?
agent-g store recent --limit 5    # what were the last few runs?
```

These are non-destructive and idempotent. Run any of them anytime.

If you're still stuck after consulting this guide, the `runs/<trace_id>/` directory is the source of truth for any run — `trace.jsonl` (every tool call), `events.jsonl` (runtime events), `checkpoint.json` (resume state), `provenance.json` (signed verdict bundle). Diff against a known-good run if needed.
