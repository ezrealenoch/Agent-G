# Agent-G

**Headless binary-analysis agent** that drives Ghidra with an LLM.

Give Agent-G a binary and it will:

1. Spin up a sandboxed Ghidra instance
2. Let an LLM investigate the binary through a ReAct tool-calling loop
3. Produce a verdict + structured report + signed audit trail

Works with Claude, Gemini, GPT-5, local Ollama models, or anything OpenAI-compatible.

---

## Install

**The only thing you need installed on your host is Docker and Python 3.10+.**
Everything else (Ghidra, Java, the sandbox) is in the container.

```bash
# 1. Clone
git clone https://github.com/ezrealenoch/Agent-G.git
cd Agent-G

# 2. Install the CLI
pip install -e .

# 3. Copy the env template and pick an LLM
cp .env.example .env
```

Open `.env` and **set exactly one provider block** (pick whichever you have access to):

```bash
# ─── Pick ONE of these ───

# Option 1: Claude (Anthropic)
LLM_PROVIDER=external
EXTERNAL_PROVIDER=anthropic
EXTERNAL_MODEL=claude-opus-4-6
EXTERNAL_API_KEY=sk-ant-api03-...

# Option 2: Gemini (Google)
LLM_PROVIDER=external
EXTERNAL_PROVIDER=google
EXTERNAL_MODEL=gemini-3.1-flash-lite-preview
EXTERNAL_API_KEY=AIza...

# Option 3: OpenAI API key
LLM_PROVIDER=external
EXTERNAL_PROVIDER=openai
EXTERNAL_MODEL=gpt-5.4
EXTERNAL_API_KEY=sk-...

# Option 4: Local Ollama (no API key, no internet)
LLM_PROVIDER=ollama
OLLAMA_MODEL=gemma4:e4b

# Option 5: ChatGPT Team/Pro via Codex desktop OAuth (no API key)
LLM_PROVIDER=custom_api
CUSTOM_API_URL=https://chatgpt.com/backend-api/codex/responses
CUSTOM_API_MODEL=gpt-5.4
CUSTOM_API_AUTH_MODE=codex_oauth
```

Then start the sandbox and run:

```bash
# Start Ghidra inside Docker (one time, ~5 min on first build)
export AGENT_G_GHIDRA_AUTH_TOKEN=$(openssl rand -base64 32)
export AGENT_G_BINARY=/abs/path/to/your/binary
docker compose -f sandbox/docker-compose.yml up --build -d

# Tell Agent-G to use the sandbox
export AGENT_G_MODE=docker
export GHIDRA_BASE_URL=http://localhost:18080

# Verify everything is wired up
agent-g doctor

# Analyze
agent-g analyze "$AGENT_G_BINARY"
```

That's it. `agent-g doctor` will tell you exactly what's missing if something is wrong.

---

## Without Docker (bare-metal)

If you'd rather run Ghidra directly on your host:

1. Install **Java JDK 17+** ([Eclipse Temurin](https://adoptium.net) recommended)
2. Download **[Ghidra 12.0.2](https://github.com/NationalSecurityAgency/ghidra/releases)** and unzip it
3. Set `GHIDRA_INSTALL_DIR=/path/to/ghidra_12.0.2_PUBLIC` in `.env`
4. Skip the Docker steps above — `agent-g analyze` will spin up Ghidra directly

`agent-g doctor` will verify JDK and Ghidra are found.

---

## Commands

```
agent-g version              Show the installed version
agent-g doctor               Self-check JDK, Ghidra, deps, and config
agent-g analyze <binary>     Analyze one binary
agent-g replay <trace>       Inspect a captured trace
agent-g pool status          Show the Ghidra instance pool
agent-g store recent         Show recent investigations
```

Run `agent-g <command> --help` for flags.

---

## What you get back

Every `analyze` run writes a full audit trail to `runs/<trace_id>/`:

```
runs/abc123def456/
├── trace.jsonl       # Every LLM call + tool call (replayable)
├── checkpoint.json   # Crash-resume snapshot
├── events.jsonl      # Runtime event stream
├── provenance.json   # Binary hash + model + prompt + verdict (signable)
└── alerts.jsonl      # Anything that fired during the run
```

Runs are also indexed in `runs/results.sqlite` so you can query prior investigations:

```bash
agent-g store recent --limit 10
agent-g store get --trace-id abc123def456
```

---

## Configuration

Full list of environment variables lives in [`.env.example`](.env.example). The big ones:

| Variable | What it controls |
|---|---|
| `LLM_PROVIDER` | `ollama` / `external` / `custom_api` |
| `EXTERNAL_PROVIDER` | `anthropic` / `google` / `openai` (when `LLM_PROVIDER=external`) |
| `EXTERNAL_API_KEY` | Your provider API key |
| `EXTERNAL_MODEL` | The model name |
| `GHIDRA_INSTALL_DIR` | Bare-metal only: path to Ghidra |
| `GHIDRA_BASE_URL` | Docker mode only: `http://localhost:18080` |
| `AGENT_G_MODE` | Set to `docker` to skip JDK/Ghidra preflight checks |
| `AGENT_G_SECRETS_BACKEND` | `env` (default), `winvault`, `vault`, `awssm` |

For production, don't put API keys in `.env`. Use a secrets backend:

```bash
pip install -e '.[winvault]'   # or .[vault] or .[awssm]
export AGENT_G_SECRETS_BACKEND=winvault
python -c "from src.runtime.secrets import set_secret; \
           set_secret('ANTHROPIC_API_KEY', 'sk-ant-...')"
```

---

## Testing

```bash
pip install -e '.[dev]'
pytest tests/ -v
```

20 regression tests covering the ReAct loop, budget enforcement, trace replay, tool schema validation, and prompt library.

---

## Architecture

`src/runtime/` is where the production-grade pieces live:

- **`conversation.py`** — ReAct loop, budget + checkpoint + trace wiring
- **`circuit_breaker.py`** — per-provider circuit with backoff and HALF_OPEN probe
- **`budget.py`** — hard caps on wall-time, tokens, tool calls, cost (with pricing table)
- **`checkpoint.py`** — atomic JSON checkpoints for crash-resume
- **`trace.py`** — append-only JSONL trace + replay + provenance bundle
- **`ghidra_pool.py`** — stateless pool manager (concurrent investigations)
- **`result_store.py`** — SQLite store for querying prior runs
- **`prompt_library.py`** — versioned prompts with content hashes
- **`tool_schema.py`** — strict validation of LLM tool calls
- **`observability.py`** — JSON logs + trace-id contextvar + alert sinks
- **`secrets.py`** — pluggable secrets chain (env / winvault / vault / awssm)

`benchmark/` holds the Juliet test-suite harness (not imported by production code). `sandbox/` holds the Docker image. `tests/` holds the regression suite.

---

## License

MIT — see [LICENSE](LICENSE).
