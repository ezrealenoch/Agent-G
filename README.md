# Agent-G

**Headless binary-analysis agent** that drives Ghidra with an LLM.

Give Agent-G a binary and it will:

1. Spin up a sandboxed Ghidra instance
2. Let an LLM investigate the binary through a ReAct tool-calling loop
3. Produce a verdict + structured report + signed audit trail

Works with Claude, Gemini, GPT-5, local Ollama models, or anything OpenAI-compatible.

---

## Install

Agent-G has two parts that run in different places:

| Component | Where it runs | Why |
|---|---|---|
| **Ghidra HTTP server** | Inside a Docker container (recommended) or bare-metal on your host | Analyzes the untrusted binary; isolated from your host via Docker |
| **Agent-G CLI** | Always on your host | Talks to your LLM provider; you need the API keys here |

Pick one of the two install paths below. Both end with the same `agent-g analyze` command.

### Path A — Docker (recommended)

**Docker side** (runs the Ghidra sandbox):
- Docker 24+ with `compose v2` — **no Java, no Ghidra install**, everything is baked into the image

**Host side** (runs the Agent-G CLI):
- Python 3.10+
- `pip install -e .`

```bash
# 1. Clone + install the host CLI
git clone https://github.com/ezrealenoch/Agent-G.git
cd Agent-G
pip install -e .

# 2. Copy the env template and fill in ONE provider's credentials
cp .env.example .env
$EDITOR .env   # see .env.example for inline provider docs

# 3. Spin up the Docker Ghidra sandbox
export AGENT_G_GHIDRA_AUTH_TOKEN=$(openssl rand -base64 32)
export AGENT_G_BINARY=/abs/path/to/your/binary
docker compose -f sandbox/docker-compose.yml up --build -d

# 4. Point the CLI at the sandbox and verify
export AGENT_G_MODE=docker
export GHIDRA_BASE_URL=http://localhost:18080
agent-g doctor      # should print PASS

# 5. Analyze
agent-g analyze "$AGENT_G_BINARY"
```

### Path B — Bare-metal (no Docker)

**Host side** (runs everything):
- Python 3.10+
- **Java JDK 17+** ([Eclipse Temurin](https://adoptium.net) recommended)
- **Ghidra 12.0.2** ([download](https://github.com/NationalSecurityAgency/ghidra/releases))
- `pip install -e .`

```bash
# 1. Install Java + Ghidra on your host
#    Ubuntu/Debian:
sudo apt install -y openjdk-17-jdk unzip wget
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.0.2_build/ghidra_12.0.2_PUBLIC_20240314.zip
unzip ghidra_12.0.2_PUBLIC_20240314.zip -d /opt/
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.0.2_PUBLIC

# 2. Clone + install the Agent-G CLI
git clone https://github.com/ezrealenoch/Agent-G.git
cd Agent-G
pip install -e .

# 3. Configure credentials
cp .env.example .env
$EDITOR .env   # set GHIDRA_INSTALL_DIR and ONE provider block

# 4. Verify
agent-g doctor      # should print PASS

# 5. Analyze
agent-g analyze /path/to/binary
```

`agent-g doctor` tells you exactly what's missing if anything is wrong.

---

## Configuration

All configuration lives in `.env`. Copy [`.env.example`](.env.example) and
edit — the file is the single source of truth for every knob Agent-G reads,
grouped into labelled sections with inline comments for each provider.

At minimum you need to set:

1. **One LLM provider block** (Anthropic / Google / OpenAI / Codex OAuth / Ollama — all documented inline in `.env.example`)
2. **`GHIDRA_INSTALL_DIR`** (bare-metal only) or **`AGENT_G_MODE=docker` + `GHIDRA_BASE_URL`** (Docker only)

For production, prefer a real secrets backend over `.env`:

```bash
pip install -e '.[winvault]'   # or .[vault] or .[awssm]
export AGENT_G_SECRETS_BACKEND=winvault
python -c "from src.runtime.secrets import set_secret; \
           set_secret('ANTHROPIC_API_KEY', 'sk-ant-...')"
```

---

## Benchmark results

Agent-G ships with a **leak-free Juliet benchmark** (`benchmark/`) that
measures how well different LLMs drive the ReAct loop on a 30-binary
test corpus covering 10 CWE categories (OS command injection, format
string, integer overflow, divide by zero, uninitialized variable,
stack/heap overflow, double free, use-after-free, NULL deref).

Before every run the harness anonymizes symbol names, strips DWARF
parameter names, masks Juliet scaffolding strings inside decompile
output, redacts the `/health` endpoint, and hashes the binary filename
to `sample_NNNNN.bin`. Nothing in the anonymized corpus tells the
model whether a binary is the `_bad` or `_good` variant — every
verdict has to come from actual data-flow analysis.

![Effective F1 by model](docs/images/benchmark_f1.svg)

| # | Model | Provider | Eff F1 | Coverage | TP/TN/FP/FN | UNK / BLANK |
|---|---|---|---|---|---|---|
| 🥇 1 | **Claude Opus 4.6** (blind) | Anthropic | **1.000** | 30/30 | 15 / 15 / 0 / 0 | 0 / 0 |
| 🥈 2 | Claude Sonnet 4.5 | Anthropic | 0.629 | 29/30 | 11 / 6 / 8 / 4 | 1 / 0 |
| 🥉 3 | Gemini 3.1 Flash Lite | Google | 0.611 | 26/30 | 11 / 5 / 8 / 2 | 2 / 2 |
| 4 | GPT-5.4 (Codex OAuth) | OpenAI | 0.583 | 27/30 | 7 / 13 / 1 / 6 | 3 / 0 |
| 5 | gemma4:e4b (local) | Ollama | 0.276 | 12/30 | 4 / 5 / 0 / 3 | 0 / 18 |
| 6 | GPT-5.4 Mini | OpenAI | 0.222 | 29/30 | 2 / 14 / 0 / 13 | 1 / 0 |

**"Effective F1"** counts any `UNKNOWN` or `BLANK` response as a wrong
answer (missed bug on a vulnerable binary, false alarm on a safe one).

### What we learned

- **Only Claude Opus 4.6 actually solves this corpus** (30/30 clean).
  Every other model faces the standard precision/recall trade-off.
- **Gemini Flash Lite and Claude Sonnet 4.5 are "aggressive"** — high
  recall on real bugs, high false-positive rate on safe variants
  ("shout wolf" bias).
- **GPT-5.4 and GPT-5.4 Mini are "conservative"** — near-perfect
  precision but they miss most real vulnerabilities, especially Mini
  which committed to `NOT_VULNERABLE` on 13 of 15 bad binaries.
- **gemma4:e4b struggles with commitment, not reasoning.** When it
  commits to a verdict (12/30 cases) its raw F1 is 0.727 — better than
  Flash Lite's. The problem is the other 18 binaries where the small
  model goes blank before producing a verdict block.
- **GPT-5.4 Mini is pathologically cautious on security tasks.**
  Precision 1.000 but recall 0.133. On a vulnerability audit you want
  the opposite trade-off.

The full HTML report — including per-CWE heatmap, per-model verdict
matrix, and a **Model Compatibility Notes** section documenting every
quirk we hit per provider and the code fix that handles it — lives at
[`logs/juliet_comparison_report.html`](logs/juliet_comparison_report.html).
Regenerate any time with:

```bash
python benchmark/build_html_report.py
```

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

## Testing

```bash
pip install -e '.[dev]'
pytest tests/ -v
```

20 regression tests covering the ReAct loop, budget enforcement,
trace replay, tool schema validation, and prompt library.

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
