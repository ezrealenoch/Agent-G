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

## Benchmark results

Agent-G ships with a **leak-free Juliet benchmark** (`benchmark/`) that
measures how well different LLMs drive the ReAct loop on a 30-binary
test corpus covering 10 CWE categories (OS command injection, format
string, integer overflow, divide by zero, uninitialized variable,
stack/heap overflow, double free, use-after-free, NULL deref).

Before every run the harness:
1. Anonymizes symbol names + DWARF parameter names
2. Masks Juliet scaffolding strings inside decompile output
3. Redacts the `/health` endpoint
4. Hashes the binary filename to `sample_NNNNN.bin`

So nothing in the anonymized corpus tells the model whether a given
binary is the `_bad` or `_good` variant — every verdict has to come from
actual data-flow analysis.

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
Raw F1 on the classified subset only is tracked separately in the
[full HTML report](logs/juliet_comparison_report.html).

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

You can regenerate the full HTML report any time with:

```bash
python benchmark/build_html_report.py
# → writes logs/juliet_comparison_report.html
```

---

## Model compatibility notes

What we hit while getting each model to run through the Agent-G
runtime. Short version: **Anthropic + local Ollama are painless; the
cloud models each have at least one gotcha** that Agent-G now handles
automatically in code. These are worth reading before you pick a
provider for production.

### Anthropic (Claude)

**Works out of the box** once the API key is correct. The one issue we
hit was a typo in the key itself — Anthropic returned
`401 invalid x-api-key` without pointing at the specific character
that was wrong. Lesson: when in doubt, copy-paste straight from the
Anthropic console; a single missing dash breaks the whole key.

Native `v1/messages` API + `x-api-key` header, so it sidesteps the
`Authorization: Bearer` schemes that other providers use. No
thinking-token handling needed for the standard Claude models; they
just return text.

### Google (Gemini + Gemma)

Three things bit us in sequence:

1. **Gemini 3.x is a thinking model that can exhaust its visible-token
   budget.** The response comes back with
   `candidatesTokenCount: 0` even though the request was a `STOP`
   success, because all the budget went to hidden reasoning tokens.
   Fix: `thinking_models` registry auto-bumps `maxOutputTokens` to
   32k and retries with 2x budget on empty visible output, up to a
   131k ceiling. ([`src/runtime/thinking_models.py`](src/runtime/thinking_models.py),
   [`src/external_client.py`](src/external_client.py))

2. **Gemini 3.x emits `MALFORMED_FUNCTION_CALL`** when the built-in
   function-calling mode is active and the model hasn't finished
   emitting the call. Fix: we set
   `toolConfig.functionCallingConfig.mode = NONE` for mandatory-thinking
   Gemini variants, forcing plain-text tool-call syntax instead.

3. **Gemma 4 31B returns a multi-part response** with a
   `{"thought": true}` part first and the visible answer as a second
   part. The original parser grabbed `parts[0]` (the thought!) and
   returned an empty visible string. Fix: parser now concatenates all
   non-thought text parts.

4. **Preview endpoints get shed aggressively under load.** During
   development we hit a 59/60 HTTP 503 storm on
   `gemini-3.1-flash-lite-preview` that lasted ~20 minutes. The error
   body admitted it plainly: *"This model is currently experiencing
   high demand"*. Fix: the per-provider circuit breaker
   ([`src/runtime/circuit_breaker.py`](src/runtime/circuit_breaker.py))
   trips after 3 consecutive 5xx errors and stops hammering the endpoint
   until a cooldown expires.

### OpenAI (GPT-5 family via API key)

**Worked once we knew the exact model name.** `gpt-5`, `gpt-5.4`,
`gpt-5.4-mini` are all valid; `gpt5.4`, `gpt-5-4`, `gpt-5.4-turbo` get
rejected with 400 by OpenAI's router. Use `EXTERNAL_MODEL=gpt-5.4`
verbatim.

The real gotcha: **GPT-5 writes `**INVESTIGATION COMPLETE**` as a
transitional phrase *before* producing the final verdict block.** The
original ReAct loop saw the marker, exited, and the harness classified
the response as UNKNOWN. Fix: the loop now requires *both* a completion
marker *and* a parseable verdict pattern in the same response before
exiting. If the marker appears alone, the loop keeps going. This is
covered by a regression test in
[`tests/test_conversation_replay.py`](tests/test_conversation_replay.py).

### Codex desktop OAuth (ChatGPT Team/Pro, no API key)

This was the most surprising path. The token in `~/.codex/auth.json`
**is a real OpenAI OAuth token** but it has the wrong scopes for the
public OpenAI API:

| Endpoint | Response | Reason |
|---|---|---|
| `api.openai.com/v1/chat/completions` | 500 *"Internal server error"* | Masked — means "wrong auth for this endpoint" |
| `api.openai.com/v1/responses` | 401 *"Missing scopes: api.responses.write"* | Explicit scope rejection |
| `chatgpt.com/backend-api/codex/responses` | **200 OK** | This is the endpoint Codex desktop actually uses |

The token has `api.connectors.read` + `api.connectors.invoke` scopes,
which work only against the ChatGPT-internal backend. Agent-G now
detects this case from the URL (`chatgpt.com/backend-api/codex` in
`CUSTOM_API_URL`) and switches to the Responses-API payload shape
(`instructions` + `input` list, `stream=true` mandatory, `store=false`,
`chatgpt-account-id` header). See
[`src/custom_api_client.py:_generate_chatgpt_backend`](src/custom_api_client.py).

Rate limiting on this endpoint is also stricter than on
`api.openai.com` — about 6–10 requests per minute before it 429s. Set
`CUSTOM_API_REQUEST_DELAY=10` to stay under the cap.

### Local Ollama

Small models (gemma4:e4b and friends) have a capacity issue that looks
like a thinking-model failure: they truncate to an empty completion on
long agentic prompts. We added them to the `thinking_models` registry
not because they're reasoning models, but because that registry is the
central place where Agent-G auto-bumps `num_predict`. The fix in
[`src/ollama_client.py`](src/ollama_client.py) also drops temperature
from 0.7 → 0.1 for registered small-model entries, because they
"sample themselves into" blank responses when temperature is high.

**Cloud Ollama** (models with `-cloud` suffix like
`gemma4:31b-cloud`, `qwen3.5:397b-cloud`) reliably rate-limits after
~6 binaries per minute. The circuit breaker catches it after 3
consecutive 429s and tells Agent-G to fall back or give up cleanly.

### Summary

| Provider | Works out of box? | Code changes needed |
|---|---|---|
| Anthropic (Claude) | ✅ | None (key typo was user error) |
| Google Gemini 3.x | ⚠️ | thinking_models registry, multi-part parser, circuit breaker, thinkingConfig |
| Google Gemma 4 | ⚠️ | multi-part response parser |
| OpenAI (API key) | ⚠️ | `INVESTIGATION COMPLETE` marker + verdict co-requirement |
| Codex OAuth (ChatGPT) | ⚠️ | ChatGPT backend endpoint + Responses API payload + account header |
| Ollama local (small) | ⚠️ | num_predict bump + temperature floor |
| Ollama cloud | ❌ | Rate limits unusable for batch runs; use circuit breaker + retry later |

All of these fixes are **already in the code** — you don't need to do
anything extra. But they explain the weird edge cases you might hit if
you add a new provider.

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
