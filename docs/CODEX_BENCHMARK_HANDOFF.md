# Codex Handoff: Agent-G Juliet Cheat-Resistant Benchmark

> **2026-04-07 amendment** — significant changes landed late on 2026-04-07 that supersede some of the guidance below. **Read this block first**:
>
> 1. **All three known data leaks have been plugged at the source.** Decompile string literals, DWARF parameter names, and `/health` endpoint name disclosure are all fixed in `src/runtime/leak_filter.py`, `ghidra/scripts/JulietAnonymizer.java`, and `ghidra/scripts/OGhidraHeadlessServer.java` respectively. Verified end-to-end via direct probe + Google Flash Lite smoke test. The "Known Leakage" notice in the HTML report still mentions the historical issue but new runs are leak-free.
>
> 2. **CLI flags now bypass `.env` entirely.** Pass `--llm-provider`, `--external-provider`, `--llm-model`, `--llm-api-key`, `--llm-base-url` to `test_juliet.py` and the harness will override `.env` at config-load time. Multiple Agent-G instances can now run concurrently without `.env` races. The §4 inline-env pattern below is still useful for environment variables, but the CLI-flag pattern is the recommended one going forward.
>
> 3. **Anthropic and OpenAI providers are now first-class** in `src/external_client.py`. Both implement the same thinking-model max_tokens auto-bump and empty-response retry escalation as the existing Google path. The canonical `BLANK_RESPONSE_SENTINEL` lives in `src/runtime/thinking_models.py` so all four clients (Google/Anthropic/OpenAI/Ollama) reference the same string.
>
> 4. **Codex OAuth path: works at the resolution layer, blocked at the API layer.** The custom_api client correctly resolves the OAuth access token from `~/.codex/auth.json`, but the token is **missing the `api.responses.write` scope** required by `/v1/responses`, and is rejected by `/v1/chat/completions` with a masked 500 error. To use Codex OAuth for the harness, either populate the `OPENAI_API_KEY` field in `auth.json` (currently empty) or request a token with the right scope. See §7 of `BENCHMARK_COORDINATION.md` for the full diagnosis.
>
> 5. **e4b runtime + classifier fixes** drop the `"(no response)"` mislabeling pattern. New e4b runs will correctly tag empty completions as `BLANK_RESPONSE` instead of `UNKNOWN`. Temperature is also lowered to 0.1 for small-model capacity-fix entries.
>
> Sections below describe the original handoff. Anything that conflicts with this amendment is superseded.



**Audience**: Codex (OpenAI's coding agent), or any other agent runtime with access to multiple OpenAI / Anthropic / xAI / Mistral / etc. models.

**Goal**: Reproduce the Agent-G Juliet vulnerability-analysis benchmark on your model lineup so we can append your results to the existing multi-model comparison report.

**Existing benchmark**: 6 models so far — Claude (blind sub-agents), Gemini 3.1 Pro Preview, Gemini 3.1 Flash Lite Preview, qwen3.5:397b-cloud, gemma4:31b-cloud, gemma4:e4b (local). Two corpora:
- **Original 20** (5 CWE categories: 121, 122, 415, 416, 476)
- **New 30** (5 additional CWE categories: 78, 134, 190, 369, 457)
- **Total**: 50 anonymized ELF-x86_64 binaries from the NIST Juliet Test Suite

---

## 1. Why this benchmark is hard to cheat on

The Juliet Test Suite ships binaries whose exported symbols, function names, file paths, and even some embedded strings encode the answer (e.g. `CWE121_Stack_Based_Buffer_Overflow__CWE129_connect_socket_01_bad`). Without sanitisation, any "benchmark" becomes a test of filename pattern matching. Three layers of defence are applied:

1. **Symbol renaming** — A Ghidra `-postScript` (`JulietAnonymizer.java`) renames every leaky function and data symbol (`CWE*`, `*_bad`, `*_good`, `printLine`, `decodeHex`, `goodG2B`, etc.) to generic `FUN_<addr>` / `DAT_<addr>` forms with `SourceType.USER_DEFINED` so Ghidra's analyzer can't restore them.

2. **String filtering** — A Python `LeakFilter` wraps the tool runner and strips lines containing leak tokens from `/list_strings` results before the model sees them. The current LeakFilter pattern set is in `src/runtime/leak_filter.py` and was extended on 2026-04-07 to also catch `printLine`, `printIntLine`, `printStruct`, `decodeHex`, `globalReturns`, `goodG2B`, `omitbad/omitgood`.

3. **Filename hashing** — The original filename is replaced with `sample_NNNNN.bin` (hash-derived) in all prompts, preventing the model from reading the CWE label out of the file path, and `/health` is forbidden after the readiness poll because it returns Ghidra's program name.

A leak verifier (`scripts/verify_corpus_leaks.py`) confirmed all 50 binaries return zero leak tokens across `/exports`, `/imports`, `/strings`, `/symbols`, `/segments` after the LeakFilter is applied.

---

## 2. What you need from us

We will (or already have) provided you with:

| Item | Where |
|---|---|
| The 50 binary IDs | `logs/new_corpus_30_ids.txt` (new 30) + the original 20 are derivable from the manifest defaults |
| The Juliet binary tree | `C:/Users/Era/Desktop/ClawdBot/binary-samples/regression-suite/` (or the equivalent on your machine — it's the standard NIST Juliet 1.3 ELF build, unmodified) |
| The Juliet manifest | `C:/Users/Era/Desktop/ClawdBot/binary-samples/regression-suite/manifest_juliet_full.json` (large JSON streamed via `ijson`) |
| Ghidra 12.0.2 PUBLIC | `C:/Users/Era/Desktop/OGhidra/ghidra_12.0.2_PUBLIC` |
| The Agent-G repo | `C:/Users/Era/Desktop/OGhidra/Agent-G` |
| `JulietAnonymizer.java` | `Agent-G/ghidra/scripts/JulietAnonymizer.java` |
| `OGhidraHeadlessServer.java` (HTTP server post-script) | `Agent-G/ghidra/scripts/OGhidraHeadlessServer.java` |
| `ghidra_oneshot.py` (start/stop helper) | `Agent-G/scripts/ghidra_oneshot.py` |
| The expected result schema | See §6 below |

---

## 3. Two equivalent integration paths

### Path A — Use Agent-G's harness directly (recommended for OpenAI / Mistral / xAI models)

Agent-G's `scripts/test_juliet.py` already supports an "external" provider tier that works with anything speaking the OpenAI Chat Completions API. To run a new model:

1. Set environment variables for your provider:

   ```bash
   # OpenAI (e.g. gpt-5, gpt-5.1-codex, o4-mini, gpt-4.1)
   export LLM_PROVIDER=external
   export EXTERNAL_PROVIDER=openai
   export EXTERNAL_BASE_URL=https://api.openai.com/v1
   export EXTERNAL_MODEL=gpt-5.1-codex      # or o4-mini, gpt-5, etc.
   export EXTERNAL_API_KEY=sk-...

   # xAI Grok
   export EXTERNAL_PROVIDER=xai
   export EXTERNAL_BASE_URL=https://api.x.ai/v1
   export EXTERNAL_MODEL=grok-4
   export EXTERNAL_API_KEY=xai-...

   # Mistral
   export EXTERNAL_PROVIDER=mistral
   export EXTERNAL_BASE_URL=https://api.mistral.ai/v1
   export EXTERNAL_MODEL=mistral-large-latest
   export EXTERNAL_API_KEY=...
   ```

2. Run the harness on the **original 20**:

   ```bash
   cd C:/Users/Era/Desktop/OGhidra/Agent-G
   python -u scripts/test_juliet.py \
     --port 21000 \
     --out-tag <model_tag>_old20
   ```

3. Run it on the **new 30** (broader CWE coverage):

   ```bash
   python -u scripts/test_juliet.py \
     --only-ids logs/new_corpus_30_ids.txt \
     --cwes "CWE-121,CWE-122,CWE-415,CWE-416,CWE-476,CWE-78,CWE-134,CWE-190,CWE-369,CWE-457" \
     --port 21100 \
     --out-tag <model_tag>_new30
   ```

   Total target: **50 binaries × your model count**.

4. Output JSON files land in `Agent-G/logs/juliet_test_<timestamp>_<model_tag>_old20.json` and `..._new30.json`. Their schema is `{"records": [{...}], "metrics": {...}}` — see `compute_metrics()` in `scripts/test_juliet.py`.

### Important harness notes

- **Thinking models**: The harness already auto-bumps `max_tokens` for known thinking models via `src/runtime/thinking_models.py`. If your model is a thinking model not yet in the registry (gpt-5 with reasoning, o4-mini, o3, deepseek-r1, etc.), add it to the patterns list. The constant `THINKING_MODEL_MAX_TOKENS = 32768` and ceiling `MAX_THINKING_RETRY_CEILING = 131072` may both need bumping for reasoning-heavy models.

- **Tool use mode**: For models prone to malformed function calls, the harness can fall back to a JSON-action protocol. If you see "MALFORMED_FUNCTION_CALL"-style errors, set `EXTERNAL_TOOL_MODE=json_action` (or whatever the equivalent is for your provider) and re-run.

- **Per-binary timeout**: `INVESTIGATION_TIMEOUT = 240 s`. For very slow reasoning models, bump this in `scripts/test_juliet.py:74`.

- **Don't change LeakFilter, don't change JulietAnonymizer**, don't change the prompts in `bridge_lite.py`. If you want to vary the prompt, run a separate experiment, don't overwrite the baseline.

### Path B — Replicate the "blind sub-agent" harness (Claude-style)

If your runtime doesn't have a Python LLM client but does support shell + an LLM, replicate the Claude blind setup from `Agent-G/scripts/ghidra_oneshot.py`:

1. For each binary in the corpus, in your agent (one agent per binary, or batches of 5):
   - **Start**: `python ghidra_oneshot.py start --id "<juliet_id>" --port <P>` in the background
   - **Wait**: poll `curl http://localhost:<P>/health` until response contains `ready`. **STOP CALLING `/health` AFTER READY** — it leaks the original program name.
   - **Investigate** using these endpoints (all GET):
     - `/list_functions?limit=20&offset=N`
     - `/list_imports?limit=20`
     - `/list_exports?limit=20`
     - `/list_strings?limit=20&filter=<token>` (auto-LeakFiltered)
     - `/list_segments`
     - `/decompile_function_by_address?address=<addr>` ← key tool
     - `/get_xrefs_to?address=<addr>`
     - `/get_xrefs_from?address=<addr>`
     - `/disassemble_function?address=<addr>`
     - `/read_bytes?address=<addr>&length=<N>`
   - **Stop**: `python ghidra_oneshot.py stop --port <P>`
   - Append a result row to your output JSON.

2. Use the prompt template in `logs/claude_blind_batch_*_input.json` for the input format and `logs/juliet_test_20260407_claude_blind_new30.json` for the expected output schema. The blind setup is described in detail in `logs/juliet_claude_blind_comparison.md`.

---

## 3.5. Concurrency and port ranges (read if running multiple agents at once)

If you want to run several benchmarks in parallel — either on your own, or alongside Agent-G's own sequential queue — here's what you must coordinate.

### Port range reservation

The harness takes `--port <base>` and uses `base + i` for binary `i` (1..N). Two runs with overlapping bases will cause Ghidra's `analyzeHeadless` to fail binding the second instance. Use the following reservation table:

| Port range | Reserved for |
|---|---|
| 18000–18999 | Interactive development, ad-hoc runs |
| 19000–19999 | Agent-G legacy (original 20-binary runs, now historical) |
| 20000–20999 | Agent-G blind sub-agent harness (Claude-style) |
| 21000–21999 | Agent-G production benchmarks, first active run |
| 22000–22999 | Agent-G production benchmarks, second active run |
| **23000–23999** | **Codex batch 1** (GPT-5 family, o-series) |
| **24000–24999** | **Codex batch 2** (xAI Grok, Mistral) |
| **25000–25999** | **Codex batch 3** (DeepSeek, Meta Llama, Cohere) |
| **26000–29999** | **Codex free-use, pick your own sub-range** |

Always use `--port <base>` with `base` a multiple of 1000 and stay within a 30-wide window (one binary per port). If you need more than 30 binaries in one run, jump to the next 1000 (e.g. first 30 at 23000, next 30 at 23100, etc.).

### Do not modify `.env` while a benchmark is running

Agent-G's harness picks up config from `.env` via pydantic-settings + `os.environ.setdefault`, which means:

1. Any instance that imports `get_config()` will read whatever is in `.env` *at import time*
2. If you swap `.env` to a different provider while another instance is starting up, it gets the wrong config

**Recommendation**: pass all provider config via inline environment variables on the command line instead of writing to `.env`. Example for gpt-5.1-codex:

```bash
LLM_PROVIDER=external EXTERNAL_PROVIDER=openai \
EXTERNAL_BASE_URL=https://api.openai.com/v1 \
EXTERNAL_MODEL=gpt-5.1-codex \
EXTERNAL_API_KEY=sk-... \
python -u scripts/test_juliet.py --port 23000 --out-tag gpt5codex_old20 ...
```

**Caveat**: this only works reliably if the harness doesn't re-read `.env` after the inline vars are set. On some providers the external client re-loads config from disk — in that case, you must use a provider-specific `.env` file per run. We're working on adding `--provider / --api-key / --model / --base-url` CLI flags so no run ever needs to touch disk config. Check whether `test_juliet.py` has these flags before starting; if not, run your benchmarks one at a time for now.

### Per-run progress file

As of 2026-04-07, the harness writes its crash-recovery progress file as:

```
logs/juliet_progress_<YYYYMMDD>_<out_tag>.json
```

(It previously used a single file per day, which two concurrent runs would clobber.) Always pass `--out-tag <unique_tag>` so your progress file has a distinct name.

### LLM provider rate limits

- **Ollama daemon**: set `OLLAMA_NUM_PARALLEL=1` if you're running two Ollama-backed benchmarks at once, or stagger them by a few minutes.
- **Ollama cloud**: reliably rate-limits at around ~6-10 requests/minute. Do NOT run two cloud-model benchmarks in parallel — they will both 429 within 5 binaries.
- **Google Gemini**: 250 req/day on the free tier per model, RPM limits on top. Space runs at least 30 minutes apart if you're using free-tier.
- **OpenAI**: per-org RPM/TPM limits; check your org's quota before launching multiple o-series runs.

### Sanity check before starting

Run `tasklist //FI "IMAGENAME eq python.exe"` (Windows) or `pgrep -af test_juliet` (Unix) to confirm no other harness is active before you start. If you see a running instance and you don't know which port range it's using, err on the side of waiting — collisions are silent and leave you with corrupted output files.

---

## 4. Critical anti-cheat rules — read these

These rules apply to BOTH integration paths. Violating any of them invalidates the run.

1. **Never call `/health` after the initial readiness poll.** It returns Ghidra's program name which decodes the original filename.

2. **Never assume the binary is vulnerable from the CWE category.** Both `_bad` and `_good` variants exist for every CWE. The `_good` variants contain a defensive check that fixes the flaw. You are looking at one specific binary, and you must determine which it is from the actual decompiled code.

3. **Never extract or guess the original filename.** The binary name your model receives is `sample_NNNNN.bin` (hash-derived). If your runtime exposes the underlying file path through any other tool, scrub it.

4. **Never modify** `JulietAnonymizer.java`, `LeakFilter`, or the harness prompts in `bridge_lite.py`. Any anonymization regression will be caught by `scripts/verify_corpus_leaks.py` (run it before reporting results).

5. **Verdict format**: Each binary must produce one of `VULNERABLE`, `NOT_VULNERABLE`, `UNKNOWN`, or `BLANK_RESPONSE`. The harness's `classify_verdict()` parser already handles `## Verdict` headings and inline `Verdict: X` patterns — match one of those formats in your model's output and you're fine.

---

## 5. What models we'd love you to run

If your runtime has access to any of these, please run them on the full 50 binaries:

| Family | Models of interest |
|---|---|
| OpenAI | gpt-5.1-codex (high priority), gpt-5, o4-mini, o4, gpt-4.1, o3 |
| xAI | grok-4, grok-4-fast, grok-3 |
| Mistral | mistral-large-latest, codestral-25.01 |
| DeepSeek | deepseek-v3.1, deepseek-r1 (thinking — expect num_predict bumps) |
| Anthropic | claude-sonnet-4.5, claude-opus-4.5, claude-haiku-4 (we have Sonnet via blind harness, would love a normal Agent-G run for apples-to-apples) |
| Cohere | command-r-plus-08-2024 |
| Meta | llama-4-maverick, llama-4-scout (via Together / Fireworks / Groq) |

For each model, the **two output files we need**:

```
logs/juliet_test_<timestamp>_<model_tag>_old20.json
logs/juliet_test_<timestamp>_<model_tag>_new30.json
```

Plus a one-line description of the model + provider for the report's `RUN_METADATA` table:

```python
"juliet_test_20260408_gpt5codex_old20.json": (
    "GPT-5.1 Codex",
    "cloud · flagship · OpenAI",
    "openai",
),
```

---

## 6. Output JSON schema

Each test run JSON must have this shape (from `scripts/test_juliet.py:write_reports`):

```json
{
  "timestamp": "20260408_140530",
  "sample_size": 30,
  "metrics": {
    "total_binaries": 30,
    "true_positives": 14, "true_negatives": 13,
    "false_positives": 1, "false_negatives": 1,
    "unknown_verdicts": 1, "blank_responses": 0,
    "errors": 0,
    "precision": 0.933, "recall": 0.933, "f1": 0.933, "accuracy": 0.9,
    "per_cwe": { /* see compute_metrics() */ }
  },
  "records": [
    {
      "id": "juliet_CWE78_OS_Command_Injection_..._bad_elf-x86_64",
      "cwe": "CWE-78",
      "variant": "bad",
      "ground_truth": "VULNERABLE",
      "binary_path": "<path or sentinel>",
      "verdict": "VULNERABLE",
      "duration_s": 47.3,
      "iterations": 5,
      "tool_calls": 12,
      "tokens_in": 8421,
      "tokens_out": 1037,
      "report_text": "<full free-text analysis from your model>",
      "anonymizer_stats": { "export_count": 64, "remaining_leaks": [] },
      "error": null
    },
    ...
  ]
}
```

If you run via Path A (Agent-G harness), this schema is produced automatically. If you run via Path B (blind), populate the fields manually — `tokens_in/out` and `duration_s` can be 0 if you don't track them, but `verdict`, `id`, `cwe`, `ground_truth`, `tool_calls` must all be present.

---

## 7. Returning results to us

When you're done, push the test JSON files to:

```
C:/Users/Era/Desktop/OGhidra/Agent-G/logs/
```

Then update `scripts/build_html_report.py`'s `RUN_METADATA` dict (line ~54) with one entry per model, and re-run:

```bash
cd C:/Users/Era/Desktop/OGhidra/Agent-G
python scripts/build_html_report.py
```

The output is `logs/juliet_comparison_report.html` — a tan-themed multi-section HTML report with TOC, executive summary, aggregate table, Effective F1 vs Raw F1 horizontal bar chart, per-CWE heatmap, and per-model detail cards. Your new models will sort into the leaderboard automatically.

If you'd like us to do the metadata + rebuild step, just drop the JSONs in `logs/` and let us know which model labels to use.

---

## 8. Sanity-check before reporting your results

1. **Run the leak verifier** on any binary in your run to confirm anonymization is intact:
   ```bash
   python scripts/verify_corpus_leaks.py --ids logs/new_corpus_30_ids.txt --port 21500 --audit 5
   ```
   Expected: `clean: 30 / with leaks: 0`. If any binary leaks, your LeakFilter or anonymizer is broken — do NOT report results until fixed.

2. **Spot-check one VULNERABLE and one NOT_VULNERABLE record** in your output: read the `report_text` field and confirm the model cited specific addresses + decompiled evidence rather than category-keyword guessing. Models that just say "this is CWE-NN therefore VULNERABLE" are cheating off the input prompt and need their prompt scrubbed.

3. **Confirm your raw F1 vs effective F1 gap** — if a model has `unknown_verdicts > 0` or `blank_responses > 0`, the report will compute both. A large gap indicates the model frequently fails to commit to a verdict, which is informative on its own.

---

## 9. Reference: existing run summary

For calibration, here are the current scores (effective F1 — UNKNOWN/BLANK counted as wrong):

| Model | Old 20 | New 30 | Notes |
|---|---|---|---|
| Claude (blind sub-agents) | 1.000 (20/20) | **1.000 (30/30)** | Perfect on both corpora |
| Gemini 3.1 Pro Preview | partial (1/15 classified) | n/a | Daily quota exhausted |
| Gemini 3.1 Flash Lite | 0.636 | _running_ | |
| qwen3.5:397b-cloud | 0.500 (3 TP / 2 FN / 4 FP / 11 UNK) | _running_ | Thinking model, num_predict bumped to 16384 |
| gemma4:31b-cloud | 0.737 | _pending_ | |
| gemma4:e4b (local) | 0.571 | _pending_ | Frequently empty output, not viable |

The big takeaway so far: **Claude is the only model that solves Juliet at near-perfect accuracy under the cheat-resistant setup**. All other models drop into the 0.50–0.75 range. We're hoping your runs add more flagship contenders to the top tier, or at least clarify whether the gap is Anthropic-specific or top-tier-LLM-general.

---

## 10. Questions?

Look at:
- `Agent-G/scripts/test_juliet.py` for the harness logic
- `Agent-G/scripts/build_html_report.py` for how runs flow into the report
- `Agent-G/scripts/verify_corpus_leaks.py` for the anonymization audit
- `Agent-G/src/runtime/leak_filter.py` for the regex patterns
- `Agent-G/src/runtime/thinking_models.py` for the thinking-model registry
- `Agent-G/ghidra/scripts/JulietAnonymizer.java` for the symbol-rename pass
- `Agent-G/logs/juliet_claude_blind_comparison.md` for the original Claude blind methodology

If a tool or endpoint behaves unexpectedly, dump `/list_imports`, `/list_exports`, `/list_strings` for any binary and check whether the LeakFilter regex matches what you see — extending the regex is the usual fix.

Good hunting, and please run as many models in parallel as your rate limits allow. The benchmark needs ~50 × N model calls per run, with each binary taking 30 s – 5 min depending on model latency, so a full lineup of 8 models is roughly a half-day of compute.

— Agent-G team, 2026-04-07
