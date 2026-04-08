#!/usr/bin/env python3
"""Build HTML comparison report from Juliet test JSON logs.

Usage:
    python scripts/build_html_report.py [--output report.html]

Reads all `juliet_test_*.json` files in logs/, plus a manually-provided
Claude results dataset, and produces a single self-contained HTML report
with per-model + per-CWE breakdowns.
"""

import argparse
import glob
import json
import os
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# Hardcoded Claude blind-sub-agent results (from conversation history — the only source)
# Format: (CWE, variant, verdict, http_calls, duration_s)
CLAUDE_RECORDS = [
    ("CWE-121", "bad", "VULNERABLE", 4, 19.0),
    ("CWE-121", "bad", "VULNERABLE", 4, 17.7),
    ("CWE-121", "good", "NOT_VULNERABLE", 4, 17.1),
    ("CWE-121", "good", "NOT_VULNERABLE", 3, 14.4),
    ("CWE-122", "bad", "VULNERABLE", 4, 19.2),
    ("CWE-122", "bad", "VULNERABLE", 4, 16.9),
    ("CWE-122", "good", "NOT_VULNERABLE", 4, 16.4),
    ("CWE-122", "good", "NOT_VULNERABLE", 3, 16.4),
    ("CWE-415", "bad", "VULNERABLE", 4, 12.6),
    ("CWE-415", "bad", "VULNERABLE", 3, 11.6),
    ("CWE-415", "good", "NOT_VULNERABLE", 4, 20.7),
    ("CWE-415", "good", "NOT_VULNERABLE", 3, 15.5),
    ("CWE-416", "bad", "VULNERABLE", 3, 13.3),
    ("CWE-416", "bad", "VULNERABLE", 3, 16.0),
    ("CWE-416", "good", "NOT_VULNERABLE", 4, 18.6),
    ("CWE-416", "good", "NOT_VULNERABLE", 3, 15.5),
    ("CWE-476", "bad", "NOT_VULNERABLE", 8, 48.1),  # FN — the only Claude miss
    ("CWE-476", "bad", "VULNERABLE", 3, 15.6),
    ("CWE-476", "good", "NOT_VULNERABLE", 4, 20.4),
    ("CWE-476", "good", "NOT_VULNERABLE", 5, 19.6),
]

# Explicit mapping from report file timestamp → model label
# (since the JSON files don't embed the model name)
#
# Exclusions:
#   - juliet_test_20260406_181746.json → broken first Gemini Pro attempt (no thinkingConfig)
#   - juliet_test_20260406_183843.json → Gemini 3.1 Pro v2 (superseded by v5 with all patches)
#   - juliet_test_20260406_gemini3_flash_final.json → Gemini 3 Flash Preview (deduplicated out
#     of the comparison table to keep the Gemini family focused on a single representative)
_OLD = "old20"; _NEW = "new30"
# (label, deployment, family, corpus_segment)
#
# This report is the LEAK-FREE benchmark. All registered runs were produced
# on 2026-04-07 after the three-leak-fix landed:
#   1. LeakFilter masks Juliet scaffold strings in decompile output ("[FILTERED]")
#   2. JulietAnonymizer strips DWARF parameter names to param_N
#   3. OGhidraHeadlessServer /health + /program redact the program name
# plus the in-conversation runtime fix that requires verdict presence before
# exiting on an "INVESTIGATION COMPLETE" marker.
#
# Older contaminated runs (2026-04-06 + the first-pass 2026-04-07 attempts)
# remain on disk for audit but are NOT registered here so they don't pollute
# the leak-free comparison.
RUN_METADATA = {
    # ── Clean leak-free new30 runs (2026-04-07 afternoon) ──
    "juliet_test_20260407_opus46_blind_clean_new30.json": (
        "Claude Opus 4.6 (blind sub-agents)", "blind harness · Anthropic · sub-agent", "anthropic", _NEW),
    "juliet_test_20260407_161332_claude_sonnet45_clean_new30.json": (
        "Claude Sonnet 4.5", "cloud · flagship · Anthropic", "anthropic", _NEW),
    "juliet_test_20260407_152628_flashlite_clean_new30.json": (
        "Gemini 3.1 Flash Lite Preview", "cloud · cheap tier · Google", "google", _NEW),
    "juliet_test_20260407_152842_e4b_clean_new30.json": (
        "gemma4:e4b (local)", "local · small open weight · capacity-fixed", "ollama", _NEW),
    "juliet_test_20260407_161132_gpt54mini_oauth_clean_new30.json": (
        "GPT-5.4 Mini (Codex OAuth)", "cloud · OpenAI · ChatGPT backend", "openai", _NEW),
    "juliet_test_20260407_172654_gpt54_oauth_clean_new30.json": (
        "GPT-5.4 (Codex OAuth)", "cloud · OpenAI · ChatGPT backend", "openai", _NEW),

    # ── Intentionally de-registered (on disk for audit only) ──
    #   - juliet_test_20260407_152150_gpt5_oauth_clean_new30.json
    #     → GPT-5 v1 (no throttle), ChatGPT-backend rate-limited at 6/30
    #   - juliet_test_20260407_161557_gpt5_oauth_clean_new30_throttled.json
    #     → GPT-5 v2 throttled, hit the INVESTIGATION COMPLETE early-exit bug
    #       (11 UNK); replaced by the patched GPT-5.4 run above
    #   - juliet_test_20260407_gemma4_31b_clean_new30_SKIPPED.json
    #     → Gemma 4 31B partial (15/30), killed by user due to ~5.5 min/binary
    #       dense-thinking-model tail
    #   - all 2026-04-06 runs → contaminated corpus (pre-leak-fix)
}


def _normalize_run_metadata(data, fname):
    """Return report metadata from embedded JSON, falling back to legacy mapping."""
    meta = dict(data.get("run_metadata") or {})
    legacy = RUN_METADATA.get(fname)
    if legacy:
        label, deployment, family, *rest = legacy
        meta.setdefault("model_name", label)
        meta.setdefault("deployment", deployment)
        meta.setdefault("provider", family)
        meta.setdefault("model_id", label)
        if rest:
            meta.setdefault("corpus_label", rest[0])
    meta.setdefault("model_name", fname.replace(".json", ""))
    meta.setdefault("deployment", "")
    meta.setdefault("provider", "unknown")
    meta.setdefault("model_id", meta.get("model_name", ""))
    meta.setdefault("corpus_label", "")
    meta.setdefault("notes", "")
    # STRICT ALLOWLIST: only files that are explicitly registered in the
    # RUN_METADATA dict above are included in the report. Files with
    # embedded run_metadata but no allowlist entry are smoke tests,
    # historical contaminated runs, or superseded runs that should remain
    # on disk for audit but NOT pollute the leaderboard.
    #
    # We HARD-OVERRIDE include_in_report here (not setdefault) because some
    # embedded run_metadata blocks include `"include_in_report": true` from
    # their own harness invocation, which would otherwise defeat the
    # allowlist. The RUN_METADATA dict is the single source of truth.
    meta["include_in_report"] = bool(legacy)
    return meta


def compute_metrics(records, label=""):
    """Compute aggregate and per-CWE metrics from records."""
    tp = tn = fp = fn = unk = blank = 0
    by_cwe = defaultdict(lambda: {
        "tp": 0, "tn": 0, "fp": 0, "fn": 0,
        "unk": 0, "blank": 0,
        "n_bad": 0, "n_good": 0,
        "total_time": 0.0, "total_tools": 0,
    })
    total_time = 0.0
    total_tools = 0
    total_iters = 0

    # Also recognize blank-response sentinel that may be in report_text but
    # not yet reflected in the verdict field (for pre-patch runs).
    BLANK_MARKERS = (
        "Model returned a blank response",
        "thinking budget was exhausted",
        "thinking budget exhausted",
        "[MODEL_RETURNED_BLANK_RESPONSE]",
    )

    for r in records:
        cwe = r["cwe"]
        t = r["ground_truth"]
        v = r["verdict"]
        report = r.get("report_text", "") or ""
        # Retro-detect blank responses in pre-patch runs (the verdict was
        # stored as UNKNOWN but the text shows thinking budget exhausted).
        if v == "UNKNOWN" and any(m in report for m in BLANK_MARKERS):
            v = "BLANK_RESPONSE"

        c = by_cwe[cwe]
        c["n_bad" if t == "VULNERABLE" else "n_good"] += 1
        dur = r.get("duration_s", 0) or 0
        tc = r.get("tool_calls", 0) or 0
        it = r.get("iterations", 0) or 0
        c["total_time"] += dur
        c["total_tools"] += tc
        total_time += dur
        total_tools += tc
        total_iters += it

        if v == "BLANK_RESPONSE":
            blank += 1; c["blank"] += 1
        elif v == "UNKNOWN":
            unk += 1; c["unk"] += 1
        elif t == "VULNERABLE" and v == "VULNERABLE":
            tp += 1; c["tp"] += 1
        elif t == "NOT_VULNERABLE" and v == "NOT_VULNERABLE":
            tn += 1; c["tn"] += 1
        elif t == "NOT_VULNERABLE" and v == "VULNERABLE":
            fp += 1; c["fp"] += 1
        elif t == "VULNERABLE" and v == "NOT_VULNERABLE":
            fn += 1; c["fn"] += 1

    # Standard F1 (UNK and BLANK excluded from precision/recall denominators)
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    accuracy = (tp + tn) / len(records) if records else 0.0

    # Effective F1 — treat UNKNOWNs and BLANK_RESPONSEs as wrong answers.
    # UNKNOWN on bad binary = missed vuln (FN)
    # UNKNOWN on good binary = uninformative (FP)
    # BLANK_RESPONSE is treated the same as UNKNOWN here since both are
    # failures to produce a usable verdict. The "blank" column in the
    # headline table reports blanks separately so users can see the
    # underlying cause.
    eff_tp = tp
    eff_tn = tn
    eff_fp = fp
    eff_fn = fn
    unk_bad = unk_good = 0
    blank_bad = blank_good = 0
    for r in records:
        v = r["verdict"]
        rep = r.get("report_text", "") or ""
        # retroactively catch blank responses in pre-patch runs
        if v == "UNKNOWN" and any(m in rep for m in BLANK_MARKERS):
            v = "BLANK_RESPONSE"
        t = r["ground_truth"]
        if v == "UNKNOWN":
            if t == "VULNERABLE":
                unk_bad += 1
            else:
                unk_good += 1
        elif v == "BLANK_RESPONSE":
            if t == "VULNERABLE":
                blank_bad += 1
            else:
                blank_good += 1
    eff_fn += unk_bad + blank_bad
    eff_fp += unk_good + blank_good
    eff_precision = eff_tp / (eff_tp + eff_fp) if (eff_tp + eff_fp) else 0.0
    eff_recall = eff_tp / (eff_tp + eff_fn) if (eff_tp + eff_fn) else 0.0
    eff_f1 = 2 * eff_precision * eff_recall / (eff_precision + eff_recall) if (eff_precision + eff_recall) else 0.0
    eff_accuracy = (eff_tp + eff_tn) / len(records) if records else 0.0

    return {
        "label": label,
        "n": len(records),
        "tp": tp, "tn": tn, "fp": fp, "fn": fn,
        "unk": unk, "blank": blank,
        "precision": precision, "recall": recall, "f1": f1, "accuracy": accuracy,
        "eff_precision": eff_precision, "eff_recall": eff_recall,
        "eff_f1": eff_f1, "eff_accuracy": eff_accuracy,
        "unk_bad": unk_bad, "unk_good": unk_good,
        "blank_bad": blank_bad, "blank_good": blank_good,
        "total_time_s": total_time,
        "avg_time_s": total_time / len(records) if records else 0,
        "avg_tools": total_tools / len(records) if records else 0,
        "avg_iters": total_iters / len(records) if records else 0,
        "by_cwe": {k: dict(v) for k, v in by_cwe.items()},
    }


def load_all_runs():
    """Load all model results into a unified structure.

    Multiple JSON files mapped to the same label are merged so each model has
    one combined record set spanning both the old 20-binary and new 30-binary
    corpora when both are available.
    """
    runs = {}

    # ── Aggregate by label across all source files ─────────────────────
    by_label = {}  # label -> {"records": [...], "tier": ..., "family": ..., "sources": [...], "segments": set()}

    # NOTE (2026-04-07): Hardcoded Claude old20 records were the contaminated
    # pre-leak-fix run and are intentionally NOT injected anymore. Claude's
    # entry in this report comes from the leak-free Opus 4.6 blind run at
    # logs/juliet_test_20260407_opus46_blind_clean_new30.json, which has its
    # own run_metadata embedded in the JSON and is discovered by the for-loop
    # below. The CLAUDE_RECORDS tuple remains at the top of this file for
    # historical audit but is no longer referenced by the loader.

    # 2. All registered JSON files. Resolved relative to the repo root so
    # the builder works regardless of where it's run from.
    logs_dir = Path(__file__).resolve().parent.parent / "logs"
    for json_path in sorted(logs_dir.glob("juliet_test_*.json")):
        fname = json_path.name
        with open(json_path, encoding="utf-8") as f:
            data = json.load(f)
        meta = _normalize_run_metadata(data, fname)
        if not meta.get("include_in_report", True):
            continue
        label = meta["model_name"]
        deployment = meta.get("deployment", "")
        family = meta.get("provider", "unknown")
        segment = meta.get("corpus_label") or (RUN_METADATA.get(fname, ("", "", "", ""))[3])
        recs = data.get("records", [])
        if label not in by_label:
            by_label[label] = {
                "records": [],
                "tier": deployment,
                "family": family,
                "sources": [],
                "segments": set(),
                "model_id": meta.get("model_id", label),
                "notes": meta.get("notes", ""),
            }
        by_label[label]["records"].extend(recs)
        by_label[label]["sources"].append(fname)
        if segment:
            by_label[label]["segments"].add(segment)
        if not by_label[label].get("notes") and meta.get("notes"):
            by_label[label]["notes"] = meta["notes"]
        if by_label[label].get("model_id") == label and meta.get("model_id"):
            by_label[label]["model_id"] = meta["model_id"]

    # 3. Build the runs dict with merged metrics
    for label, info in by_label.items():
        runs[label] = {
            "metrics": compute_metrics(info["records"], label),
            "records": info["records"],
            "family": info["family"],
            "tier": info["tier"],
            "model_id": info.get("model_id", label),
            "notes": info.get("notes", ""),
            "source_files": info["sources"],
            "segments": sorted(info["segments"]),
        }

    # 3. Add notes to specific runs after they're loaded
    if "Gemini 3.1 Pro Preview" in runs:
        runs["Gemini 3.1 Pro Preview"]["model_id"] = "gemini-3.1-pro-preview (thinkingConfig=-1, functionCallingConfig=NONE, empty-response retry)"
        runs["Gemini 3.1 Pro Preview"]["notes"] = runs["Gemini 3.1 Pro Preview"].get("notes") or (
            "Run with the full ExternalClient patch set: thinking-model max_tokens bump, "
            "toolConfig.functionCallingConfig.mode=NONE to prevent MALFORMED_FUNCTION_CALL, "
            "and automatic retry on empty visible output. The test was interrupted at 15 of "
            "20 binaries when the daily public-API quota of 250 requests per model was "
            "exhausted. Of five real investigations completed before the quota limit, one "
            "produced a full correct VULNERABLE verdict, demonstrating the patch set is "
            "functionally correct. A full 20-binary re-run requires waiting for the quota "
            "reset window or using a paid Gemini API tier."
        )
    if "Gemini 3.1 Flash Lite Preview" in runs:
        runs["Gemini 3.1 Flash Lite Preview"]["model_id"] = "gemini-3.1-flash-lite-preview"
        runs["Gemini 3.1 Flash Lite Preview"]["notes"] = runs["Gemini 3.1 Flash Lite Preview"].get("notes") or (
            "Google's cheapest Gemini 3 tier. Optimised for speed/cost over accuracy. NOT representative "
            "of Gemini 3.1 Pro or non-Lite Flash. The new-30 corpus run was rate-limited after binary 5 "
            "(the remaining 25 records are UNKNOWN due to the public-API daily quota), so the new-30 "
            "scores undercount the model's true capability. The original 20-binary corpus run completed "
            "in full and is the more representative number."
        )
    if "gemma4:31b-cloud" in runs:
        runs["gemma4:31b-cloud"]["model_id"] = "gemma4:31b-cloud (Ollama cloud)"
        runs["gemma4:31b-cloud"]["notes"] = runs["gemma4:31b-cloud"].get("notes") or "Mid-tier open-weight model served via Ollama's cloud backend. Best self-hostable performer."
    if "qwen3.5:397b-cloud" in runs:
        runs["qwen3.5:397b-cloud"]["model_id"] = "qwen3.5:397b-cloud (Ollama, thinking model, num_predict=16384)"
        runs["qwen3.5:397b-cloud"]["notes"] = runs["qwen3.5:397b-cloud"].get("notes") or (
            "Large open-weight thinking model served via Ollama cloud. Required the new "
            "thinking-model registry patch in OllamaClient to bump num_predict from 2000 "
            "to 16384, otherwise the first response was empty (done_reason=length). The "
            "old-20 run completed in full (assembled from a 13-binary overnight segment "
            "plus a 7-binary resume); the new-30 run was rate-limited at binary 3 by "
            "Ollama cloud, so 27 of the new-30 records are UNKNOWN."
        )
    if "Claude (blind sub-agents)" in runs:
        runs["Claude (blind sub-agents)"]["model_id"] = "claude-sonnet-class (blind harness, two corpora)"
        runs["Claude (blind sub-agents)"]["notes"] = runs["Claude (blind sub-agents)"].get("notes") or (
            "Two manual blind sub-agent runs: the original 20-binary corpus (run 2026-04-06) "
            "and the new 30-binary corpus (run 2026-04-07 via 6 parallel sub-agents, 5 binaries each). "
            "Each sub-agent received only the CWE category as a hint, never the bad/good label, "
            "and used raw curl against the anonymized Ghidra HTTP server. Achieved 49 / 50 correct "
            "across both corpora — the only miss is the CWE-476 char_bad in the original 20."
        )
    if "gemma4:e4b (local)" in runs:
        runs["gemma4:e4b (local)"]["model_id"] = "gemma4:e4b (Ollama local, 16GB VRAM)"
        runs["gemma4:e4b (local)"]["notes"] = runs["gemma4:e4b (local)"].get("notes") or "Despite the 'e4b' name, uses 16GB VRAM. Frequently returns empty output and gives up after 1 iteration. Not viable for this task."
    # (Gemini 3 Flash Preview run was removed from the comparison table by request.)

    return runs


# ── HTML rendering ─────────────────────────────────────────────────────

HTML_HEAD = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Agent-G Juliet Benchmark — Multi-Model Comparison</title>
<style>
  :root {
    /* Warm tan/parchment theme — easy on the eyes */
    --bg:        #f8f1e3;   /* parchment */
    --bg-alt:    #efe4cd;   /* light tan */
    --bg-code:   #ece0c4;
    --text:      #3a2e1f;   /* deep cocoa */
    --text-sub:  #5b4830;
    --text-mute: #8a7253;
    --border:    #d4c19a;
    --border-lt: #e3d4ae;
    --accent:    #7a4f24;   /* warm sienna */
    --accent-lt: #a06a35;
    --accent-bg: #f3e6c8;

    /* Status colors — desaturated to match the tan palette */
    --status-pass:  #4f7a2f;   /* sage green */
    --status-warn:  #b07a18;   /* honey */
    --status-fail:  #a23a2c;   /* terracotta */
    --status-mute:  #9c8866;
    --status-info:  #4a6c8a;   /* dusty blue */

    /* Typography */
    --font-body: -apple-system, BlinkMacSystemFont, "Segoe UI", "Helvetica Neue", Arial, sans-serif;
    --font-head: "Charter", "Georgia", "Times New Roman", Times, serif;
    --font-mono: "SF Mono", "Monaco", "Menlo", "Consolas", "Liberation Mono", monospace;
  }

  * { box-sizing: border-box; }

  html { scroll-behavior: smooth; }

  body {
    margin: 0;
    font-family: var(--font-body);
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    font-size: 15px;
    -webkit-font-smoothing: antialiased;
  }

  .container {
    max-width: 1120px;
    margin: 0 auto;
    padding: 48px 40px 80px;
  }

  /* ── Typography ─────────────────────────────────────────────── */
  h1, h2, h3, h4 {
    font-family: var(--font-head);
    color: var(--text);
    font-weight: 600;
    line-height: 1.25;
  }
  h1 {
    font-size: 32px;
    margin: 0 0 4px;
    letter-spacing: -0.015em;
  }
  h2 {
    font-size: 22px;
    margin: 48px 0 16px;
    padding-bottom: 8px;
    border-bottom: 2px solid var(--accent);
  }
  h3 {
    font-size: 17px;
    margin: 24px 0 10px;
    color: var(--accent);
  }
  h4 {
    font-size: 14px;
    margin: 16px 0 8px;
    color: var(--text-sub);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 700;
  }
  p { margin: 0 0 12px; }
  a { color: var(--accent-lt); text-decoration: none; border-bottom: 1px solid transparent; }
  a:hover { border-bottom-color: var(--accent-lt); }
  code {
    font-family: var(--font-mono);
    font-size: 0.88em;
    background: var(--bg-code);
    padding: 1px 5px;
    border-radius: 3px;
    border: 1px solid var(--border-lt);
  }

  /* ── Document header ───────────────────────────────────────── */
  .doc-header {
    padding-bottom: 24px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 8px;
  }
  .doc-subtitle {
    font-size: 15px;
    color: var(--text-sub);
    margin: 6px 0 0;
    font-style: italic;
  }
  .doc-meta {
    margin-top: 20px;
    font-size: 13px;
    color: var(--text-mute);
    display: flex;
    gap: 24px;
    flex-wrap: wrap;
  }
  .doc-meta span strong { color: var(--text-sub); font-weight: 600; }

  /* ── Table of Contents ─────────────────────────────────────── */
  .toc {
    background: var(--bg-alt);
    border: 1px solid var(--border-lt);
    border-left: 3px solid var(--accent);
    padding: 16px 24px;
    margin: 32px 0;
    font-size: 14px;
  }
  .toc-title {
    font-family: var(--font-head);
    font-weight: 700;
    font-size: 13px;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    color: var(--accent);
    margin-bottom: 10px;
  }
  .toc ol { margin: 0; padding-left: 20px; }
  .toc ol ol { margin-top: 4px; }
  .toc li { margin: 4px 0; }
  .toc a { color: var(--text); }
  .toc a:hover { color: var(--accent); }

  /* ── Executive summary ─────────────────────────────────────── */
  .exec-summary {
    background: var(--accent-bg);
    border: 1px solid #d7be84;
    border-radius: 4px;
    padding: 20px 24px;
    margin: 24px 0 32px;
  }
  .exec-summary h3 {
    margin-top: 0;
    color: var(--accent);
    font-size: 15px;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-family: var(--font-body);
  }
  .exec-summary ul { margin: 8px 0 0; padding-left: 22px; }
  .exec-summary li { margin: 6px 0; }

  /* ── Section numbering ─────────────────────────────────────── */
  .section-num {
    color: var(--accent);
    font-variant-numeric: tabular-nums;
    margin-right: 10px;
    font-weight: 700;
  }

  /* ── Tables ────────────────────────────────────────────────── */
  .tbl-wrapper {
    margin: 16px 0 8px;
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 4px;
  }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    font-variant-numeric: tabular-nums;
  }
  th, td {
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid var(--border-lt);
    vertical-align: middle;
  }
  thead th {
    background: var(--bg-alt);
    color: var(--text-sub);
    font-weight: 700;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    border-bottom: 2px solid var(--border);
    white-space: nowrap;
  }
  tbody tr:nth-child(even) { background: var(--bg-alt); }
  tbody tr:hover { background: #e8d8b3; }
  tbody tr:last-child td { border-bottom: none; }
  td.num, th.num { text-align: right; }
  td.center, th.center { text-align: center; }

  .tbl-caption {
    font-size: 12px;
    color: var(--text-mute);
    margin: 6px 2px 20px;
    font-style: italic;
  }
  .tbl-caption strong {
    font-weight: 700;
    color: var(--text-sub);
    font-style: normal;
    margin-right: 4px;
  }

  /* ── Status indicators ─────────────────────────────────────── */
  .pass  { color: var(--status-pass); font-weight: 600; }
  .warn  { color: var(--status-warn); font-weight: 600; }
  .fail  { color: var(--status-fail); font-weight: 600; }
  .mute  { color: var(--status-mute); }
  .good  { color: var(--status-pass); font-weight: 600; }
  .bad   { color: var(--status-fail); font-weight: 600; }

  .pill {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 10px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.02em;
    border: 1px solid;
  }
  .pill-good { color: var(--status-pass); border-color: var(--status-pass); background: rgba(26, 127, 55, 0.08); }
  .pill-bad  { color: var(--status-fail); border-color: var(--status-fail); background: rgba(182, 35, 36, 0.08); }
  .pill-warn { color: var(--status-warn); border-color: var(--status-warn); background: rgba(154, 103, 0, 0.08); }
  .pill-info { color: var(--status-info); border-color: var(--status-info); background: rgba(9, 105, 218, 0.08); }
  .pill-mute { color: var(--text-mute); border-color: var(--border); background: var(--bg-alt); }

  .rank {
    display: inline-block;
    width: 22px; height: 22px;
    line-height: 22px;
    text-align: center;
    border-radius: 50%;
    background: var(--bg-alt);
    border: 1px solid var(--border);
    color: var(--text-sub);
    font-weight: 700;
    font-size: 11px;
    font-variant-numeric: tabular-nums;
    margin-right: 6px;
  }
  tbody tr:first-child .rank {
    background: var(--accent);
    color: white;
    border-color: var(--accent);
  }

  /* ── F1 score bars ─────────────────────────────────────────── */
  .score-bar {
    display: inline-flex;
    align-items: center;
    gap: 10px;
    min-width: 180px;
  }
  .bar-track {
    flex: 1;
    height: 6px;
    background: var(--bg-alt);
    border: 1px solid var(--border-lt);
    border-radius: 3px;
    overflow: hidden;
    min-width: 100px;
  }
  .bar-fill {
    height: 100%;
    background: var(--accent);
    border-radius: 2px;
  }
  .bar-fill.low { background: var(--status-fail); }
  .bar-fill.med { background: var(--status-warn); }
  .bar-fill.high { background: var(--status-pass); }
  .score-num { font-weight: 700; font-size: 13px; min-width: 42px; text-align: right; }

  /* ── Model detail card ─────────────────────────────────────── */
  .model-detail {
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 20px 24px;
    margin: 20px 0 28px;
    background: var(--bg);
  }
  .model-detail-head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    margin-bottom: 12px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--border-lt);
  }
  .model-detail-title {
    font-family: var(--font-head);
    font-weight: 600;
    font-size: 18px;
    color: var(--text);
    margin: 0;
  }
  .model-detail-id {
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--text-mute);
    margin-top: 4px;
    word-break: break-all;
  }
  .model-score-display {
    text-align: right;
    flex-shrink: 0;
    margin-left: 24px;
  }
  .model-score-display .label {
    font-size: 10px;
    color: var(--text-mute);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-weight: 600;
  }
  .model-score-display .value {
    font-family: var(--font-head);
    font-size: 26px;
    font-weight: 700;
    color: var(--accent);
  }
  .model-notes {
    background: var(--bg-alt);
    border-left: 3px solid var(--accent-lt);
    padding: 12px 16px;
    margin: 12px 0 16px;
    font-size: 13px;
    color: var(--text-sub);
    font-style: italic;
    border-radius: 0 3px 3px 0;
  }

  /* ── Statistics grid ───────────────────────────────────────── */
  .stat-grid {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 12px;
    margin: 16px 0;
  }
  .stat {
    background: var(--bg-alt);
    border: 1px solid var(--border-lt);
    border-radius: 3px;
    padding: 10px 12px;
  }
  .stat-label {
    font-size: 10px;
    color: var(--text-mute);
    text-transform: uppercase;
    letter-spacing: 0.06em;
    font-weight: 600;
  }
  .stat-value {
    font-family: var(--font-head);
    font-size: 20px;
    font-weight: 600;
    color: var(--text);
    margin-top: 2px;
  }

  /* ── Per-binary verdict matrix ─────────────────────────────── */
  .matrix-container {
    display: flex;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
    margin: 6px 0 4px;
  }
  .matrix {
    display: inline-flex;
    gap: 3px;
    padding: 3px 4px;
    border: 1px solid var(--border-lt);
    background: var(--bg-alt);
    border-radius: 3px;
  }
  .matrix-cell {
    width: 16px; height: 16px;
    border-radius: 2px;
    display: inline-block;
    cursor: help;
  }
  .m-tp    { background: var(--status-pass); }
  .m-tn    { background: var(--accent-lt); }
  .m-fp    { background: var(--status-warn); }
  .m-fn    { background: var(--status-fail); }
  .m-unk   { background: var(--status-mute); opacity: 0.6; }
  .m-blank {
    background-image: repeating-linear-gradient(
      45deg,
      var(--status-fail) 0, var(--status-fail) 3px,
      #e8c5c5 3px, #e8c5c5 6px
    );
  }

  .legend {
    display: flex;
    gap: 14px;
    font-size: 11px;
    color: var(--text-mute);
    flex-wrap: wrap;
  }
  .legend-item {
    display: flex;
    align-items: center;
    gap: 5px;
  }
  .legend-item .matrix-cell { width: 11px; height: 11px; }

  /* ── Heatmap ───────────────────────────────────────────────── */
  .heatmap td { text-align: center; font-weight: 500; }
  .heatmap td:first-child { text-align: left; font-weight: 600; }
  .hc-perfect { background: #cfe1bd; color: #2f4d18; font-weight: 700; }
  .hc-high    { background: #e1ecd0; color: #4f7a2f; }
  .hc-mid     { background: #f2e2b2; color: #8c6210; }
  .hc-low     { background: #efcfb6; color: #a23a2c; }
  .hc-fail    { background: #e6b39b; color: #722013; font-weight: 700; }
  .hc-unk     { background: var(--bg-alt); color: var(--text-mute); }

  /* ── Comparison chart ──────────────────────────────────────── */
  .chart-wrap {
    border: 1px solid var(--border);
    border-radius: 4px;
    background: var(--bg);
    padding: 20px 24px 12px;
    margin: 16px 0 8px;
  }
  .chart-title {
    font-family: var(--font-head);
    font-size: 14px;
    font-weight: 700;
    color: var(--text-sub);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin: 0 0 14px;
  }
  .chart-row {
    display: grid;
    grid-template-columns: 220px 1fr 60px;
    align-items: center;
    gap: 12px;
    margin: 6px 0;
    font-size: 13px;
  }
  .chart-label { color: var(--text-sub); font-weight: 600; text-align: right; }
  .chart-bar-track {
    background: var(--bg-alt);
    border: 1px solid var(--border-lt);
    border-radius: 3px;
    height: 18px;
    position: relative;
    overflow: hidden;
  }
  .chart-bar-fill {
    height: 100%;
    background: linear-gradient(90deg, var(--accent), var(--accent-lt));
    border-radius: 2px 0 0 2px;
  }
  .chart-bar-fill.raw-overlay {
    position: absolute;
    top: 0; left: 0;
    background: repeating-linear-gradient(
      135deg, rgba(255,255,255,0.4) 0 4px,
      rgba(255,255,255,0) 4px 8px
    );
    border-right: 1px dashed rgba(255,255,255,0.7);
  }
  .chart-value { font-weight: 700; color: var(--accent); font-variant-numeric: tabular-nums; }
  .chart-legend {
    margin-top: 12px;
    font-size: 11px;
    color: var(--text-mute);
    display: flex;
    gap: 18px;
    flex-wrap: wrap;
  }
  .chart-legend .swatch {
    display: inline-block;
    width: 14px; height: 10px;
    vertical-align: middle;
    margin-right: 4px;
    border: 1px solid var(--border);
    border-radius: 2px;
  }
  .chart-legend .swatch.eff { background: linear-gradient(90deg, var(--accent), var(--accent-lt)); }
  .chart-legend .swatch.raw {
    background: var(--accent);
    background-image: repeating-linear-gradient(
      135deg, rgba(255,255,255,0.4) 0 4px,
      rgba(255,255,255,0) 4px 8px
    );
  }

  /* ── Footnotes & references ────────────────────────────────── */
  .footnote-ref {
    font-size: 0.7em;
    vertical-align: super;
    color: var(--accent-lt);
    text-decoration: none;
    font-weight: 700;
  }
  .footnotes {
    font-size: 12px;
    color: var(--text-sub);
    border-top: 1px solid var(--border-lt);
    padding-top: 16px;
    margin-top: 40px;
  }
  .footnotes ol { padding-left: 22px; }
  .footnotes li { margin: 4px 0; }

  .footer {
    margin-top: 64px;
    padding-top: 20px;
    border-top: 1px solid var(--border);
    font-size: 12px;
    color: var(--text-mute);
    text-align: center;
  }

  /* ── Print styles ──────────────────────────────────────────── */
  @media print {
    body { font-size: 11pt; color: black; background: white; }
    .container { max-width: none; padding: 0; }
    h1 { font-size: 20pt; }
    h2 { font-size: 14pt; page-break-after: avoid; }
    h3 { font-size: 12pt; page-break-after: avoid; }
    .model-detail, .tbl-wrapper, .exec-summary { page-break-inside: avoid; }
    a { color: black; border-bottom: none; }
    .toc, .legend { break-inside: avoid; }
  }
</style>
</head>
<body>
<div class="container">
"""

HTML_FOOT = """
<div class="footer">
  <strong>Agent-G Juliet Benchmark Report</strong> &middot;
  Generated automatically by <code>scripts/build_html_report.py</code><br>
  Source data: <code>logs/juliet_test_*.json</code> &middot;
  Anonymization pipeline: <code>JulietAnonymizer.java</code> + <code>LeakFilter</code> + binary-name hashing
</div>
</div>
</body>
</html>
"""


def fmt_score_bar(f1):
    """Render a small inline F1 score bar (light theme, professional)."""
    pct = max(0, min(100, int(f1 * 100)))
    if f1 >= 0.8:
        cls = "high"
    elif f1 >= 0.5:
        cls = "med"
    else:
        cls = "low"
    return (
        f'<span class="score-bar">'
        f'  <span class="bar-track"><span class="bar-fill {cls}" style="width:{pct}%;"></span></span>'
        f'  <span class="score-num">{f1:.3f}</span>'
        f'</span>'
    )


def fmt_pill(text, kind):
    return f'<span class="pill pill-{kind}">{text}</span>'


def compute_completeness(run):
    """Count viable (classified) vs rate-limited vs model-failure UNK records.

    Returns dict with: n_total, n_classified, n_unk_rate_limit, n_unk_model,
    n_blank, coverage_pct, status ("complete"|"partial"|"blocked").
    """
    RATE_MARKERS = ("429", "Too Many Requests", "quota", "rate limit", "rate-limit")
    recs = run.get("records", []) or []
    n_total = len(recs)
    n_classified = 0
    n_unk_rate = 0
    n_unk_model = 0
    n_blank = 0
    for r in recs:
        v = (r.get("verdict") or "").upper()
        rt = r.get("report_text", "") or ""
        if v == "BLANK_RESPONSE":
            n_blank += 1
            continue
        if v == "UNKNOWN":
            if any(m in rt for m in RATE_MARKERS):
                n_unk_rate += 1
            else:
                n_unk_model += 1
            continue
        if v in ("VULNERABLE", "NOT_VULNERABLE"):
            n_classified += 1
    coverage = (n_classified / n_total) if n_total else 0.0
    if n_total == 0:
        status = "missing"
    elif coverage >= 0.95:
        status = "complete"
    elif coverage >= 0.50:
        status = "partial"
    else:
        status = "blocked"
    return {
        "n_total": n_total,
        "n_classified": n_classified,
        "n_unk_rate_limit": n_unk_rate,
        "n_unk_model": n_unk_model,
        "n_blank": n_blank,
        "coverage_pct": coverage,
        "status": status,
    }


def render_completeness_panel(runs_sorted):
    """Render a Data Completeness warning table listing viable record counts per model."""
    rows = []
    any_incomplete = False
    for name, run in runs_sorted:
        c = compute_completeness(run)
        if c["status"] != "complete":
            any_incomplete = True
        rows.append((name, run, c))

    if not any_incomplete:
        return ""  # Nothing to flag.

    out = ['<div class="exec-summary" style="background:#f4e4c1;border-color:#c8a45d;border-left:4px solid #a23a2c;">']
    out.append('<h3 style="color:#a23a2c;">&#9888; Data Completeness Notice</h3>')
    out.append('<p style="margin:8px 0 12px;font-style:normal;color:#5b4830;">'
               'Several model runs in this report are <strong>partial</strong> because of '
               'third-party API rate limits or daily quota exhaustion. Effective F1 scores '
               'for incomplete models undercount true capability &mdash; they charge '
               'rate-limited <span class="pill pill-mute">UNK</span> records as wrong answers. '
               'The table below shows, for each model, how many records were actually '
               'classified vs how many were rate-limited noise.</p>')
    out.append('<div class="tbl-wrapper" style="background:#fff;">')
    out.append('<table>')
    out.append('<thead><tr><th>Model</th><th class="center">Status</th>'
               '<th class="num">Classified</th><th class="num">Rate-limit UNK</th>'
               '<th class="num">Model-failure UNK</th><th class="num">Blank</th>'
               '<th class="num">Coverage</th></tr></thead><tbody>')
    for name, run, c in rows:
        status = c["status"]
        if status == "complete":
            badge = '<span class="pill pill-good">COMPLETE</span>'
        elif status == "partial":
            badge = '<span class="pill pill-warn">PARTIAL</span>'
        elif status == "blocked":
            badge = '<span class="pill pill-bad">BLOCKED</span>'
        else:
            badge = '<span class="pill pill-mute">MISSING</span>'
        out.append('<tr>')
        out.append(f'<td><strong>{name}</strong></td>')
        out.append(f'<td class="center">{badge}</td>')
        out.append(f'<td class="num">{c["n_classified"]} / {c["n_total"]}</td>')
        rate_cls = "num bad" if c["n_unk_rate_limit"] > 0 else "num mute"
        out.append(f'<td class="{rate_cls}">{c["n_unk_rate_limit"]}</td>')
        out.append(f'<td class="num mute">{c["n_unk_model"]}</td>')
        out.append(f'<td class="num mute">{c["n_blank"]}</td>')
        out.append(f'<td class="num">{c["coverage_pct"]:.0%}</td>')
        out.append('</tr>')
    out.append('</tbody></table>')
    out.append('</div>')
    out.append('<p style="margin:12px 0 0;font-size:12px;color:#5b4830;font-style:italic;">'
               '<strong>Rate-limit UNK</strong> = the model\'s response was blocked by the '
               'provider\'s HTTP&thinsp;429 / quota policy rather than by any limitation of the '
               'model itself. <strong>Model-failure UNK</strong> = the model produced output that '
               'could not be parsed into a definite verdict (genuine model failure). Retries for '
               'all rate-limited cloud models are scheduled; this report will be regenerated once '
               'they complete.</p>')
    out.append('</div>')
    return "\n".join(out)


def render_comparison_chart(sorted_runs, title="Effective F1 vs. Raw F1 by model"):
    """Render an inline horizontal-bar comparison chart of all models."""
    out = ['<div class="chart-wrap">']
    out.append(f'<div class="chart-title">{title}</div>')
    for name, run in sorted_runs:
        m = run["metrics"]
        eff = m["eff_f1"]; raw = m["f1"]
        eff_pct = max(0, min(100, eff * 100))
        raw_pct = max(0, min(100, raw * 100))
        out.append('<div class="chart-row">')
        out.append(f'<div class="chart-label">{name}</div>')
        out.append('<div class="chart-bar-track">')
        out.append(f'<div class="chart-bar-fill" style="width:{eff_pct:.1f}%;"></div>')
        # Raw overlay only when raw > eff (illustrates the penalty for UNK/BLANK)
        if raw > eff:
            out.append(f'<div class="chart-bar-fill raw-overlay" style="width:{raw_pct:.1f}%;"></div>')
        out.append('</div>')
        out.append(f'<div class="chart-value">{eff:.3f}</div>')
        out.append('</div>')
    out.append(
        '<div class="chart-legend">'
        '<span><span class="swatch eff"></span>Effective F1 (UNK/BLANK = wrong)</span>'
        '<span><span class="swatch raw"></span>Raw F1 (classified subset only)</span>'
        '</div>'
    )
    out.append('</div>')
    return "\n".join(out)


def heatmap_cell_class(correct, total):
    """Return a CSS class for a per-CWE heatmap cell."""
    if total == 0:
        return "hc-unk"
    r = correct / total
    if r >= 1.0: return "hc-perfect"
    if r >= 0.75: return "hc-high"
    if r >= 0.5: return "hc-mid"
    if r > 0:   return "hc-low"
    return "hc-fail"


def build_html(runs):
    """Build a professional, structured HTML benchmark report."""
    h = [HTML_HEAD]
    now = datetime.now()

    # ── Sort by effective F1 descending ────────────────────────────
    sorted_runs = sorted(runs.items(), key=lambda kv: -kv[1]["metrics"]["eff_f1"])
    cwes = sorted({cwe for run in runs.values() for cwe in run["metrics"]["by_cwe"]})
    corpus_labels = sorted({seg for run in runs.values() for seg in run.get("segments", []) if seg})

    top_name, top_run = sorted_runs[0] if sorted_runs else ("n/a", None)
    n_models = len(runs)
    n_binaries = sorted_runs[0][1]["metrics"]["n"] if sorted_runs else 0

    # ─────────────────────────────────────────────────────────────
    # Document header
    # ─────────────────────────────────────────────────────────────
    h.append('<header class="doc-header">')
    h.append('<h1>Agent-G Juliet Benchmark</h1>')
    h.append('<p class="doc-subtitle">A comparative evaluation of large language models on cheat-resistant memory-safety vulnerability analysis</p>')
    h.append('<div class="doc-meta">')
    h.append(f'<span><strong>Report date:</strong> {now.strftime("%B %d, %Y")}</span>')
    h.append(f'<span><strong>Models evaluated:</strong> {n_models}</span>')
    if len(corpus_labels) == 1:
        h.append(f'<span><strong>Test corpus:</strong> {corpus_labels[0]} ({n_binaries} anonymized ELF-x86_64 binaries)</span>')
    elif corpus_labels:
        h.append(f'<span><strong>Test corpus:</strong> mixed cohorts ({", ".join(corpus_labels)})</span>')
    else:
        h.append(f'<span><strong>Test corpus:</strong> {n_binaries} anonymized ELF-x86_64 binaries</span>')
    h.append(f'<span><strong>Revision:</strong> {now.strftime("%Y%m%d-%H%M")}</span>')
    h.append('</div>')
    h.append('</header>')

    # Table of Contents — simplified (3 sections only)
    h.append('<nav class="toc" aria-label="Table of contents">')
    h.append('<div class="toc-title">Contents</div>')
    h.append('<ol>')
    h.append('<li><a href="#exec">Summary</a></li>')
    h.append('<li><a href="#sec2">Results</a></li>')
    h.append('<li><a href="#sec3">Per-CWE breakdown</a></li>')
    h.append('<li><a href="#sec4">Per-model detail</a></li>')
    h.append('<li><a href="#sec5">Model compatibility notes</a></li>')
    h.append('</ol>')
    h.append('</nav>')

    # ─────────────────────────────────────────────────────────────
    # Executive Summary
    # ─────────────────────────────────────────────────────────────
    h.append('<section id="exec">')
    h.append('<div class="exec-summary">')
    h.append('<h3>Summary</h3>')
    if top_run:
        top_m = top_run["metrics"]
        correct = top_m["tp"] + top_m["tn"]
        total = top_m["n"]
        n_bad = top_m["tp"] + top_m["fn"] + top_m["unk_bad"] + top_m["blank_bad"]
        n_good = top_m["tn"] + top_m["fp"] + top_m["unk_good"] + top_m["blank_good"]
        h.append('<ul>')
        h.append(
            f'<li><strong>Top performer:</strong> <em>{top_name}</em> &mdash; '
            f'Effective F1 <strong>{top_m["eff_f1"]:.3f}</strong>, '
            f'{correct}/{total} binaries correct '
            f'({top_m["fp"]}/{n_good} false alarms, {top_m["fn"]}/{n_bad} missed vulnerabilities).</li>'
        )
        h.append(
            f'<li><strong>Corpus:</strong> {n_models} models evaluated on {n_binaries} '
            f'anonymized ELF-x86_64 Juliet binaries covering {len(cwes)} CWE categories '
            f'(bad + good variants of each).</li>'
        )
        h.append(
            '<li><strong>Clean data:</strong> harness is leak-free &mdash; Juliet scaffold '
            'strings are masked, DWARF parameter names are stripped, and the <code>/health</code> '
            'endpoint is redacted. See the methodology note below.</li>'
        )
        h.append(
            '<li><strong>Metric:</strong> <strong>Effective F1</strong> treats UNKNOWN and BLANK '
            'responses as wrong (missed bug on a vulnerable binary, false alarm on a safe one). '
            '<strong>Raw F1</strong> ignores them and scores only the classified subset.</li>'
        )
        h.append('</ul>')
    h.append('</div>')

    # Data Completeness panel — only rendered if at least one model is partial.
    completeness_html = render_completeness_panel(sorted_runs)
    if completeness_html:
        h.append(completeness_html)

    # ── Scope notice (what this report measures) ─────
    h.append(
        '<div class="exec-summary" style="background:#f3e6c8;border-color:#c89656;border-left:4px solid #8c4a1f;">'
        '<h3 style="color:#8c4a1f;">What this report measures</h3>'
        '<p style="margin:8px 0 10px;color:#3a2e1f;font-style:normal;">'
        'This is an <strong>Agent-G compatibility benchmark</strong>, not a model capability '
        'benchmark. It measures how well each LLM synchronises with the Agent-G runtime on a '
        'tool-calling vulnerability-analysis task &mdash; prompt adherence, tool-call formatting, '
        'verdict structure, and retry behaviour all contribute to the score. A model may be '
        'highly capable on other benchmarks yet score poorly here if its output formatting '
        'conflicts with Agent-G\'s parser, or if its reasoning-token economy conflicts with the '
        'iterative tool-call loop. Conversely, a model tuned to Agent-G\'s conventions can '
        'outperform objectively stronger models.</p>'
        '<p style="margin:8px 0 0;color:#3a2e1f;font-style:normal;">'
        '<strong>Pipeline:</strong> (1) Collect Juliet test samples from the NIST Test Suite &rarr; '
        '(2) Strip and sanitise them to prevent ground-truth leakage &mdash; symbols renamed, '
        'DWARF param names stripped, scaffold strings masked, filenames hashed, '
        '<code>/health</code> redacted &rarr; '
        '(3) Feed each sample to Agent-G under the model being tested &rarr; '
        '(4) Parse the model\'s free-text investigation report into a structured '
        '<code>VULNERABLE</code> / <code>NOT_VULNERABLE</code> / <code>UNKNOWN</code> / '
        '<code>BLANK</code> verdict and score it against the manifest ground truth. '
        'Ground truth is never visible to the model.</p>'
        '</div>'
    )

    h.append('</section>')

    # ─────────────────────────────────────────────────────────────
    # Section 1: Benchmark Design
    # ─────────────────────────────────────────────────────────────
    # CWE description table — used downstream by the heatmap section headers
    cwe_desc = {
        "CWE-121": "Stack-Based Buffer Overflow",
        "CWE-122": "Heap-Based Buffer Overflow",
        "CWE-415": "Double Free",
        "CWE-416": "Use After Free",
        "CWE-476": "NULL Pointer Dereference",
        "CWE-78":  "OS Command Injection",
        "CWE-134": "Uncontrolled Format String",
        "CWE-190": "Integer Overflow",
        "CWE-369": "Divide by Zero",
        "CWE-457": "Use of Uninitialized Variable",
    }

    # ─────────────────────────────────────────────────────────────
    # Section 1: Results
    # ─────────────────────────────────────────────────────────────
    h.append('<section>')
    h.append('<h2 id="sec2"><span class="section-num">1.</span>Results</h2>')
    h.append(
        f'<p>{n_models} model runs on {n_binaries} binaries, sorted by Effective F1 (descending). '
        'Rank&nbsp;1 is highlighted. <span class="mute">*</span> next to a Raw F1 value means '
        'the score excludes one or more UNKNOWN / BLANK outcomes; see Figure&nbsp;1 for the '
        'visual gap between Effective and Raw F1.</p>'
    )

    h.append('<div class="tbl-wrapper">')
    h.append('<table>')
    h.append('<thead><tr>')
    headers = [
        "Rank", "Model", "Family",
        "Effective F1",
        "Raw F1",
        "Accuracy", "TP", "TN", "FP", "FN", "UNK", "BLANK",
        "Avg Time", "Avg Tools",
    ]
    for hdr in headers:
        cls = "center" if hdr in ("Rank", "TP", "TN", "FP", "FN", "UNK", "BLANK") else ("num" if hdr in ("Avg Time", "Avg Tools", "Accuracy") else "")
        h.append(f'<th class="{cls}">{hdr}</th>')
    h.append('</tr></thead><tbody>')

    for idx, (name, run) in enumerate(sorted_runs, start=1):
        m = run["metrics"]
        raw_marker = "" if (m.get("unk", 0) + m.get("blank", 0) == 0) else '<span class="mute">*</span>'
        raw_f1_str = f'{m["f1"]:.3f}{raw_marker}'
        acc_str = f'{m["eff_accuracy"]:.1%}'
        bar = fmt_score_bar(m["eff_f1"])

        h.append('<tr>')
        h.append(f'<td class="center"><span class="rank">{idx}</span></td>')
        h.append(f'<td><strong>{name}</strong><div class="mute" style="font-size:11px;margin-top:2px;">{run.get("model_id", "")[:80]}</div></td>')
        h.append(f'<td>{run.get("family", "?")}</td>')
        h.append(f'<td>{bar}</td>')
        h.append(f'<td class="num">{raw_f1_str}</td>')
        h.append(f'<td class="num">{acc_str}</td>')
        h.append(f'<td class="center good">{m["tp"]}</td>')
        h.append(f'<td class="center good">{m["tn"]}</td>')
        h.append(f'<td class="center warn">{m["fp"]}</td>')
        h.append(f'<td class="center bad">{m["fn"]}</td>')
        h.append(f'<td class="center mute">{m["unk"]}</td>')
        blank_count = m.get("blank", 0)
        blank_td_cls = "center bad" if blank_count > 0 else "center mute"
        h.append(f'<td class="{blank_td_cls}">{blank_count}</td>')
        h.append(f'<td class="num">{m["avg_time_s"]:.0f}&thinsp;s</td>')
        h.append(f'<td class="num">{m["avg_tools"]:.1f}</td>')
        h.append('</tr>')
    h.append('</tbody></table>')
    h.append('</div>')
    h.append(
        f'<p class="tbl-caption"><strong>Table 1.</strong> Aggregate results for {n_models} model '
        'runs, sorted by Effective F1. <span class="mute">*</span> denotes Raw F1 computed with '
        'UNKNOWN/BLANK verdicts excluded from the denominator.</p>'
    )

    h.append('<h4>Visual comparison</h4>')
    h.append(render_comparison_chart(sorted_runs, "Effective F1 by model (sorted)"))
    h.append('<p class="tbl-caption"><strong>Figure 1.</strong> Solid bar = Effective F1 (UNK/BLANK counted as wrong). Striped overlay (where present) shows the higher Raw F1 the model would attain if its UNK/BLANK responses were excluded entirely &mdash; the gap visualises the cost of failing to commit to a verdict.</p>')

    h.append('<h4>Verdict category legend</h4>')
    h.append('<div class="legend" style="margin-bottom:12px;">')
    h.append('<div class="legend-item"><span class="pill pill-good">TP</span> True positive &mdash; vulnerable binary correctly flagged</div>')
    h.append('<div class="legend-item"><span class="pill pill-good">TN</span> True negative &mdash; safe binary correctly cleared</div>')
    h.append('<div class="legend-item"><span class="pill pill-warn">FP</span> False positive &mdash; safe binary over-flagged</div>')
    h.append('<div class="legend-item"><span class="pill pill-bad">FN</span> False negative &mdash; vulnerable binary missed</div>')
    h.append('<div class="legend-item"><span class="pill pill-mute">UNK</span> Response unparseable</div>')
    h.append('<div class="legend-item"><span class="pill pill-bad">BLANK</span> Blank response (thinking budget exhausted)</div>')
    h.append('</div>')
    h.append('</section>')

    # ─────────────────────────────────────────────────────────────
    # Section 3: Per-CWE Heatmap
    # ─────────────────────────────────────────────────────────────
    h.append('<section>')
    h.append('<h2 id="sec3"><span class="section-num">2.</span>Per-CWE Performance</h2>')
    h.append(
        f'<p>Correct verdicts (TP&thinsp;+&thinsp;TN) out of binaries per CWE category. '
        'UNKNOWN and BLANK are counted as incorrect.</p>'
    )
    h.append('<div class="tbl-wrapper">')
    h.append('<table class="heatmap">')
    h.append('<thead><tr><th>Model</th>')
    for cwe in cwes:
        desc_short = cwe_desc.get(cwe, "").split()[0]
        h.append(f'<th class="center">{cwe}<br><span style="font-weight:400;text-transform:none;color:var(--text-mute);font-size:10px;">{desc_short}</span></th>')
    h.append('<th class="center">Total</th></tr></thead><tbody>')

    for name, run in sorted_runs:
        m = run["metrics"]
        h.append('<tr>')
        h.append(f'<td>{name}</td>')
        total_correct = 0
        total_n = 0
        for cwe in cwes:
            cdata = m["by_cwe"].get(cwe, {})
            correct = cdata.get("tp", 0) + cdata.get("tn", 0)
            total = cdata.get("n_bad", 0) + cdata.get("n_good", 0)
            total_correct += correct
            total_n += total
            cls = heatmap_cell_class(correct, total)
            h.append(f'<td class="{cls}">{correct}/{total}</td>')
        overall_cls = heatmap_cell_class(total_correct, total_n)
        h.append(f'<td class="{overall_cls}"><strong>{total_correct}/{total_n}</strong></td>')
        h.append('</tr>')
    h.append('</tbody></table>')
    h.append('</div>')
    h.append(
        '<p class="tbl-caption"><strong>Table 2.</strong> Per-CWE correct-verdict ratios. '
        'Darker green = higher accuracy on that category.</p>'
    )
    h.append('</section>')

    # ─────────────────────────────────────────────────────────────
    # Section 3: Per-Model Detail
    # ─────────────────────────────────────────────────────────────
    h.append('<section>')
    h.append('<h2 id="sec4"><span class="section-num">3.</span>Per-Model Detail</h2>')
    h.append(
        '<p>Binary-by-binary verdict matrix, aggregate stats, and per-CWE breakdown for each model.</p>'
    )

    BLANK_MARKERS = (
        "Model returned a blank response",
        "thinking budget was exhausted",
        "thinking budget exhausted",
        "[MODEL_RETURNED_BLANK_RESPONSE]",
    )

    for idx, (name, run) in enumerate(sorted_runs, start=1):
        m = run["metrics"]
        anchor = f"sec4-{idx}"
        h.append(f'<h3 id="{anchor}">3.{idx} {name}</h3>')
        h.append('<div class="model-detail">')

        # Header block
        h.append('<div class="model-detail-head">')
        h.append(
            f'<div><div class="model-detail-title">{name}</div>'
            f'<div class="model-detail-id">Model ID: {run.get("model_id", "?")}</div>'
            f'<div class="model-detail-id">Family: {run.get("family", "?")} &middot; Tier: {run.get("tier", "?")}</div></div>'
        )
        h.append('<div class="model-score-display">')
        h.append('<div class="label">Effective F1</div>')
        h.append(f'<div class="value">{m["eff_f1"]:.3f}</div>')
        h.append('</div>')
        h.append('</div>')

        # Notes (if any)
        if run.get("notes"):
            h.append(f'<div class="model-notes">{run["notes"]}</div>')

        # Stats grid
        h.append('<div class="stat-grid">')
        stats = [
            ("Accuracy", f'{m["eff_accuracy"]:.1%}'),
            ("Precision", f'{m["eff_precision"]:.3f}'),
            ("Recall", f'{m["eff_recall"]:.3f}'),
            ("Total Time", f'{m["total_time_s"]:.0f}\u2009s'),
            ("Tool Calls / Bin", f'{m["avg_tools"]:.1f}'),
            ("Iterations / Bin", f'{m["avg_iters"]:.1f}'),
        ]
        for label, val in stats:
            h.append(f'<div class="stat"><div class="stat-label">{label}</div><div class="stat-value">{val}</div></div>')
        h.append('</div>')

        # Per-binary matrix
        h.append('<h4>Per-Binary Verdict Matrix</h4>')
        h.append('<div class="matrix-container">')
        h.append('<div class="matrix">')
        for r in run["records"]:
            t = r.get("ground_truth", "")
            v = r.get("verdict", "")
            rep = r.get("report_text", "") or ""
            if v == "UNKNOWN" and any(mk in rep for mk in BLANK_MARKERS):
                v = "BLANK_RESPONSE"
            cwe_short = r.get('cwe', '?')
            var_short = r.get('variant', '?')
            if v == "BLANK_RESPONSE":
                cls = "m-blank"; title = f"{cwe_short} {var_short}: BLANK (thinking budget exhausted)"
            elif v == "UNKNOWN":
                cls = "m-unk"; title = f"{cwe_short} {var_short}: UNKNOWN"
            elif t == v == "VULNERABLE":
                cls = "m-tp"; title = f"{cwe_short} {var_short}: True Positive"
            elif t == v == "NOT_VULNERABLE":
                cls = "m-tn"; title = f"{cwe_short} {var_short}: True Negative"
            elif t == "NOT_VULNERABLE" and v == "VULNERABLE":
                cls = "m-fp"; title = f"{cwe_short} {var_short}: False Positive (over-flagged)"
            elif t == "VULNERABLE" and v == "NOT_VULNERABLE":
                cls = "m-fn"; title = f"{cwe_short} {var_short}: False Negative (missed)"
            else:
                cls = "m-unk"; title = "unknown"
            h.append(f'<span class="matrix-cell {cls}" title="{title}"></span>')
        h.append('</div>')
        h.append('<div class="legend">')
        h.append('<div class="legend-item"><span class="matrix-cell m-tp"></span>TP</div>')
        h.append('<div class="legend-item"><span class="matrix-cell m-tn"></span>TN</div>')
        h.append('<div class="legend-item"><span class="matrix-cell m-fp"></span>FP</div>')
        h.append('<div class="legend-item"><span class="matrix-cell m-fn"></span>FN</div>')
        h.append('<div class="legend-item"><span class="matrix-cell m-unk"></span>UNK</div>')
        h.append('<div class="legend-item"><span class="matrix-cell m-blank"></span>BLANK</div>')
        h.append('</div>')
        h.append('</div>')

        # Per-CWE breakdown
        h.append('<h4>Per-CWE Breakdown</h4>')
        h.append('<div class="tbl-wrapper"><table>')
        h.append('<thead><tr><th>CWE</th>'
                '<th class="center">TP</th><th class="center">TN</th>'
                '<th class="center">FP</th><th class="center">FN</th>'
                '<th class="center">UNK</th><th class="center">BLANK</th>'
                '<th class="center">Correct / Total</th></tr></thead><tbody>')
        for cwe in cwes:
            cdata = m["by_cwe"].get(cwe, {})
            correct = cdata.get("tp", 0) + cdata.get("tn", 0)
            total = cdata.get("n_bad", 0) + cdata.get("n_good", 0)
            blank_cwe = cdata.get("blank", 0)
            blank_cls = "center bad" if blank_cwe > 0 else "center mute"
            h.append(f'<tr><td><strong>{cwe}</strong></td>')
            h.append(f'<td class="center good">{cdata.get("tp", 0)}</td>')
            h.append(f'<td class="center good">{cdata.get("tn", 0)}</td>')
            h.append(f'<td class="center warn">{cdata.get("fp", 0)}</td>')
            h.append(f'<td class="center bad">{cdata.get("fn", 0)}</td>')
            h.append(f'<td class="center mute">{cdata.get("unk", 0)}</td>')
            h.append(f'<td class="{blank_cls}">{blank_cwe}</td>')
            h.append(f'<td class="center"><strong>{correct}/{total}</strong></td></tr>')
        h.append('</tbody></table></div>')
        h.append('</div>')  # end model-detail

    h.append('</section>')

    # ─────────────────────────────────────────────────────────────
    # Section 4: Model compatibility notes
    # ─────────────────────────────────────────────────────────────
    h.append('<section>')
    h.append('<h2 id="sec5"><span class="section-num">4.</span>Model Compatibility Notes</h2>')
    h.append(
        '<p>Quirks, gotchas, and integration hurdles encountered while getting each provider '
        'to drive the Agent-G runtime. Short version: Anthropic and local Ollama are painless; '
        'every cloud model has at least one edge case that Agent-G now handles automatically in '
        'code. These notes are the primary reference for anyone adding a new provider.</p>'
    )

    # Anthropic
    h.append('<h3 id="sec5-anthropic">4.1 Anthropic (Claude)</h3>')
    h.append(
        '<p><strong>Works out of the box</strong> once the API key is correct. The one issue '
        'we hit was a typo in the key itself &mdash; Anthropic returned '
        '<code>401 invalid x-api-key</code> without pointing at the specific character that '
        'was wrong. Lesson: when in doubt, copy-paste straight from the Anthropic console; a '
        'single missing dash breaks the whole key.</p>'
        '<p>Native <code>v1/messages</code> API plus the <code>x-api-key</code> header, so it '
        'sidesteps the <code>Authorization: Bearer</code> schemes that other providers use. No '
        'thinking-token handling needed for the standard Claude models; they just return text.</p>'
    )

    # Google
    h.append('<h3 id="sec5-google">4.2 Google (Gemini + Gemma)</h3>')
    h.append(
        '<p>Four things bit us in sequence and each one has a dedicated code fix:</p>'
    )
    h.append('<ol>')
    h.append(
        '<li><strong>Gemini 3.x is a thinking model that can exhaust its visible-token '
        'budget.</strong> The response comes back with '
        '<code>candidatesTokenCount: 0</code> even on a successful <code>STOP</code> '
        'completion because all the budget went to hidden reasoning tokens. '
        '<em>Fix:</em> the <code>thinking_models</code> registry auto-bumps '
        '<code>maxOutputTokens</code> to 32k and retries with 2&times; budget on empty '
        'visible output, up to a 131k ceiling '
        '(<code>src/runtime/thinking_models.py</code>, <code>src/external_client.py</code>).</li>'
    )
    h.append(
        '<li><strong>Gemini 3.x emits <code>MALFORMED_FUNCTION_CALL</code></strong> when the '
        'built-in function-calling mode is active and the model hasn\'t finished emitting the '
        'call. <em>Fix:</em> Agent-G sets '
        '<code>toolConfig.functionCallingConfig.mode&nbsp;=&nbsp;NONE</code> for '
        'mandatory-thinking Gemini variants, forcing plain-text tool-call syntax instead.</li>'
    )
    h.append(
        '<li><strong>Gemma 4 31B returns a multi-part response</strong> with a '
        '<code>{"thought":&nbsp;true}</code> part first and the visible answer as a second '
        'part. The original parser grabbed <code>parts[0]</code> (the thought!) and returned '
        'an empty visible string. <em>Fix:</em> the parser now concatenates all non-thought '
        'text parts from the <code>candidates[0].content.parts</code> array.</li>'
    )
    h.append(
        '<li><strong>Preview endpoints get shed aggressively under load.</strong> During '
        'development we hit a 59/60 HTTP 503 storm on '
        '<code>gemini-3.1-flash-lite-preview</code> that lasted ~20 minutes. The error body '
        'admitted it plainly: <em>"This model is currently experiencing high demand"</em>. '
        '<em>Fix:</em> the per-provider circuit breaker '
        '(<code>src/runtime/circuit_breaker.py</code>) trips after 3 consecutive 5xx errors '
        'and stops hammering the endpoint until a cooldown expires.</li>'
    )
    h.append('</ol>')

    # OpenAI
    h.append('<h3 id="sec5-openai">4.3 OpenAI (GPT-5 family via API key)</h3>')
    h.append(
        '<p><strong>Worked once we knew the exact model name.</strong> <code>gpt-5</code>, '
        '<code>gpt-5.4</code>, and <code>gpt-5.4-mini</code> are all valid; '
        '<code>gpt5.4</code>, <code>gpt-5-4</code>, and <code>gpt-5.4-turbo</code> get '
        'rejected with 400 by OpenAI\'s router. Use <code>EXTERNAL_MODEL=gpt-5.4</code> '
        'verbatim.</p>'
        '<p>The real gotcha: <strong>GPT-5 writes '
        '<code>**INVESTIGATION COMPLETE**</code> as a transitional phrase BEFORE producing '
        'the final verdict block.</strong> The original ReAct loop saw the marker, exited, '
        'and the harness classified the response as UNKNOWN. '
        '<em>Fix:</em> the loop now requires <em>both</em> a completion marker <em>and</em> '
        'a parseable verdict pattern in the same response before exiting. If the marker '
        'appears alone, the loop keeps going. Covered by a regression test in '
        '<code>tests/test_conversation_replay.py</code>.</p>'
    )

    # Codex OAuth
    h.append('<h3 id="sec5-codex-oauth">4.4 Codex Desktop OAuth (ChatGPT Team/Pro, no API key)</h3>')
    h.append(
        '<p>This was the most surprising path. The token in <code>~/.codex/auth.json</code> '
        '<strong>is a real OpenAI OAuth token</strong> but it has the wrong scopes for the '
        'public OpenAI API:</p>'
    )
    h.append('<div class="tbl-wrapper"><table>')
    h.append('<thead><tr><th>Endpoint</th><th>Response</th><th>Reason</th></tr></thead><tbody>')
    h.append('<tr><td><code>api.openai.com/v1/chat/completions</code></td>'
             '<td>500 <em>"Internal server error"</em></td>'
             '<td>Masked &mdash; means "wrong auth for this endpoint"</td></tr>')
    h.append('<tr><td><code>api.openai.com/v1/responses</code></td>'
             '<td>401 <em>"Missing scopes: api.responses.write"</em></td>'
             '<td>Explicit scope rejection</td></tr>')
    h.append('<tr><td><code>chatgpt.com/backend-api/codex/responses</code></td>'
             '<td><strong>200 OK</strong></td>'
             '<td>This is the endpoint Codex desktop actually uses</td></tr>')
    h.append('</tbody></table></div>')
    h.append(
        '<p>The token has <code>api.connectors.read</code> + <code>api.connectors.invoke</code> '
        'scopes, which work only against the ChatGPT-internal backend. Agent-G detects this '
        'case from the URL (<code>chatgpt.com/backend-api/codex</code> in '
        '<code>CUSTOM_API_URL</code>) and switches to the Responses-API payload shape '
        '(<code>instructions</code> + <code>input</code> list, <code>stream=true</code> '
        'mandatory, <code>store=false</code>, <code>chatgpt-account-id</code> header). See '
        '<code>src/custom_api_client.py:_generate_chatgpt_backend</code>.</p>'
        '<p>Rate limiting on this endpoint is also stricter than on <code>api.openai.com</code> '
        '&mdash; about 6&ndash;10 requests per minute before it 429s. Set '
        '<code>CUSTOM_API_REQUEST_DELAY=10</code> to stay under the cap.</p>'
    )

    # Ollama
    h.append('<h3 id="sec5-ollama">4.5 Local Ollama</h3>')
    h.append(
        '<p>Small models (<code>gemma4:e4b</code> and friends) have a capacity issue that '
        'looks like a thinking-model failure: they truncate to an empty completion on long '
        'agentic prompts. Agent-G added them to the <code>thinking_models</code> registry not '
        'because they\'re reasoning models, but because that registry is the central place '
        'where <code>num_predict</code> gets auto-bumped. The fix in '
        '<code>src/ollama_client.py</code> also drops temperature from 0.7 &rarr; 0.1 for '
        'registered small-model entries, because they "sample themselves into" blank '
        'responses when temperature is high.</p>'
        '<p><strong>Cloud Ollama</strong> (models with <code>-cloud</code> suffix like '
        '<code>gemma4:31b-cloud</code>, <code>qwen3.5:397b-cloud</code>) reliably rate-limits '
        'after ~6 binaries per minute. The circuit breaker catches it after 3 consecutive '
        '429s and tells Agent-G to fall back or give up cleanly.</p>'
    )

    # Summary table
    h.append('<h3 id="sec5-summary">4.6 Summary</h3>')
    h.append('<div class="tbl-wrapper"><table>')
    h.append('<thead><tr><th>Provider</th><th class="center">Works out of box?</th>'
             '<th>Code changes needed</th></tr></thead><tbody>')
    compat = [
        ("Anthropic (Claude)",         "✓", "None (key typo was user error)"),
        ("Google Gemini 3.x",          "partial", "thinking_models registry, multi-part parser, circuit breaker, thinkingConfig"),
        ("Google Gemma 4",             "partial", "multi-part response parser"),
        ("OpenAI (API key)",           "partial", "<code>INVESTIGATION COMPLETE</code> marker + verdict co-requirement"),
        ("Codex OAuth (ChatGPT)",      "partial", "ChatGPT backend endpoint + Responses API payload + account header"),
        ("Ollama local (small)",       "partial", "<code>num_predict</code> bump + temperature floor"),
        ("Ollama cloud",               "no",      "Rate limits unusable for batch runs; circuit breaker absorbs the 429s"),
    ]
    for name, status, notes in compat:
        cls = {"✓": "good", "partial": "warn", "no": "bad"}.get(status, "mute")
        label = {"✓": "YES", "partial": "PARTIAL", "no": "NO"}.get(status, status)
        h.append(f'<tr><td>{name}</td>'
                 f'<td class="center"><span class="pill pill-{cls}">{label}</span></td>'
                 f'<td>{notes}</td></tr>')
    h.append('</tbody></table></div>')
    h.append(
        '<p>All of these fixes are <strong>already in the Agent-G codebase</strong> &mdash; '
        'nothing extra is needed to use any of the providers above. These notes exist so '
        'that anyone adding a new provider can recognize the failure modes and apply '
        'the same patterns.</p>'
    )

    h.append('</section>')

    h.append(HTML_FOOT)
    return "\n".join(h)


def main():
    parser = argparse.ArgumentParser()
    default_out = Path(__file__).resolve().parent.parent / "logs" / "juliet_comparison_report.html"
    parser.add_argument("--output", default=str(default_out))
    args = parser.parse_args()

    runs = load_all_runs()
    print(f"Loaded {len(runs)} model runs:")
    for name, run in runs.items():
        m = run["metrics"]
        print(f"  - {name}: F1={m['f1']:.3f}, acc={m['accuracy']:.2%}, n={m['n']}, unk={m['unk']}")

    html = build_html(runs)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\nHTML report written to: {args.output}")
    print(f"File size: {os.path.getsize(args.output)} bytes")


if __name__ == "__main__":
    main()
