#!/usr/bin/env python3
"""Cheat-resistant Juliet test harness for Agent-G.

Runs Agent-G's vulnerability-hunting task on a stratified sample of Juliet
test binaries with the JulietAnonymizer applied to strip giveaway symbol names.
Computes precision/recall against the manifest's `is_vulnerable` ground truth.

Usage:
    cd C:\\Users\\Era\\Desktop\\OGhidra\\Agent-G
    python scripts/test_juliet.py [--sample-size 20] [--cwes CWE-121,CWE-122,...]
"""

import argparse
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
import threading
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import httpx
import ijson

# Make src/ importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Load .env BEFORE importing config
_env_path = Path(__file__).resolve().parent.parent / ".env"
if _env_path.exists():
    for line in _env_path.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k, v)

from src.config import get_config  # noqa: E402
from src.bridge_lite import BridgeLite  # noqa: E402
# LeakFilter lives in benchmark/ because it is benchmark-specific (Juliet
# scaffold masking). Production Agent-G deployments should not depend on it.
from benchmark.leak_filter import LeakFilter  # noqa: E402


# ── Configuration ────────────────────────────────────────────────────────

JULIET_ROOT = Path(os.environ.get(
    "JULIET_CORPUS_ROOT",
    str(Path.home() / "juliet-corpus"),
))
MANIFEST_PATH = JULIET_ROOT / "manifest_juliet_full.json"

GHIDRA_INSTALL = Path(os.environ.get("GHIDRA_INSTALL_DIR", ""))
# analyzeHeadless extension is platform-specific (.bat on Windows, bare name
# on Linux/macOS). Pick whichever exists.
_candidates = [
    GHIDRA_INSTALL / "support" / "analyzeHeadless.bat",
    GHIDRA_INSTALL / "support" / "analyzeHeadless",
]
HEADLESS_BIN = next((c for c in _candidates if c.exists()), _candidates[0])

AGENT_G_ROOT = Path(__file__).resolve().parent.parent
# Production Ghidra scripts live under ghidra/scripts (OGhidraHeadlessServer etc.)
# Benchmark-only scripts (JulietAnonymizer) live under benchmark/ghidra/.
# Both directories are passed to analyzeHeadless via -scriptPath (semicolon-separated on Windows).
SCRIPT_DIR = AGENT_G_ROOT / "ghidra" / "scripts"
BENCH_SCRIPT_DIR = AGENT_G_ROOT / "benchmark" / "ghidra"
LOGS_DIR = AGENT_G_ROOT / "logs"
LOGS_DIR.mkdir(exist_ok=True)

# Default CWE categories for the smoke test (memory safety focus)
DEFAULT_CWES = [
    "CWE-121",  # Stack Buffer Overflow
    "CWE-122",  # Heap Buffer Overflow
    "CWE-415",  # Double Free
    "CWE-416",  # Use After Free
    "CWE-476",  # NULL Pointer Dereference
]

# Per-binary safety budgets
GHIDRA_READY_TIMEOUT = 120  # seconds to wait for analyzeHeadless to start the HTTP server
INVESTIGATION_TIMEOUT = 240  # seconds for the agent's run_turn() call

logger = logging.getLogger("juliet_test")


# ── Manifest sampling ────────────────────────────────────────────────────

def load_juliet_samples(cwes: list, per_class: int = 4):
    """Stream the manifest and select a balanced sample.

    Args:
        cwes: List of CWE IDs (e.g., ['CWE-121']) to sample from
        per_class: For each CWE, return per_class//2 bad + per_class//2 good

    Returns:
        List of dicts with: id, path, cwe, is_vulnerable, variant
    """
    targets = {cwe: {"bad": [], "good": []} for cwe in cwes}
    bad_per = max(per_class // 2, 1)
    good_per = max(per_class - bad_per, 1)

    print(f"[harness] Streaming manifest: {MANIFEST_PATH}")
    with open(MANIFEST_PATH, "rb") as f:
        for entry in ijson.items(f, "samples.item"):
            cwe = entry.get("cwe")
            if cwe not in targets:
                continue
            # Filter to ELF only (faster analysis)
            if entry.get("format") != "elf":
                continue
            # Prefer flow_variant 01 (simplest control flow)
            if entry.get("flow_variant") != "01":
                continue

            variant = entry.get("variant")
            if variant == "bad" and len(targets[cwe]["bad"]) < bad_per:
                targets[cwe]["bad"].append(entry)
            elif variant == "good" and len(targets[cwe]["good"]) < good_per:
                targets[cwe]["good"].append(entry)

            # Early exit if all targets full
            if all(
                len(t["bad"]) >= bad_per and len(t["good"]) >= good_per
                for t in targets.values()
            ):
                break

    # Flatten into a single list, interleaving bad/good
    sample = []
    for cwe in cwes:
        for v in ("bad", "good"):
            for entry in targets[cwe][v]:
                sample.append(entry)

    return sample


# ── Headless Ghidra launcher ─────────────────────────────────────────────

def launch_headless_with_anonymizer(binary_path: Path, port: int):
    """Start headless Ghidra with JulietAnonymizer + OGhidraHeadlessServer.

    Returns: (subprocess.Popen, temp_dir_path)
    """
    temp_dir = tempfile.mkdtemp(prefix="juliet_test_")
    # Pass BOTH the production script dir and the benchmark script dir so
    # analyzeHeadless can resolve JulietAnonymizer.java (benchmark) AND
    # OGhidraHeadlessServer.java (production) by simple name.
    script_path_arg = f"{SCRIPT_DIR}{os.pathsep}{BENCH_SCRIPT_DIR}"
    cmd = [
        str(HEADLESS_BIN),
        temp_dir,
        "TestProj",
        "-import", str(binary_path),
        "-scriptPath", script_path_arg,
        "-postScript", "JulietAnonymizer.java",
        "-postScript", "OGhidraHeadlessServer.java", str(port),
    ]
    logger.debug("Launching: %s", " ".join(cmd))

    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )

    # Background thread to drain stdout (prevent buffer deadlock)
    def drain():
        for line in proc.stdout:
            logger.debug("[ghidra] %s", line.rstrip())

    threading.Thread(target=drain, daemon=True).start()
    return proc, temp_dir


def wait_for_ghidra_ready(port: int, timeout: int = GHIDRA_READY_TIMEOUT) -> bool:
    """Poll /health until ready or timeout."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            r = httpx.get(f"http://localhost:{port}/health", timeout=2)
            if r.status_code == 200 and "ready" in r.text:
                return True
        except Exception:
            pass
        time.sleep(2)
    return False


def shutdown_ghidra(port: int, proc: subprocess.Popen, temp_dir: str):
    """Best-effort shutdown of headless Ghidra and cleanup."""
    try:
        httpx.post(f"http://localhost:{port}/shutdown", timeout=5)
    except Exception:
        pass
    try:
        proc.wait(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait(timeout=5)
    # Clean up temp project
    try:
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
    except Exception:
        pass


def verify_anonymized(port: int) -> dict:
    """Spot-check that the anonymizer worked. Returns stats."""
    leak_pattern = re.compile(
        r"(?i)(cwe\d+|stack_based|heap_based|^bad\d*$|^good\d*$|"
        r"printLine|printIntLine|printStruct|decodeHex|globalReturns)"
    )
    try:
        r = httpx.get(f"http://localhost:{port}/exports?offset=0&limit=200", timeout=10)
        export_lines = r.text.split("\n")
        leaks = [
            ln for ln in export_lines
            if " -> " in ln and leak_pattern.search(ln.split(" -> ")[0])
        ]
        return {"export_count": len(export_lines), "remaining_leaks": leaks}
    except Exception as e:
        return {"error": str(e)}


# ── Verdict classification ───────────────────────────────────────────────

# Pattern to extract the explicit "## Verdict\nXXX" section value
VERDICT_SECTION = re.compile(
    # Match "## Verdict" header followed by the next non-empty line.
    # Captures the *first* uppercase word run on that line, allowing
    # trailing parenthetical context like "NOT VULNERABLE (no findings)".
    r"(?im)^[#*\s]*verdict[:\s]*\n+\s*\**\s*([A-Z][A-Z _-]+?)(?:\s*\(|\s*\**\s*$)"
)
# Inline alternative: "Verdict: VULNERABLE" or "**Verdict**: VULNERABLE"
# Also accepts trailing parenthetical context.
VERDICT_INLINE = re.compile(
    r"(?i)\*?\*?verdict\*?\*?\s*[:\-]+\s*\**\s*([a-zA-Z _-]+?)\s*(?:\(|\**(?:\s|$|\.))"
)


def classify_verdict(report_text: str) -> str:
    """Map the agent's free-text report to a verdict string.

    Returns one of:
      - VULNERABLE      — model asserted the binary is vulnerable
      - NOT_VULNERABLE  — model asserted the binary is safe
      - BLANK_RESPONSE  — model returned a blank response (thinking budget exhausted)
      - UNKNOWN         — response was present but couldn't be classified

    Strategy: first check for the blank-response sentinel from ExternalClient,
    then parse the explicit "## Verdict" section the system prompt asks the
    model to produce. Only fall back to keyword search if there's no explicit
    verdict section.
    """
    if not report_text or not report_text.strip():
        return "UNKNOWN"

    # Detect the blank-response sentinel from the thinking-model retry
    # escalation. We check for a distinctive phrase fragment so both the
    # raw sentinel and the runtime's rewritten human-readable version match.
    if ("Model returned a blank response" in report_text
            or "thinking budget was exhausted" in report_text.lower()
            or "thinking budget exhausted" in report_text.lower()):
        return "BLANK_RESPONSE"

    # Strategy 1: Extract the explicit "## Verdict\nXXX" section
    m = VERDICT_SECTION.search(report_text)
    if not m:
        m = VERDICT_INLINE.search(report_text)

    if m:
        verdict_str = m.group(1).strip().upper()
        # Map common verdict phrasings
        if any(k in verdict_str for k in ("NOT VULN", "BENIGN", "SAFE", "INSUFFICIENT")):
            return "NOT_VULNERABLE"
        if any(k in verdict_str for k in ("VULNERABLE", "MALICIOUS", "EXPLOIT")):
            return "VULNERABLE"

    # Strategy 2: Fallback — scan for unambiguous statements
    # Skip pure markdown headers ("## Confirmed Findings" etc.)
    lower = report_text.lower()
    if "verdict: not vulnerable" in lower or "verdict:\nnot vulnerable" in lower:
        return "NOT_VULNERABLE"
    if "verdict: vulnerable" in lower or "verdict:\nvulnerable" in lower:
        return "VULNERABLE"
    if "no vulnerabilities found" in lower or "no exploitable" in lower:
        return "NOT_VULNERABLE"
    if "is vulnerable" in lower and "is not vulnerable" not in lower:
        return "VULNERABLE"

    return "UNKNOWN"


# ── Main test runner ─────────────────────────────────────────────────────

def run_one_binary(entry: dict, port: int, config) -> dict:
    """Run Agent-G on one binary, return result dict."""
    binary_path = JULIET_ROOT / entry["path"]
    binary_id = entry["id"]
    truth_vulnerable = entry["is_vulnerable"]
    cwe = entry["cwe"]

    record = {
        "id": binary_id,
        "cwe": cwe,
        "variant": entry["variant"],
        "ground_truth": "VULNERABLE" if truth_vulnerable else "NOT_VULNERABLE",
        "binary_path": str(binary_path),
        "verdict": "ERROR",
        "duration_s": 0.0,
        "iterations": 0,
        "tool_calls": 0,
        "tokens_in": 0,
        "tokens_out": 0,
        "report_text": "",
        "anonymizer_stats": {},
        "error": None,
    }

    if not binary_path.exists():
        record["error"] = f"Binary not found: {binary_path}"
        return record

    print(f"\n[harness] {'='*60}")
    print(f"[harness] Testing: {binary_id}")
    print(f"[harness] CWE: {cwe} | Truth: {record['ground_truth']}")
    print(f"[harness] {'='*60}")

    proc = None
    temp_dir = None
    t_start = time.time()
    try:
        # Launch headless Ghidra
        proc, temp_dir = launch_headless_with_anonymizer(binary_path, port)

        if not wait_for_ghidra_ready(port):
            record["error"] = "Ghidra failed to become ready in time"
            return record

        # Verify anonymization worked
        record["anonymizer_stats"] = verify_anonymized(port)
        if record["anonymizer_stats"].get("remaining_leaks"):
            print(f"[harness] WARNING: anonymizer left leaks: {record['anonymizer_stats']['remaining_leaks'][:3]}")

        # Configure Agent-G to point at this Ghidra
        config.ghidra.base_url = f"http://localhost:{port}"

        # Build BridgeLite + install LeakFilter
        # Anonymize the binary name we pass to the agent — the actual filename
        # contains CWE/bad/good which would leak into the bootstrap context.
        anon_name = f"sample_{abs(hash(binary_id)) % 100000:05d}.bin"
        bridge = BridgeLite(config=config, binary_name=anon_name)
        filtered_runner = LeakFilter(bridge.tool_runner)
        bridge.set_tool_runner(filtered_runner)

        # Run the vuln-hunting task
        bridge.start_task("vuln")

        t_invest_start = time.time()
        result = bridge.runtime.run_turn(
            "Find specific exploitable vulnerabilities in this binary. "
            "Trace data flow from external inputs to dangerous sinks. "
            "Provide concrete addresses and decompiled evidence for each finding. "
            "If you find no vulnerabilities, state clearly: 'Verdict: NOT VULNERABLE'."
        )
        invest_duration = time.time() - t_invest_start

        # Capture metrics
        record["iterations"] = result.iterations
        record["tool_calls"] = result.tool_calls
        record["tokens_in"] = result.usage.input_tokens
        record["tokens_out"] = result.usage.output_tokens
        record["report_text"] = result.final_text
        record["verdict"] = classify_verdict(result.final_text)
        record["duration_s"] = round(invest_duration, 1)

        print(f"[harness] Done: verdict={record['verdict']}, "
              f"iters={record['iterations']}, tools={record['tool_calls']}, "
              f"time={record['duration_s']}s")

    except Exception as e:
        record["error"] = f"{type(e).__name__}: {e}"
        logger.exception("Binary test failed")
        print(f"[harness] ERROR: {record['error']}")
    finally:
        if proc is not None:
            shutdown_ghidra(port, proc, temp_dir or "")

    return record


def compute_metrics(records: list) -> dict:
    """Compute confusion matrix and precision/recall from record list."""
    tp = tn = fp = fn = unknown = blank = errors = 0
    by_cwe = defaultdict(lambda: {
        "tp": 0, "tn": 0, "fp": 0, "fn": 0,
        "unk": 0, "blank": 0, "err": 0,
    })

    for r in records:
        cwe = r["cwe"]
        truth = r["ground_truth"]
        verdict = r["verdict"]

        if r.get("error"):
            errors += 1
            by_cwe[cwe]["err"] += 1
            continue

        # Distinguish "model returned blank" from generic "unknown"
        if verdict == "BLANK_RESPONSE":
            blank += 1
            by_cwe[cwe]["blank"] += 1
            continue

        if verdict == "UNKNOWN":
            unknown += 1
            by_cwe[cwe]["unk"] += 1
            continue

        if truth == "VULNERABLE" and verdict == "VULNERABLE":
            tp += 1
            by_cwe[cwe]["tp"] += 1
        elif truth == "NOT_VULNERABLE" and verdict == "NOT_VULNERABLE":
            tn += 1
            by_cwe[cwe]["tn"] += 1
        elif truth == "NOT_VULNERABLE" and verdict == "VULNERABLE":
            fp += 1
            by_cwe[cwe]["fp"] += 1
        elif truth == "VULNERABLE" and verdict == "NOT_VULNERABLE":
            fn += 1
            by_cwe[cwe]["fn"] += 1

    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0

    total = len(records)
    classified = tp + tn + fp + fn
    accuracy = (tp + tn) / classified if classified else 0.0

    return {
        "total_binaries": total,
        "true_positives": tp,
        "true_negatives": tn,
        "false_positives": fp,
        "false_negatives": fn,
        "unknown_verdicts": unknown,
        "blank_responses": blank,
        "errors": errors,
        "precision": round(precision, 3),
        "recall": round(recall, 3),
        "f1": round(f1, 3),
        "accuracy": round(accuracy, 3),
        "per_cwe": dict(by_cwe),
    }


def _provider_details(config) -> tuple[str, str]:
    """Return (provider_family, model_id) for the active LLM config."""
    provider = getattr(config, "llm_provider", "unknown")
    if provider == "external":
        return config.external.provider, config.external.model
    if provider == "custom_api":
        return "custom_api", config.custom_api.model
    if provider == "ollama":
        return "ollama", config.ollama.model
    return provider, ""


def build_run_metadata(args, config, cwes: list, sample: list) -> dict:
    """Build self-describing metadata for the benchmark artifact."""
    provider_family, model_id = _provider_details(config)
    corpus_label = args.corpus_label or args.out_tag or f"sample_{len(sample)}"
    model_name = args.model_name or model_id or provider_family or "unknown-model"

    sample_set = "default_manifest_sample"
    if args.only_ids:
        sample_set = Path(args.only_ids).name
    elif args.exclude_ids:
        sample_set = f"default_minus_{Path(args.exclude_ids).name}"

    return {
        "model_name": model_name,
        "model_id": model_id,
        "provider": provider_family,
        "llm_provider": getattr(config, "llm_provider", "unknown"),
        "deployment": args.deployment,
        "corpus_label": corpus_label,
        "sample_set": sample_set,
        "cwes": cwes,
        "include_in_report": not args.exclude_from_report,
        "notes": args.notes,
        "out_tag": args.out_tag,
    }


def write_reports(
    records: list,
    metrics: dict,
    sample_size: int,
    tag: str = None,
    run_metadata: dict | None = None,
):
    """Write JSON + Markdown reports to logs/."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suffix = f"_{tag}" if tag else ""

    # JSON log (utf-8)
    json_path = LOGS_DIR / f"juliet_test_{timestamp}{suffix}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": timestamp,
            "sample_size": sample_size,
            "run_metadata": run_metadata or {},
            "metrics": metrics,
            "records": records,
        }, f, indent=2)
    print(f"\n[harness] JSON log: {json_path}")

    # Markdown report (utf-8)
    md_path = LOGS_DIR / f"juliet_test_{timestamp}{suffix}.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Agent-G Juliet Test Report\n\n")
        f.write(f"**Run timestamp**: {timestamp}\n\n")
        f.write(f"**Sample size**: {sample_size} binaries\n\n")
        if run_metadata:
            if run_metadata.get("model_name"):
                f.write(f"**Model**: {run_metadata['model_name']}\n\n")
            if run_metadata.get("provider"):
                f.write(f"**Provider**: {run_metadata['provider']}\n\n")
            if run_metadata.get("corpus_label"):
                f.write(f"**Corpus**: {run_metadata['corpus_label']}\n\n")

        f.write("## Aggregate Metrics\n\n")
        f.write("| Metric | Value |\n|---|---|\n")
        for k in ["total_binaries", "true_positives", "true_negatives",
                  "false_positives", "false_negatives", "unknown_verdicts",
                  "errors", "precision", "recall", "f1", "accuracy"]:
            f.write(f"| {k} | {metrics[k]} |\n")

        f.write("\n## Confusion Matrix\n\n")
        f.write("|              | Predicted VULNERABLE | Predicted NOT_VULNERABLE |\n")
        f.write("|---|---|---|\n")
        f.write(f"| **Actual VULNERABLE** | {metrics['true_positives']} (TP) | {metrics['false_negatives']} (FN) |\n")
        f.write(f"| **Actual NOT_VULN** | {metrics['false_positives']} (FP) | {metrics['true_negatives']} (TN) |\n")

        f.write("\n## Per-CWE Breakdown\n\n")
        f.write("| CWE | TP | TN | FP | FN | UNK | ERR |\n|---|---|---|---|---|---|---|\n")
        for cwe, vals in sorted(metrics["per_cwe"].items()):
            f.write(f"| {cwe} | {vals['tp']} | {vals['tn']} | {vals['fp']} | {vals['fn']} | {vals['unk']} | {vals['err']} |\n")

        f.write("\n## Per-Binary Results\n\n")
        f.write("| ID | CWE | Truth | Verdict | Iters | Tools | Time | Status |\n")
        f.write("|---|---|---|---|---|---|---|---|\n")
        for r in records:
            short_id = r["id"].replace("juliet_", "")[:50]
            status = "PASS" if r["ground_truth"] == r["verdict"] else "FAIL"
            if r.get("error"):
                status = "ERR"
            f.write(f"| {short_id} | {r['cwe']} | {r['ground_truth']} | "
                    f"{r['verdict']} | {r['iterations']} | {r['tool_calls']} | "
                    f"{r['duration_s']}s | {status} |\n")

        # Show error details
        errors = [r for r in records if r.get("error")]
        if errors:
            f.write("\n## Errors\n\n")
            for r in errors:
                f.write(f"- **{r['id']}**: {r['error']}\n")

    print(f"[harness] Markdown report: {md_path}")
    return md_path


def main():
    parser = argparse.ArgumentParser(description="Juliet test harness for Agent-G")
    parser.add_argument("--sample-size", type=int, default=20,
                        help="Total binaries to test (default: 20)")
    parser.add_argument("--cwes", type=str, default=",".join(DEFAULT_CWES),
                        help="Comma-separated CWE list")
    parser.add_argument("--port", type=int, default=18200,
                        help="Starting port for headless Ghidra")
    parser.add_argument("--log-level", type=str, default="INFO")
    parser.add_argument("--only-ids", type=str, default=None,
                        help="Newline-separated file of binary IDs; only those are run (resume mode)")
    parser.add_argument("--exclude-ids", type=str, default=None,
                        help="Newline-separated file of binary IDs to skip")
    parser.add_argument("--per-class", type=int, default=None,
                        help="Override per-CWE sample count (else derived from --sample-size)")
    parser.add_argument("--out-tag", type=str, default=None,
                        help="Suffix for the output JSON/MD filename")
    parser.add_argument("--model-name", type=str, default=None,
                        help="Display label for this run in the comparison report")
    parser.add_argument("--deployment", type=str, default="",
                        help="Deployment/tier label for report display (e.g. 'cloud · flagship · OpenAI')")
    parser.add_argument("--corpus-label", type=str, default=None,
                        help="Short corpus label such as old20, new30, or full50")
    parser.add_argument("--notes", type=str, default="",
                        help="Optional report note describing provider quirks, quota limits, etc.")
    parser.add_argument("--exclude-from-report", action="store_true",
                        help="Mark this artifact as excluded from build_html_report auto-discovery")
    # ── Inline LLM provider override flags (bypass .env entirely) ──
    # Pass any subset of these to override what .env sets. Lets multiple
    # Agent-G instances run concurrently, each pinned to a different
    # provider, without racing on the on-disk .env file.
    parser.add_argument("--llm-provider", type=str, default=None,
                        choices=["ollama", "external", "custom_api"],
                        help="Override LLM_PROVIDER (e.g. 'external')")
    parser.add_argument("--external-provider", type=str, default=None,
                        choices=["google", "anthropic", "openai"],
                        help="Override EXTERNAL_PROVIDER (only meaningful with --llm-provider external)")
    parser.add_argument("--llm-model", type=str, default=None,
                        help="Override the model name for the active provider")
    parser.add_argument("--llm-api-key", type=str, default=None,
                        help="Override the API key for the active provider")
    parser.add_argument("--llm-base-url", type=str, default=None,
                        help="Override the base URL (for self-hosted Ollama or custom OpenAI-compat endpoints)")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level.upper(), logging.INFO),
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    cwes = [c.strip() for c in args.cwes.split(",")]
    per_class = args.per_class if args.per_class else max(args.sample_size // len(cwes), 2)

    only_ids = set()
    if args.only_ids and Path(args.only_ids).exists():
        only_ids = {ln.strip() for ln in Path(args.only_ids).read_text().splitlines() if ln.strip()}
        print(f"[harness] --only-ids: restricting to {len(only_ids)} binaries")
    exclude_ids = set()
    if args.exclude_ids and Path(args.exclude_ids).exists():
        exclude_ids = {ln.strip() for ln in Path(args.exclude_ids).read_text().splitlines() if ln.strip()}
        print(f"[harness] --exclude-ids: skipping {len(exclude_ids)} binaries")

    print(f"\n{'='*70}")
    print(f"Agent-G Juliet Test Harness")
    print(f"{'='*70}")
    print(f"  CWE categories: {cwes}")
    print(f"  Per-CWE: {per_class} ({per_class//2} bad + {per_class - per_class//2} good)")
    print(f"  Total target: ~{per_class * len(cwes)} binaries\n")

    # Sample binaries from manifest
    # If --only-ids is set, use a larger per_class so the loader finds them all,
    # then filter by ID.
    _pc = per_class if not only_ids else max(per_class, 20)
    sample = load_juliet_samples(cwes, per_class=_pc)
    if only_ids:
        sample = [e for e in sample if e["id"] in only_ids]
    if exclude_ids:
        sample = [e for e in sample if e["id"] not in exclude_ids]
    print(f"[harness] Selected {len(sample)} binaries from manifest")

    # Initialize config
    config = get_config()

    # ── Apply inline LLM provider overrides (bypass .env race) ──
    # When running multiple Agent-G instances concurrently, the on-disk .env
    # is a shared resource that we can't safely mutate. Inline overrides via
    # CLI flags take precedence over .env. The pydantic models accept
    # attribute mutation, so we just rebind the relevant fields. None of this
    # touches .env on disk.
    if args.llm_provider:
        config.llm_provider = args.llm_provider
        print(f"[harness] override: LLM_PROVIDER={args.llm_provider}")
    if args.llm_provider == "external" or (args.llm_provider is None and config.llm_provider == "external"):
        if args.external_provider:
            config.external.provider = args.external_provider
            print(f"[harness] override: EXTERNAL_PROVIDER={args.external_provider}")
        if args.llm_model:
            config.external.model = args.llm_model
            print(f"[harness] override: EXTERNAL_MODEL={args.llm_model}")
        if args.llm_api_key:
            config.external.api_key = args.llm_api_key
            print(f"[harness] override: EXTERNAL_API_KEY=<redacted, len={len(args.llm_api_key)}>")
        if args.llm_base_url:
            config.external.base_url = args.llm_base_url
            print(f"[harness] override: EXTERNAL_BASE_URL={args.llm_base_url}")
    if args.llm_provider == "ollama" or (args.llm_provider is None and config.llm_provider == "ollama"):
        if args.llm_model:
            config.ollama.model = args.llm_model
            print(f"[harness] override: OLLAMA_MODEL={args.llm_model}")
        if args.llm_base_url:
            config.ollama.base_url = args.llm_base_url
            print(f"[harness] override: OLLAMA_BASE_URL={args.llm_base_url}")
    if args.llm_provider == "custom_api" or (args.llm_provider is None and config.llm_provider == "custom_api"):
        if args.llm_model:
            config.custom_api.model = args.llm_model
            print(f"[harness] override: CUSTOM_API_MODEL={args.llm_model}")
        if args.llm_api_key:
            config.custom_api.api_key = args.llm_api_key
            print(f"[harness] override: CUSTOM_API_KEY=<redacted, len={len(args.llm_api_key)}>")
        if args.llm_base_url:
            # CustomAPIConfig uses api_url (not base_url) — pydantic will reject
            # the wrong field name with a setattr ValueError
            config.custom_api.api_url = args.llm_base_url
            print(f"[harness] override: CUSTOM_API_URL={args.llm_base_url}")

    print(f"[harness] LLM provider: {config.llm_provider}")
    if config.llm_provider == "external":
        print(f"[harness] External: {config.external.provider}/{config.external.model}")
    elif config.llm_provider == "custom_api":
        print(f"[harness] Custom API: {config.custom_api.model}")

    run_metadata = build_run_metadata(args, config, cwes, sample)
    print(f"[harness] Run label: {run_metadata['model_name']}")
    print(f"[harness] Corpus label: {run_metadata['corpus_label']}")

    # Run tests
    records = []
    for i, entry in enumerate(sample, 1):
        port = args.port + i  # unique port per test
        print(f"\n[harness] === Binary {i}/{len(sample)} (port {port}) ===")
        record = run_one_binary(entry, port, config)
        records.append(record)

        # Save progress after each binary in case of crash.
        # Per-run progress file so concurrent benchmarks on the same day
        # don't clobber each other. The filename is derived from
        # --out-tag (preferred) or the process PID + port as fallback.
        progress_tag = args.out_tag or f"pid{os.getpid()}_port{args.port}"
        progress_path = LOGS_DIR / f"juliet_progress_{datetime.now().strftime('%Y%m%d')}_{progress_tag}.json"
        with open(progress_path, "w") as f:
            json.dump({"records": records}, f, indent=2)

    # Compute metrics + write final reports
    metrics = compute_metrics(records)

    print(f"\n{'='*70}")
    print(f"FINAL METRICS")
    print(f"{'='*70}")
    print(f"  Total binaries:     {metrics['total_binaries']}")
    print(f"  True positives:     {metrics['true_positives']}")
    print(f"  True negatives:     {metrics['true_negatives']}")
    print(f"  False positives:    {metrics['false_positives']}")
    print(f"  False negatives:    {metrics['false_negatives']}")
    print(f"  Unknown:            {metrics['unknown_verdicts']}")
    print(f"  Errors:             {metrics['errors']}")
    print(f"  Precision:          {metrics['precision']}")
    print(f"  Recall:             {metrics['recall']}")
    print(f"  F1:                 {metrics['f1']}")
    print(f"  Accuracy:           {metrics['accuracy']}")

    write_reports(
        records,
        metrics,
        len(sample),
        tag=args.out_tag,
        run_metadata=run_metadata,
    )


if __name__ == "__main__":
    main()
