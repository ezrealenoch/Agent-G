#!/usr/bin/env python3
"""Data-leak verification for a Juliet test corpus.

For every binary in an ID list, launch headless Ghidra with the JulietAnonymizer
+ OGhidraHeadlessServer, then scan /exports, /strings, /symbols for giveaway
tokens that would leak ground truth into the agent's context.

Usage:
    python scripts/verify_corpus_leaks.py --ids logs/new_corpus_30_ids.txt
"""
import argparse, json, re, subprocess, sys, tempfile, threading, time, random
from pathlib import Path
import httpx, ijson

AGENT_G = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(AGENT_G))
from benchmark.leak_filter import LeakFilter  # noqa: E402
GHIDRA = Path(os.environ.get("GHIDRA_INSTALL_DIR", ""))
_candidates = [
    GHIDRA / "support" / "analyzeHeadless.bat",
    GHIDRA / "support" / "analyzeHeadless",
]
HEADLESS = next((c for c in _candidates if c.exists()), _candidates[0])
SCRIPT_DIR = AGENT_G / "ghidra" / "scripts"
BENCH_SCRIPT_DIR = AGENT_G / "benchmark" / "ghidra"
JULIET_ROOT = Path(os.environ.get(
    "JULIET_CORPUS_ROOT",
    str(Path.home() / "juliet-corpus"),
))
MANIFEST = JULIET_ROOT / "manifest_juliet_full.json"
LOGS = AGENT_G / "logs"

# Tokens that should NEVER appear in exports/strings/symbols after anonymization
LEAK_TOKENS = [
    r"(?i)\bcwe[-_]?\d+\b",           # "CWE121", "cwe-121"
    r"(?i)juliet",
    r"(?i)\bbad\d*\b",                 # "bad", "bad1", "bad2"
    r"(?i)\bgood[GB]?\d*\b",           # "good", "goodG2B", "goodB2G"
    r"(?i)stack_based",
    r"(?i)heap_based",
    r"(?i)use_after_free",
    r"(?i)null_pointer",
    r"(?i)double_free",
    r"(?i)divide_by_zero",
    r"(?i)os_command_injection",
    r"(?i)format_string",
    r"(?i)integer_overflow",
    r"(?i)uninitialized",
    r"(?i)printLine",
    r"(?i)printIntLine",
    r"(?i)printStruct",
    r"(?i)decodeHex",
    r"(?i)globalReturns",
    r"(?i)__attribute__\(\(used\)\).*bad",
]
COMPILED = [re.compile(p) for p in LEAK_TOKENS]

def scan(text: str):
    hits = []
    for p in COMPILED:
        for m in p.finditer(text):
            hits.append(m.group(0))
    return hits

def launch(bin_path: Path, port: int):
    import os as _os
    tmp = tempfile.mkdtemp(prefix="leakchk_")
    script_path_arg = f"{SCRIPT_DIR}{_os.pathsep}{BENCH_SCRIPT_DIR}"
    cmd = [str(HEADLESS), tmp, "LeakChk",
           "-import", str(bin_path),
           "-scriptPath", script_path_arg,
           "-postScript", "JulietAnonymizer.java",
           "-postScript", "OGhidraHeadlessServer.java", str(port)]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    threading.Thread(target=lambda: [None for _ in p.stdout], daemon=True).start()
    return p, tmp

def wait_ready(port, timeout=120):
    t0 = time.time()
    while time.time() - t0 < timeout:
        try:
            r = httpx.get(f"http://localhost:{port}/health", timeout=2)
            if r.status_code == 200 and "ready" in r.text: return True
        except: pass
        time.sleep(2)
    return False

def shutdown(port, proc, tmp):
    try: httpx.post(f"http://localhost:{port}/shutdown", timeout=5)
    except: pass
    try: proc.wait(timeout=15)
    except: proc.kill(); proc.wait(timeout=5)
    import shutil; shutil.rmtree(tmp, ignore_errors=True)

def pull_text(port, endpoint):
    try:
        return httpx.get(f"http://localhost:{port}{endpoint}", timeout=15).text
    except Exception as e:
        return f"__ERROR__ {e}"

def check_one(bin_path: Path, port: int, verbose=False):
    proc, tmp = launch(bin_path, port)
    result = {"binary": bin_path.name, "ready": False, "sections": {}, "leak_counts": {}, "total_leaks": 0}
    try:
        if not wait_ready(port):
            result["error"] = "not ready"; return result
        result["ready"] = True
        for name, ep in [
            ("exports", "/exports?offset=0&limit=500"),
            ("imports", "/imports?offset=0&limit=500"),
            ("strings", "/strings?offset=0&limit=1000"),
            ("symbols", "/symbols?offset=0&limit=500"),
            ("segments","/segments"),
        ]:
            txt = pull_text(port, ep)
            # Apply the same LeakFilter that wraps the agent's tool runner at
            # runtime so we measure what the model actually sees.
            if name == "strings":
                txt = LeakFilter._filter_strings(txt)
            hits = scan(txt)
            result["sections"][name] = {"chars": len(txt), "sample": txt[:300] if verbose else ""}
            result["leak_counts"][name] = len(hits)
            result["total_leaks"] += len(hits)
            if verbose and hits:
                result["sections"][name]["leak_samples"] = list(set(hits))[:10]
    finally:
        shutdown(port, proc, tmp)
    return result

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ids", required=True)
    ap.add_argument("--port", type=int, default=19500)
    ap.add_argument("--audit", type=int, default=5, help="Verbose manual-audit count")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    ids = [l.strip() for l in Path(args.ids).read_text().splitlines() if l.strip()]
    # Resolve id -> path via manifest
    id_to_path = {}
    with open(MANIFEST, "rb") as f:
        for e in ijson.items(f, "samples.item"):
            if e["id"] in set(ids):
                id_to_path[e["id"]] = JULIET_ROOT / e["path"]
    missing = [i for i in ids if i not in id_to_path]
    if missing:
        print(f"MISSING from manifest: {missing}"); sys.exit(1)

    random.seed(42)
    audit_ids = set(random.sample(ids, min(args.audit, len(ids))))

    results = []
    for i, bid in enumerate(ids, 1):
        port = args.port + i
        verbose = bid in audit_ids
        print(f"[{i:2d}/{len(ids)}] {bid[:70]}  (audit={verbose})")
        r = check_one(id_to_path[bid], port, verbose=verbose)
        r["id"] = bid
        r["audit"] = verbose
        print(f"      ready={r['ready']} leaks={r['total_leaks']} {r['leak_counts']}")
        results.append(r)

    summary = {
        "total": len(results),
        "ready": sum(1 for r in results if r["ready"]),
        "clean": sum(1 for r in results if r["total_leaks"] == 0),
        "with_leaks": [r["id"] for r in results if r["total_leaks"] > 0],
        "audited": sorted(audit_ids),
    }
    out = args.out or str(LOGS / "leak_verification.json")
    json.dump({"summary": summary, "results": results}, open(out, "w"), indent=2)
    print(f"\n=== SUMMARY ===")
    print(f"  total:      {summary['total']}")
    print(f"  ready:      {summary['ready']}")
    print(f"  clean:      {summary['clean']}")
    print(f"  with leaks: {len(summary['with_leaks'])}")
    if summary["with_leaks"]:
        print("  LEAKING BINARIES:")
        for bid in summary["with_leaks"]:
            print(f"    - {bid}")
    print(f"\nReport: {out}")

if __name__ == "__main__":
    main()
