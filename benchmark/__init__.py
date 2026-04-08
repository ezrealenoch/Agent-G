"""Benchmark-only code. Not imported by production Agent-G deployments.

Contents:
  - test_juliet.py           — Juliet vulnerability benchmark harness
  - verify_corpus_leaks.py   — pre-run leak audit for the Juliet corpus
  - ghidra_oneshot.py        — single-binary Ghidra lifecycle helper (blind sub-agents)
  - build_html_report.py     — HTML comparison report builder
  - leak_filter.py           — Juliet-scaffold content filter (wraps tool runner)
  - ghidra/JulietAnonymizer.java — Ghidra post-script to strip Juliet symbols
  - run_remaining_models.sh  — sequential orchestrator for multi-model runs
"""
