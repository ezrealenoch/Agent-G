# Ghidra Scripts for Agent-G

These files run **inside Ghidra's JVM** via the `analyzeHeadless` CLI tool. They are NOT standalone Java programs.

## Requirements

- **Ghidra 11.3+** (tested with 12.0.2)
- **Java 17+** (Temurin recommended)
- Ghidra installation referenced at: `C:\Users\Era\Desktop\OGhidra\ghidra_12.0.2_PUBLIC`

## How It Works

Agent-G's `headless_launcher.py` automatically:
1. Locates your Ghidra installation (via `GHIDRA_INSTALL_DIR` env var or auto-detection)
2. Runs `analyzeHeadless` to import and auto-analyze the target binary
3. Executes `OGhidraHeadlessServer.java` as a post-analysis script
4. The script starts an HTTP server (same API as the OGhidraMCP GUI plugin)
5. Agent-G's Python side connects to this HTTP server for all analysis

## Files

- `scripts/OGhidraHeadlessServer.java` — HTTP server script (ported from OGhidraMCP plugin)

## Origin

The HTTP server endpoints are ported from the OGhidraMCP plugin:
`OGhidra-Leads-Production-External/OGhidraMCP/src/main/java/com/lauriewired/GhidraMCPPlugin.java`

Original GhidraMCP by LaurieWired: https://github.com/LaurieWired/GhidraMCP
