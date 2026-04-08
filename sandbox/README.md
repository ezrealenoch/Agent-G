# Agent-G binary sandbox

This directory contains the **Docker-based binary analysis sandbox** for
Agent-G. Use it whenever you analyze a binary you don't fully trust.

## Threat model

Agent-G's host process *itself* is trusted (it's your code). The thing that
needs sandboxing is **the binary being analyzed**, because:

- Ghidra is pure Java and never executes the analyzed binary, **but** it
  parses arbitrary binary formats which is a historically rich source of
  parser RCE bugs.
- The post-analysis scripts run inside Ghidra's JVM with full filesystem
  and network access on the host by default.
- Even if Ghidra never crashes, an LLM with bad output may cause the
  agent to issue file-system or network operations the user didn't intend.

The sandbox addresses these by running the entire Ghidra HTTP server
inside a container with:

| Defense | Mechanism |
|---|---|
| Filesystem write isolation | `read_only: true` rootfs + tmpfs for `/tmp` and the Ghidra workspace |
| No host source binary leakage | Binary mounted **read-only** at `/sandbox/in/binary` |
| No host workspace persistence | tmpfs for `/sandbox/work`, never touches host disk |
| Dropped capabilities | `cap_drop: [ALL]` — Ghidra is pure Java, needs none |
| `no_new_privs` | Set on the security_opt |
| PID + memory + CPU caps | `pids_limit: 256`, `mem_limit: 4g`, `cpus: 2.0` |
| Network isolation | Default bridge network; only the inbound 8080 → host 18080 mapping |
| Bearer auth on HTTP API | `AGENT_G_GHIDRA_AUTH_TOKEN` enforced by `OGhidraHeadlessServer.java` |
| Non-root JVM | `USER ghidra` (uid 1500) |

## Quick start

```bash
# Generate a fresh auth token
export AGENT_G_GHIDRA_AUTH_TOKEN=$(openssl rand -base64 32)

# Pick a binary to analyze
export AGENT_G_BINARY=/path/to/untrusted/binary

# Build + start the sandbox
docker compose -f sandbox/docker-compose.yml up --build -d

# Wait for ready
curl -H "Authorization: Bearer $AGENT_G_GHIDRA_AUTH_TOKEN" \
     http://localhost:18080/health

# Connect Agent-G client to the sandboxed Ghidra
GHIDRA_BASE_URL=http://localhost:18080 \
AGENT_G_GHIDRA_AUTH_TOKEN=$AGENT_G_GHIDRA_AUTH_TOKEN \
python -m agent_g analyze ...

# Tear down
docker compose -f sandbox/docker-compose.yml down
```

## What's NOT in this sandbox

- The LLM client itself runs on the **host**, outside the sandbox. The
  sandbox only protects the binary parsing surface. Calls to Anthropic /
  Google / OpenAI / Ollama still go through the normal `external_client`
  / `ollama_client` paths and use the normal API keys.
- Egress filtering is at the docker-network level only. If you need
  stricter outbound rules (e.g. block DNS resolution from inside the
  container), wrap the docker-compose with a firewalld / nftables policy
  on the host bridge interface.
- The sandbox does not jail the LLM's tool-call decisions. If the agent
  asks the host to write a file, the host's `tool_runner` runs that
  request with normal host privileges. If you need to defang specific
  tool calls (e.g. block file writes outside a workspace), use the
  upcoming production `ContentFilter` framework (replaces the
  benchmark-only `LeakFilter`).

## Future hardening

- Drop network isolation to "none" mode and proxy the HTTP server via a
  Unix socket bind-mounted from the host
- Add seccomp profile to block `ptrace` / `personality` / etc.
- Switch to gVisor / Firecracker for kernel isolation if attacking JVM
  parsers becomes a real threat
