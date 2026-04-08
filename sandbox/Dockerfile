# Agent-G binary-analysis sandbox image
#
# Runs the Ghidra HTTP server inside a locked-down container so untrusted
# binaries can be analyzed without risking the host. The image bundles:
#
#   - JDK 17 + Ghidra 12.0.2 PUBLIC (download URL provided as build arg)
#   - The OGhidraHeadlessServer.java post-script (read-only)
#   - A non-root `ghidra` user that owns nothing on the host
#
# The host caller is expected to bind-mount the binary as read-only at
# /sandbox/in/binary and consume the HTTP server on the port published by
# the docker run / docker-compose layer (default 8080).
#
# Network egress is denied by default; only localhost:8080 inside the
# container is exposed via the published port. The Ghidra HTTP server
# enforces bearer auth (see OGhidraHeadlessServer.java) — set
# AGENT_G_GHIDRA_AUTH_TOKEN at run time so the host client can connect.

FROM eclipse-temurin:17-jdk-jammy

ARG GHIDRA_VERSION=12.0.2
ARG GHIDRA_DATE=20240314
ARG GHIDRA_URL=https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VERSION}_build/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_DATE}.zip

# Minimal runtime deps. wget for the install, then purge it.
RUN apt-get update && apt-get install -y --no-install-recommends \
        wget unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Ghidra at /opt/ghidra
RUN wget -q -O /tmp/ghidra.zip "${GHIDRA_URL}" \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv /opt/ghidra_${GHIDRA_VERSION}_PUBLIC /opt/ghidra \
    && rm /tmp/ghidra.zip \
    && chmod +x /opt/ghidra/support/analyzeHeadless

# Non-root user
RUN useradd --system --create-home --uid 1500 ghidra
USER ghidra
WORKDIR /home/ghidra

# Drop the OGhidra script into a known location at build time. The host
# can also bind-mount its own scripts dir over /opt/agent-g-scripts at
# `docker run` time if it wants to update the post-script without rebuilding.
COPY --chown=ghidra:ghidra ghidra/scripts /opt/agent-g-scripts

# Volumes:
#   /sandbox/in   — host-side binary (RO)
#   /sandbox/work — temp Ghidra project workspace (RW, ephemeral)
VOLUME ["/sandbox/in", "/sandbox/work"]

EXPOSE 8080

# Default entrypoint runs the headless server on the configured port. The
# binary path inside the container is fixed at /sandbox/in/binary; the host
# bind-mounts whichever real binary it wants to analyze to that location.
ENV PORT=8080
ENV TEMP=/sandbox/work
ENV TMPDIR=/sandbox/work

ENTRYPOINT ["/bin/bash", "-c", "\
    mkdir -p /sandbox/work/proj && \
    /opt/ghidra/support/analyzeHeadless \
        /sandbox/work/proj SandboxProj \
        -import /sandbox/in/binary \
        -scriptPath /opt/agent-g-scripts \
        -postScript OGhidraHeadlessServer.java ${PORT} \
"]
