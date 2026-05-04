#!/usr/bin/env bash
# Install Agent-G + Claude Code skill on this machine.
#   - pip install -e . (so the `agent-g` CLI is on PATH)
#   - link skills/agent-g/ into ~/.claude/skills/agent-g/ so Claude Code sees it
#   - export AGENT_G_HOME hint for the skill's helper scripts
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL_SRC="$REPO_DIR/skills/agent-g"
SKILL_DST="$HOME/.claude/skills/agent-g"

echo "[agent-g] installing CLI (force-reinstall to refresh stale copies)..."
python -m pip install --force-reinstall --no-deps -e "$REPO_DIR"

echo "[agent-g] linking skill into $SKILL_DST"
mkdir -p "$HOME/.claude/skills"
if [ -e "$SKILL_DST" ] || [ -L "$SKILL_DST" ]; then
    echo "[agent-g] $SKILL_DST already exists - removing it"
    rm -rf "$SKILL_DST"
fi
if ln -s "$SKILL_SRC" "$SKILL_DST" 2>/dev/null; then
    echo "[agent-g] linked"
else
    echo "[agent-g] symlink failed (likely permissions) - copying instead"
    cp -r "$SKILL_SRC" "$SKILL_DST"
fi

# Make the bash helper executable
chmod +x "$SKILL_SRC/g.sh" 2>/dev/null || true

# Offer an AGENT_G_HOME hint via shell profile (idempotent)
PROFILE=""
if [ -n "${BASH_VERSION:-}" ] && [ -f "$HOME/.bashrc" ]; then
    PROFILE="$HOME/.bashrc"
elif [ -n "${ZSH_VERSION:-}" ] && [ -f "$HOME/.zshrc" ]; then
    PROFILE="$HOME/.zshrc"
elif [ -f "$HOME/.profile" ]; then
    PROFILE="$HOME/.profile"
fi
if [ -n "$PROFILE" ]; then
    if ! grep -q "AGENT_G_HOME=" "$PROFILE" 2>/dev/null; then
        echo "" >> "$PROFILE"
        echo "# Added by Agent-G install.sh" >> "$PROFILE"
        echo "export AGENT_G_HOME=\"$REPO_DIR\"" >> "$PROFILE"
        echo "[agent-g] added AGENT_G_HOME export to $PROFILE"
        echo "[agent-g] (run 'source $PROFILE' or open a new shell to pick it up)"
    else
        echo "[agent-g] AGENT_G_HOME already in $PROFILE - skipping"
    fi
fi

echo "[agent-g] verifying CLI..."
if agent-g --version > /dev/null 2>&1; then
    echo "[agent-g] OK: $(agent-g --version)"
else
    echo "[agent-g] WARNING: 'agent-g' is not on PATH. Make sure your pip bin dir is in PATH."
fi

echo
echo "[agent-g] Done. Restart Claude Code and the 'agent-g' skill will be available."
echo "[agent-g] Try: claude  ->  'investigate /path/to/some/binary'"
echo "[agent-g] Or for the internal-LLM CLI mode: agent-g doctor && agent-g analyze /path/to/binary"
