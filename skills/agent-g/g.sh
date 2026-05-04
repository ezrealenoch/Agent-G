#!/usr/bin/env bash
# g.sh — Tiny helper for querying Agent-G's provisioned Ghidra HTTP server.
#
# Reads URL + bearer token from ./ghidra_session.json (written by
# provision_ghidra.py in the same directory) and forwards the rest of the
# args as authenticated GET parameters.
#
# Usage:
#   ./g.sh plugin-version
#   ./g.sh imports offset=0 limit=50
#   ./g.sh strings filter=http limit=200
#   ./g.sh decompile_function address=0x180001000
#   ./g.sh xrefs_to address=0x180001000
#   ./g.sh searchFunctions query=main
#   ./g.sh read_bytes address=0x180001000 length=64 format=hex
#
# Environment overrides:
#   AGENT_G_SESSION_FILE   — path to a non-default ghidra_session.json
set -e

# Find the session file: env var > current working dir > script's own dir.
SESS="${AGENT_G_SESSION_FILE:-}"
if [ -z "$SESS" ]; then
    if [ -f "$(pwd)/ghidra_session.json" ]; then
        SESS="$(pwd)/ghidra_session.json"
    else
        SESS="$(dirname "$0")/ghidra_session.json"
    fi
fi

if [ ! -f "$SESS" ]; then
    cat >&2 <<EOF
ERROR: ghidra_session.json not found at $SESS

The provisioner is not running, or you ran g.sh from the wrong directory.
Start a Ghidra instance first:

    python "\$(dirname "\$0")/provision_ghidra.py" "/path/to/binary" &

Then wait for ghidra_session.json to appear before running g.sh.
EOF
    exit 2
fi

URL=$(python -c "import json,sys; print(json.load(open(r'$SESS'))['base_url'])")
TOK=$(python -c "import json,sys; print(json.load(open(r'$SESS'))['auth_token'])")

ENDPOINT="${1:-}"
shift || true

if [ -z "$ENDPOINT" ] || [ "$ENDPOINT" = "--help" ] || [ "$ENDPOINT" = "-h" ]; then
    cat <<EOF
Usage: g.sh <endpoint> [k=v ...]

Common endpoints:
  plugin-version
  imports                     [offset=N] [limit=N]
  exports                     [offset=N] [limit=N]
  segments
  strings                     [offset=N] [limit=N] [filter=substr]
  list_functions              [offset=N] [limit=N]
  searchFunctions             query=<name> [offset=N] [limit=N]
  decompile_function          address=0x...
  disassemble_function        address=0x...
  xrefs_to / xrefs_from       address=0x... [offset=N] [limit=N]
  function_xrefs              name=<name> [offset=N] [limit=N]
  get_function_by_address     address=0x...
  read_bytes                  address=0x... length=N [format=hex|ascii|raw]

Session: $SESS
URL    : $URL
EOF
    exit 0
fi

QS=""
for kv in "$@"; do
    if [ -n "$QS" ]; then QS="$QS&$kv"; else QS="$kv"; fi
done

if [ -n "$QS" ]; then
    exec curl -sS --max-time 120 -H "Authorization: Bearer $TOK" "$URL/$ENDPOINT?$QS"
else
    exec curl -sS --max-time 120 -H "Authorization: Bearer $TOK" "$URL/$ENDPOINT"
fi
