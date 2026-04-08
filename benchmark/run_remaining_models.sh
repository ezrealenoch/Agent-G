#!/usr/bin/env bash
# Sequential orchestrator for the Agent-G batch of new-30 runs.
#
# Run order (Flash Lite SKIPPED — Google preview endpoint returning 503s):
#   1. gemma4:e4b (local)             — new30 (num_predict-bumped)
#   2. Gemini 3.1 Pro Preview         — new30 (Google, watch 250/day)
#
# Flash Lite will be retried separately once Google's preview capacity
# recovers. Ollama cloud models (gemma4:31b-cloud, qwen3.5:397b-cloud)
# remain SKIPPED due to rate limits.
#
# Each run blocks the next, so we never have concurrent Ollama traffic
# and the local num_predict bump for e4b gets a clean shot.

set -e
cd C:/Users/Era/Desktop/OGhidra/Agent-G

ENV_BACKUP=.env.backup_orchestrator_v2
cp .env "$ENV_BACKUP" 2>/dev/null || true

write_env_ollama() {
    local model="$1"
    cat > .env <<EOF
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=$model
OLLAMA_TIMEOUT=600
OLLAMA_NUM_PARALLEL=1
GHIDRA_INSTALL_DIR=C:\\Users\\Era\\Desktop\\OGhidra\\ghidra_12.0.2_PUBLIC
EOF
}

write_env_gemini_pro() {
    cat > .env <<EOF
LLM_PROVIDER=external
EXTERNAL_PROVIDER=google
EXTERNAL_MODEL=gemini-3.1-pro-preview
EXTERNAL_API_KEY=REDACTED_SET_GOOGLE_API_KEY_ENV_VAR
GOOGLE_API_KEY=REDACTED_SET_GOOGLE_API_KEY_ENV_VAR
GOOGLE_MODEL=gemini-3.1-pro-preview
EXTERNAL_TIMEOUT=600
GHIDRA_INSTALL_DIR=C:\\Users\\Era\\Desktop\\OGhidra\\ghidra_12.0.2_PUBLIC
EOF
}

CWES="CWE-121,CWE-122,CWE-415,CWE-416,CWE-476,CWE-78,CWE-134,CWE-190,CWE-369,CWE-457"

echo "=== [1/2] gemma4:e4b (local, num_predict-bumped via thinking registry) ==="
write_env_ollama gemma4:e4b
python -u scripts/test_juliet.py \
    --only-ids logs/new_corpus_30_ids.txt --cwes "$CWES" \
    --port 22000 --out-tag gemma4e4b_new30_v2 \
    --model-name "gemma4:e4b (local)" --deployment "local · small open weight" \
    --corpus-label new30 \
    --notes "OLLAMA_NUM_PARALLEL=1, num_predict auto-bumped via thinking_models registry (capacity fix, not reasoning config)" \
    > logs/gemma4e4b_new30_v2.out 2>&1
echo "  done -> logs/gemma4e4b_new30_v2.out"

echo
echo "=== [2/2] Gemini 3.1 Pro Preview (Google, watch 250/day quota) ==="
write_env_gemini_pro
python -u scripts/test_juliet.py \
    --only-ids logs/new_corpus_30_ids.txt --cwes "$CWES" \
    --port 22300 --out-tag geminipro_new30_v2 \
    --model-name "Gemini 3.1 Pro Preview" --deployment "cloud · flagship · thinking model" \
    --corpus-label new30 \
    --notes "New-30 run with full ExternalClient patch set (thinkingConfig=-1, functionCallingConfig=NONE, empty-response retry)" \
    > logs/geminipro_new30_v2.out 2>&1
echo "  done -> logs/geminipro_new30_v2.out"

# Restore original .env
cp "$ENV_BACKUP" .env

echo
echo "=== ALL RUNS COMPLETE ==="
ls -la logs/juliet_test_*_v2*.json 2>/dev/null
