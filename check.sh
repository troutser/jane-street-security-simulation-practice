#!/usr/bin/env bash
# Reveals answers.md for the CURRENT scenario only. Safe to call from inside a
# scenarios/run-*/ directory, from a shell opened by practice.sh, or from the
# security-sim-practice/ root (falls back to the most recently generated run).
set -euo pipefail

TARGET=""
if [ -f "./answers.md" ]; then
    TARGET="./answers.md"
elif [ -n "${SECURITY_SIM_SCENARIO:-}" ] && [ -f "${SECURITY_SIM_SCENARIO}/answers.md" ]; then
    TARGET="${SECURITY_SIM_SCENARIO}/answers.md"
else
    ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [ -f "$ROOT/scenarios/.latest" ]; then
        LATEST="$(cat "$ROOT/scenarios/.latest")"
        if [ -f "$ROOT/scenarios/$LATEST/answers.md" ]; then
            TARGET="$ROOT/scenarios/$LATEST/answers.md"
        fi
    fi
fi

if [ -z "$TARGET" ]; then
    echo "Couldn't find an answers.md for the current scenario. Run ./practice.sh (or generate.py) first." >&2
    exit 1
fi

if [ -t 1 ]; then
    less "$TARGET"
else
    cat "$TARGET"
fi
