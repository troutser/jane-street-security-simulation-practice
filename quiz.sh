#!/usr/bin/env bash
# Interactive self-check: prompts you for each question in questions.md and
# grades your answer against answers.md WITHOUT showing the answer, the
# pipeline, or the explanation up front. Type '?' on any question to reveal
# just that answer, or 'skip' to move on without seeing it.
#
# Safe to call from inside a scenarios/run-*/ directory, from a shell opened
# by practice.sh, or from the security-sim-practice/ root (falls back to the
# most recently generated run).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

find_scenario_dir() {
    if [ -f "./questions.md" ] && [ -f "./answers.md" ]; then
        echo "$(pwd)"
        return 0
    fi
    if [ -n "${SECURITY_SIM_SCENARIO:-}" ] && [ -f "${SECURITY_SIM_SCENARIO}/questions.md" ] \
        && [ -f "${SECURITY_SIM_SCENARIO}/answers.md" ]; then
        echo "$SECURITY_SIM_SCENARIO"
        return 0
    fi
    if [ -f "$ROOT/scenarios/.latest" ]; then
        LATEST="$(cat "$ROOT/scenarios/.latest")"
        if [ -f "$ROOT/scenarios/$LATEST/questions.md" ] && [ -f "$ROOT/scenarios/$LATEST/answers.md" ]; then
            echo "$ROOT/scenarios/$LATEST"
            return 0
        fi
    fi
    return 1
}

TARGET=""
if ! TARGET="$(find_scenario_dir)"; then
    echo "Couldn't find questions.md/answers.md for the current scenario. Run ./practice.sh (or generate.py) first." >&2
    exit 1
fi

QFILE="$TARGET/questions.md"
AFILE="$TARGET/answers.md"

mapfile -t QUESTIONS < <(grep -oP '^\d+\.\s+\K.*' "$QFILE")
mapfile -t ANSWERS   < <(grep -oP '\*\*Answer:\*\*\s+`\K[^`]*' "$AFILE")

if [ "${#QUESTIONS[@]}" -eq 0 ] || [ "${#QUESTIONS[@]}" -ne "${#ANSWERS[@]}" ]; then
    echo "Couldn't line up questions.md and answers.md cleanly -- falling back to check.sh." >&2
    exec "$ROOT/check.sh"
fi

norm() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
}

score=0
total="${#QUESTIONS[@]}"

echo "================================================================"
echo " Self-check -- $(basename "$TARGET")"
echo " Answer each question. '?' reveals just that answer, 'skip' moves"
echo " on without seeing it. Full pipelines/explanations stay hidden --"
echo " run check.sh afterward for those."
echo "================================================================"

for i in "${!QUESTIONS[@]}"; do
    n=$((i + 1))
    q="${QUESTIONS[$i]}"
    a="${ANSWERS[$i]}"
    echo
    echo "Q$n. $q"
    while true; do
        if ! read -r -p "> " guess; then
            echo
            guess="skip"
        fi
        case "$guess" in
            "?"|"help")
                echo "  Answer: $a"
                break
                ;;
            "skip")
                echo "  Skipped. Answer: $a"
                break
                ;;
            "quit"|"exit")
                echo
                echo "Stopped early at $score/$n scored so far."
                exit 0
                ;;
            *)
                if [ "$(norm "$guess")" = "$(norm "$a")" ]; then
                    echo "  Correct!"
                    score=$((score + 1))
                    break
                else
                    echo "  Not quite -- try again ('?' for the answer, 'skip' to move on)."
                fi
                ;;
        esac
    done
done

echo
echo "================================================================"
echo " Score: $score / $total"
echo "================================================================"
echo "Run $ROOT/check.sh for the full pipelines + explanations."
