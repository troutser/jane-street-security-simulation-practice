#!/usr/bin/env bash
# Interactive self-check: prompts you for each question in questions.md and
# grades your answer against answers.md WITHOUT showing the command pipeline
# up front. Type '?' on any question to reveal just that answer, or 'skip' to
# move on without seeing it.
#
# After each question, prints the one-line "why it matters" explanation (but
# not the pipeline) -- rehearse saying your own reasoning out loud BEFORE
# reading it, since the actual interview is about explaining your thought
# process, not just stating a fact.
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

QUESTIONS=()
while IFS= read -r line; do
    if [[ "$line" =~ ^[0-9]+\.[[:space:]]+(.*)$ ]]; then
        QUESTIONS+=("${BASH_REMATCH[1]}")
    fi
done < "$QFILE"

ANSWERS=()
ans_re='\*\*Answer:\*\*[[:space:]]+`([^`]*)`'
while IFS= read -r line; do
    if [[ "$line" =~ $ans_re ]]; then
        ANSWERS+=("${BASH_REMATCH[1]}")
    fi
done < "$AFILE"

EXPLANATIONS=()
expl_re='\*\*Why these flags:\*\*[[:space:]]+(.*)$'
while IFS= read -r line; do
    if [[ "$line" =~ $expl_re ]]; then
        EXPLANATIONS+=("${BASH_REMATCH[1]}")
    fi
done < "$AFILE"

if [ "${#QUESTIONS[@]}" -eq 0 ] || [ "${#QUESTIONS[@]}" -ne "${#ANSWERS[@]}" ] \
    || [ "${#QUESTIONS[@]}" -ne "${#EXPLANATIONS[@]}" ]; then
    echo "Couldn't line up questions.md and answers.md cleanly -- falling back to check.sh." >&2
    exec "$ROOT/check.sh"
fi

norm() {
    printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//'
}

# Some answers are compound, e.g. "192.0.2.14 (342 requests)". Echo the full
# answer plus, when it matches that "X (Y ...)" shape, the head alone (X) and
# any bare number found inside the parens (Y) -- so typing just the IP or
# just the count still counts as correct instead of only the exact string.
paren_re='^(.+) \(([^)]*)\)[[:space:]]*$'
num_re='([0-9]+)'

answer_variants() {
    local a="$1"
    printf '%s\n' "$a"
    if [[ "$a" =~ $paren_re ]]; then
        local head="${BASH_REMATCH[1]}"
        local paren="${BASH_REMATCH[2]}"
        printf '%s\n' "$head"
        if [[ "$paren" =~ $num_re ]]; then
            printf '%s\n' "${BASH_REMATCH[1]}"
        fi
    fi
}

answer_matches() {
    local guess="$1" answer="$2" guess_n variant
    guess_n="$(norm "$guess")"
    while IFS= read -r variant; do
        if [ "$guess_n" = "$(norm "$variant")" ]; then
            return 0
        fi
    done < <(answer_variants "$answer")
    return 1
}

score=0
total="${#QUESTIONS[@]}"

echo "================================================================"
echo " Self-check -- $(basename "$TARGET")"
echo " Answer each question. '?' reveals just that answer, 'skip' moves"
echo " on without seeing it. The exact pipeline stays hidden -- run"
echo " check.sh afterward for that."
echo
echo " Tip: before you type an answer, say out loud (or jot down) which"
echo " pipeline you'd use and why. The real interview is about explaining"
echo " your reasoning to an engineer, not just producing the right fact."
echo "================================================================"

for i in "${!QUESTIONS[@]}"; do
    n=$((i + 1))
    q="${QUESTIONS[$i]}"
    a="${ANSWERS[$i]}"
    why="${EXPLANATIONS[$i]}"
    echo
    echo "Q$n. $q"
    resolved=""
    while true; do
        if ! read -r -p "> " guess; then
            echo
            guess="skip"
        fi
        case "$guess" in
            "?"|"help")
                echo "  Answer: $a"
                resolved="revealed"
                break
                ;;
            "skip")
                echo "  Skipped. Answer: $a"
                resolved="skipped"
                break
                ;;
            "quit"|"exit")
                echo
                echo "Stopped early at $score/$n scored so far."
                exit 0
                ;;
            *)
                if answer_matches "$guess" "$a"; then
                    echo "  Correct!"
                    score=$((score + 1))
                    resolved="correct"
                    break
                else
                    echo "  Not quite -- try again ('?' for the answer, 'skip' to move on)."
                fi
                ;;
        esac
    done
    echo "  Why it matters: $why"
done

echo
echo "================================================================"
echo " Score: $score / $total"
echo "================================================================"
echo "Run $ROOT/check.sh for the full pipelines + explanations."
echo
echo "Follow-up practice -- rehearse answering these out loud for each"
echo "question above, the way you would with an engineer watching:"
echo "  - How would you confirm this isn't a false positive?"
echo "  - What would you check next if this were a live incident?"
echo "  - How would you summarize this finding for a non-technical stakeholder?"
