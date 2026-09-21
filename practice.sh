#!/usr/bin/env bash
# Generates a new scenario and drops you into its directory.
# Usage: ./practice.sh [--easy|--medium|--hard|--insane] [--seed N]
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PYTHON=python3
command -v python3 >/dev/null 2>&1 || PYTHON=python

"$PYTHON" generate.py "$@"

LATEST="$(cat scenarios/.latest)"
SCEN_DIR="$ROOT/scenarios/$LATEST"
cd "$SCEN_DIR"

echo
echo "================================================================"
echo " Scenario ready: $LATEST"
echo "================================================================"
cat briefing.md
echo
echo "----------------------------------------------------------------"
echo "questions.md has your investigative questions. Use grep/less/pipes on"
echo "auth.log, access.log, firewall.log, dns.log, exec.log, endpoint.log in this directory."
echo
echo "Tip: open one of the logs in 'less' first (e.g. 'less auth.log', then"
echo "/pattern to search, n/N to jump matches) before reaching for grep --"
echo "less is explicitly a required tool for this interview, easy to skip"
echo "past if grep pipelines always do the job."
echo
echo "Run:  $ROOT/quiz.sh      to self-check your answers one at a time (no spoilers)."
echo "Run:  $ROOT/check.sh     when you want the full answer key for THIS scenario."
echo "Type: exit               to leave this scenario shell."
echo "----------------------------------------------------------------"

export SECURITY_SIM_ROOT="$ROOT"
export SECURITY_SIM_SCENARIO="$SCEN_DIR"
export PS1="(sim:$LATEST) \w\$ "

exec "${SHELL:-bash}"
