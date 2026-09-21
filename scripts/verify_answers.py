#!/usr/bin/env python3
"""
Answer-key verifier. For a range of seeds/difficulties, builds a scenario in
memory, writes its logs to a scratch dir, then actually RUNS each question's
documented `cmd` pipeline against those logs via bash and checks the output
matches the declared `a`. This is the ground-truth check that the generator's
claimed answers are what the pipeline really produces -- not just "look right".

Usage:
  python3 scripts/verify_answers.py [--n N] [--start-seed N] [--difficulties easy,medium,hard] [--keep-failures]
"""
import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from generate import build_scenario, LOG_NAMES

BASH = shutil.which("bash") or "bash"

paren_re = re.compile(r'^(.+) \(([^)]*)\)\s*$')
num_re = re.compile(r'([0-9]+)')


def norm(s):
    return s.strip().lower()


def answer_variants(a):
    variants = [a]
    m = paren_re.match(a)
    if m:
        head, paren = m.group(1), m.group(2)
        variants.append(head)
        nm = num_re.search(paren)
        if nm:
            variants.append(nm.group(1))
    return variants


def outputs_match(actual, expected, cmd):
    actual_n = norm(actual)
    variants = answer_variants(expected)
    for v in variants:
        if actual_n == norm(v):
            return True
    # also allow the actual output to be a newline-joined multi-line answer
    # (e.g. "-l" filename lists) matched line-by-line, order-insensitive
    if "\n" in actual or "," in expected:
        actual_lines = sorted(x.strip() for x in actual.splitlines() if x.strip())
        expected_lines = sorted(x.strip() for x in re.split(r',\s*', expected) if x.strip())
        if actual_lines and [norm(x) for x in actual_lines] == [norm(x) for x in expected_lines]:
            return True

    first_line = actual.splitlines()[0].strip() if actual.splitlines() else ""

    # ranking pipelines ("... | sort | uniq -c | sort -rn | head[-1]") print
    # "<count> <token>" -- the real thing under test is whether the CLAIMED
    # winner is actually the top-ranked token, so compare against the last
    # whitespace field of the top line.
    if re.search(r'sort\s+-rn\s*\|\s*head', cmd) or re.search(r"uniq -c.*sort -rn", cmd):
        top_token = first_line.split()[-1] if first_line.split() else ""
        for v in variants:
            if norm(top_token) == norm(v):
                return True

    # commands that end by echoing whole matching log line(s) (no final -o/awk
    # extraction) -- the human reads the field off the line. Accept if the
    # expected value appears as a distinct token somewhere in the output.
    # Length guard against coincidental substring hits from short values (a bare
    # count/port/status like "3" or "200" showing up in an unrelated field);
    # 4+ chars (incl. 4-digit-plus numeric fields like a PID) is specific enough
    # that a real word-boundary match is meaningful.
    for v in variants:
        if len(v) >= 4:
            pattern = r'(?<![\w.])' + re.escape(v) + r'(?![\w.])'
            if re.search(pattern, actual, re.I):
                return True
    return False


def run_scenario(difficulty, seed, keep_failures, tmproot):
    scn = build_scenario(difficulty, seed)
    scen_dir = os.path.join(tmproot, f"{difficulty}-{seed}")
    os.makedirs(scen_dir, exist_ok=True)
    for name in LOG_NAMES:
        with open(os.path.join(scen_dir, f"{name}.log"), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(scn["log_texts"][name]) + "\n")

    failures = []
    for i, q in enumerate(scn["questions"], 1):
        cmd = q["cmd"]
        expected = q["a"]
        try:
            proc = subprocess.run([BASH, "-c", cmd], cwd=scen_dir, capture_output=True,
                                   text=True, timeout=30)
        except subprocess.TimeoutExpired:
            failures.append((i, q, "TIMEOUT", ""))
            continue
        actual = proc.stdout.strip()
        if not outputs_match(actual, expected, cmd):
            failures.append((i, q, actual, proc.stderr.strip()))

    if failures:
        print(f"\n=== FAIL difficulty={difficulty} seed={seed} source={scn['ctx'].seed} "
              f"featured={[r['key'] for r in scn['featured']]} ===")
        for i, q, actual, err in failures:
            print(f"  Q{i}: {q['q'][:90]}")
            print(f"    cmd:      {q['cmd']}")
            print(f"    expected: {q['a']!r}")
            print(f"    actual:   {actual!r}")
            if err:
                print(f"    stderr:   {err!r}")
        if not keep_failures:
            shutil.rmtree(scen_dir, ignore_errors=True)
        else:
            print(f"    (scenario kept at {scen_dir})")
    else:
        shutil.rmtree(scen_dir, ignore_errors=True)

    return len(failures)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=40, help="scenarios per difficulty")
    ap.add_argument("--start-seed", type=int, default=1)
    ap.add_argument("--difficulties", default="easy,medium,hard")
    ap.add_argument("--keep-failures", action="store_true")
    args = ap.parse_args()

    tmproot = tempfile.mkdtemp(prefix="verify_answers_")
    total = 0
    total_failures = 0
    try:
        for difficulty in args.difficulties.split(","):
            for seed in range(args.start_seed, args.start_seed + args.n):
                total += 1
                total_failures += run_scenario(difficulty, seed, args.keep_failures, tmproot)
    finally:
        if not args.keep_failures:
            shutil.rmtree(tmproot, ignore_errors=True)
        else:
            print(f"\nScratch root: {tmproot}")

    print(f"\n{total} scenarios checked, {total_failures} question(s) with mismatched answers.")
    sys.exit(1 if total_failures else 0)


if __name__ == "__main__":
    main()
