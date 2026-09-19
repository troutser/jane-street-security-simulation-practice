#!/usr/bin/env python3
"""
Infinite scenario generator for grep/less/pipeline investigation practice.

Usage:
  python3 generate.py [--easy|--medium|--hard] [--seed N]

Creates scenarios/run-<timestamp>/ containing:
  auth.log, access.log, firewall.log, dns.log, exec.log   - the evidence
  briefing.md                                              - incident backstory
  questions.md                                              - 4-6 checkable questions
  answers.md                                                - answers + exact pipelines
Also appends a line to progress.md and updates scenarios/.latest.
"""
import argparse
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from simlib.pool import Ctx
from simlib import noise
from simlib.archetypes import REGISTRY, plant_log_tampering
from simlib.generic_questions import generic_bank

ROOT = os.path.dirname(os.path.abspath(__file__))
SCENARIOS_DIR = os.path.join(ROOT, "scenarios")
PROGRESS_PATH = os.path.join(ROOT, "progress.md")

LOG_NAMES = ["auth", "access", "firewall", "dns", "exec"]

TARGET_TOTAL = {"easy": 4, "medium": 5, "hard": 6}


def parse_args():
    p = argparse.ArgumentParser(description="Generate a randomized blue-team investigation scenario.")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--easy", action="store_true")
    g.add_argument("--medium", action="store_true")
    g.add_argument("--hard", action="store_true")
    p.add_argument("--seed", type=int, default=None, help="Reproduce a specific scenario.")
    args = p.parse_args()
    if args.easy:
        difficulty = "easy"
    elif args.hard:
        difficulty = "hard"
    else:
        difficulty = "medium"
    return difficulty, args.seed


def pick_primary_ip(facts):
    for k in ("attacker", "infected", "client", "scanner", "exfil_ip", "pivot_ip", "ip"):
        if k in facts:
            return facts[k]
    return None


def select_archetypes(ctx, difficulty):
    rng = ctx.rng
    pool = list(REGISTRY)
    rng.shuffle(pool)
    n_featured = {"easy": 1, "medium": rng.choice([1, 2]), "hard": rng.choice([2, 3])}[difficulty]
    n_decoy = {"easy": 0, "medium": rng.randint(0, 1), "hard": rng.randint(1, 2)}[difficulty]
    n_featured = min(n_featured, len(pool))
    featured = pool[:n_featured]
    decoys = pool[n_featured:n_featured + n_decoy]
    return featured, decoys


def build_scenario(difficulty, seed):
    ctx = Ctx(seed, difficulty)
    used_ips = set(ctx.benign_noise_ips)

    featured_fns, decoy_fns = select_archetypes(ctx, difficulty)

    logs = {name: [] for name in LOG_NAMES}

    # Plant archetypes FIRST so their attacker/C2/exfil IPs and protagonist usernames land in
    # ctx.reserved_ips / ctx.reserved_users before any noise is generated -- otherwise noise
    # could coincidentally reuse one of those values and quietly corrupt a count-based answer.
    # plant_log_tampering picks a random EXISTING username for flavor rather than reserving one
    # of its own, so it must run dead last -- otherwise its doubled-word artifact could land on
    # a username another (later-executing) archetype was about to claim as its own protagonist.
    execution_order = ([("featured", fn) for fn in featured_fns] +
                        [("decoy", fn) for fn in decoy_fns])
    execution_order.sort(key=lambda item: item[1] is plant_log_tampering)

    featured_results, decoy_results = [], []
    for group, fn in execution_order:
        res = fn(ctx, used_ips)
        (featured_results if group == "featured" else decoy_results).append(res)
        for logname, events in res["events"].items():
            logs[logname] += events

    vol = noise.volumes(difficulty)
    logs["access"] += noise.gen_access_noise(ctx, vol["access"])
    logs["auth"] += noise.gen_auth_noise(ctx, vol["auth"])
    logs["firewall"] += noise.gen_firewall_noise(ctx, vol["firewall"])
    logs["dns"] += noise.gen_dns_noise(ctx, vol["dns"])
    logs["exec"] += noise.gen_exec_noise(ctx, vol["exec"])

    # sort each log chronologically and drop down to plain text lines
    log_texts = {}
    for name in LOG_NAMES:
        logs[name].sort(key=lambda e: e[0])
        log_texts[name] = [line for _, line in logs[name]]

    primary_ip = pick_primary_ip(featured_results[0]["facts"]) if featured_results else None
    generic = generic_bank(ctx, log_texts, primary_ip)

    all_featured_questions = []
    for res in featured_results:
        for q in res["questions"]:
            q = dict(q)
            q["_source"] = res["key"]
            all_featured_questions.append(q)

    target = TARGET_TOTAL[difficulty]
    questions = list(all_featured_questions)
    ctx.rng.shuffle(generic)
    gi = 0
    while len(questions) < target and gi < len(generic):
        questions.append(generic[gi])
        gi += 1
    # if archetypes alone overflow the target (e.g. 3 featured archetypes x 2Q), trim evenly
    while len(questions) > target:
        # drop the last question belonging to whichever source contributed the most
        counts = Counter(q.get("_source", "generic") for q in questions)
        worst_source = counts.most_common(1)[0][0]
        for i in range(len(questions) - 1, -1, -1):
            if questions[i].get("_source", "generic") == worst_source:
                questions.pop(i)
                break
    ctx.rng.shuffle(questions)

    return dict(ctx=ctx, difficulty=difficulty, seed=seed, log_texts=log_texts,
                featured=featured_results, decoys=decoy_results, questions=questions)


def render_briefing(scn):
    ctx = scn["ctx"]
    org = ctx.domain.replace(".local", "").replace("-", " ").title()
    lines = []
    lines.append(f"# Incident Briefing — {org}\n")
    lines.append(f"**Window under review:** {ctx.start.strftime('%b %d %H:%M')} "
                 f"through {ctx.end.strftime('%b %d %H:%M')} (host clocks, no year)\n")
    lines.append(f"**Difficulty:** {scn['difficulty']}\n")
    lines.append("**Systems in scope:** " + ", ".join(sorted(set(
        h for role in ctx.hosts.values() for h in role))) + "\n")
    lines.append("\n## What we know so far\n")
    lines.append("The SOC on-call was paged after automated alerting flagged unusual activity. "
                  "You've been handed `auth.log`, `access.log`, `firewall.log`, `dns.log`, and "
                  "`exec.log` covering the window above. Here's what's been reported:\n")
    for res in scn["featured"]:
        lines.append(f"- {res['briefing']}")
    lines.append("\nYour job is to work the evidence with `grep`, `less`, and shell pipelines and "
                  "answer the questions in `questions.md`. Not every anomaly in these logs is "
                  "necessarily related to the incident above -- background noise and unrelated "
                  "scanning traffic are normal on any real network, so confirm before you conclude.\n")
    return "\n".join(lines)


def render_questions(scn):
    lines = ["# Investigation Questions\n",
             "Answer each with a specific, checkable fact (an IP, a username, a count, a timestamp...). "
             "Everything you need is in the five log files in this directory. Use `less` to browse, "
             "`grep` to filter, and pipe into `sort` / `uniq -c` / `wc -l` / `awk` / `cut` as needed.\n"]
    for i, q in enumerate(scn["questions"], 1):
        lines.append(f"{i}. {q['q']}")
    lines.append("\nRun `../../quiz.sh` to self-check one question at a time without spoilers, or "
                 "`../../check.sh` (or just `quiz.sh`/`check.sh` if you copied them in) when you want "
                 "the full answer key.\n")
    return "\n".join(lines)


def render_answers(scn):
    lines = ["# Answers\n"]
    for i, q in enumerate(scn["questions"], 1):
        lines.append(f"## Q{i}. {q['q']}\n")
        lines.append(f"**Answer:** `{q['a']}`\n")
        lines.append("**Command(s):**")
        lines.append("```bash")
        lines.append(q["cmd"])
        lines.append("```")
        lines.append(f"**Why these flags:** {q['explain']}\n")
    return "\n".join(lines)


def append_progress(scn, run_name):
    ctx = scn["ctx"]
    header = "# Practice Progress Log\n\nAppended automatically on every `generate.py` run. " \
             "Use it to see which archetypes you've drilled and spot gaps.\n\n"
    if not os.path.exists(PROGRESS_PATH):
        with open(PROGRESS_PATH, "w", encoding="utf-8") as f:
            f.write(header)
    featured_names = ", ".join(r["title"] for r in scn["featured"])
    decoy_names = ", ".join(r["title"] for r in scn["decoys"]) or "(none)"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    entry = (f"- **{now}** | `{run_name}` | difficulty={scn['difficulty']} | seed={ctx.seed} | "
             f"featured=[{featured_names}] | decoys=[{decoy_names}]\n")
    with open(PROGRESS_PATH, "a", encoding="utf-8") as f:
        f.write(entry)


def main():
    difficulty, seed = parse_args()
    if seed is None:
        seed = int.from_bytes(os.urandom(4), "big") ^ int(time.time() * 1000) & 0xFFFFFFFF

    scn = build_scenario(difficulty, seed)

    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    run_name = f"run-{ts}"
    scen_dir = os.path.join(SCENARIOS_DIR, run_name)
    suffix = 1
    while os.path.exists(scen_dir):
        suffix += 1
        run_name = f"run-{ts}-{suffix}"
        scen_dir = os.path.join(SCENARIOS_DIR, run_name)
    os.makedirs(scen_dir, exist_ok=True)

    for name, lines in scn["log_texts"].items():
        with open(os.path.join(scen_dir, f"{name}.log"), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(lines) + "\n")

    with open(os.path.join(scen_dir, "briefing.md"), "w", encoding="utf-8") as f:
        f.write(render_briefing(scn))
    with open(os.path.join(scen_dir, "questions.md"), "w", encoding="utf-8") as f:
        f.write(render_questions(scn))
    with open(os.path.join(scen_dir, "answers.md"), "w", encoding="utf-8") as f:
        f.write(render_answers(scn))

    meta = dict(seed=seed, difficulty=difficulty,
                featured=[r["key"] for r in scn["featured"]],
                decoys=[r["key"] for r in scn["decoys"]])
    with open(os.path.join(scen_dir, "scenario_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2)

    os.makedirs(SCENARIOS_DIR, exist_ok=True)
    with open(os.path.join(SCENARIOS_DIR, ".latest"), "w", encoding="utf-8") as f:
        f.write(run_name)

    append_progress(scn, run_name)

    print(f"Generated {run_name}  (difficulty={difficulty}, seed={seed})")
    print(f"  -> {scen_dir}")


if __name__ == "__main__":
    main()
