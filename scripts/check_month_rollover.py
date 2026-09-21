#!/usr/bin/env python3
"""One-off probe: how often does a c2_beaconing run's event span cross a
calendar month boundary (which would break the awk day-of-month diffing in
its answer-key command)?"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from generate import build_scenario

hits = 0
total = 0
for seed in range(1, 4001):
    for difficulty in ("easy", "medium", "hard"):
        scn = build_scenario(difficulty, seed)
        for res in scn["featured"] + scn["decoys"]:
            if res["key"] != "c2_beaconing":
                continue
            total += 1
            events = res["events"]["firewall"]
            months = {t.month for t, _ in events}
            days = [t.day for t, _ in events]
            crosses = len(months) > 1 or any(d2 < d1 for d1, d2 in zip(days, days[1:]))
            if crosses:
                hits += 1
                print(f"seed={seed} difficulty={difficulty} months={months} "
                      f"first={events[0][0]} last={events[-1][0]}")

print(f"\n{hits}/{total} c2_beaconing instances cross a month/day-decrease boundary")
