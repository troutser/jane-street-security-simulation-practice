#!/usr/bin/env python3
"""
Denser targeted check: force ONE specific archetype to be the sole featured
archetype (bypassing the random selection) across many seeds/difficulties, so
newly-added or newly-modified archetypes get much heavier coverage per run
than they'd get from random selection alone (~1/16 chance per slot).
"""
import argparse
import os
import shutil
import subprocess
import sys
import tempfile

_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(_here))
sys.path.insert(0, _here)

import generate as G
from simlib import archetypes as A
from verify_answers import outputs_match, BASH

TARGETS = {
    "ssh_bruteforce": A.plant_ssh_bruteforce,
    "password_spraying": A.plant_password_spraying,
    "credential_stuffing": A.plant_credential_stuffing,
    "web_shell_upload": A.plant_web_shell_upload,
    "sql_injection_probing": A.plant_sql_injection,
    "directory_traversal": A.plant_directory_traversal,
    "dns_tunneling": A.plant_dns_tunneling,
    "dga_beaconing": A.plant_dga_beaconing,
    "c2_beaconing": A.plant_c2_beaconing,
    "data_exfiltration": A.plant_data_exfil,
    "priv_esc_sudo": A.plant_priv_esc,
    "lateral_movement": A.plant_lateral_movement,
    "insider_after_hours": A.plant_insider_access,
    "port_scanning": A.plant_port_scan,
    "log_tampering": A.plant_log_tampering,
    "compromise_chain": A.plant_compromise_chain,
    "workstation_malware": A.plant_workstation_malware,
}


def build_forced(difficulty, seed, fn):
    ctx = G.Ctx(seed, difficulty)
    used_ips = set(ctx.benign_noise_ips)
    res = fn(ctx, used_ips)
    logs = {name: [] for name in G.LOG_NAMES}
    for logname, events in res["events"].items():
        logs[logname] += events
    vol = G.noise.volumes(difficulty)
    logs["access"] += G.noise.gen_access_noise(ctx, vol["access"])
    logs["auth"] += G.noise.gen_auth_noise(ctx, vol["auth"])
    logs["firewall"] += G.noise.gen_firewall_noise(ctx, vol["firewall"])
    logs["dns"] += G.noise.gen_dns_noise(ctx, vol["dns"])
    logs["exec"] += G.noise.gen_exec_noise(ctx, vol["exec"])
    log_texts = {}
    for name in G.LOG_NAMES:
        logs[name].sort(key=lambda e: e[0])
        log_texts[name] = [line for _, line in logs[name]]
    return res, log_texts


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--start-seed", type=int, default=1)
    ap.add_argument("--difficulties", default="easy,medium,hard")
    ap.add_argument("--only", default=",".join(TARGETS))
    args = ap.parse_args()

    wanted = [k for k in args.only.split(",") if k in TARGETS]
    tmproot = tempfile.mkdtemp(prefix="verify_forced_")
    total = 0
    total_fail = 0
    try:
        for key in wanted:
            fn = TARGETS[key]
            for difficulty in args.difficulties.split(","):
                for seed in range(args.start_seed, args.start_seed + args.n):
                    total += 1
                    res, log_texts = build_forced(difficulty, seed, fn)
                    scen_dir = os.path.join(tmproot, f"{key}-{difficulty}-{seed}")
                    os.makedirs(scen_dir, exist_ok=True)
                    for name in G.LOG_NAMES:
                        with open(os.path.join(scen_dir, f"{name}.log"), "w", encoding="utf-8", newline="\n") as f:
                            f.write("\n".join(log_texts[name]) + "\n")
                    failures = []
                    for i, q in enumerate(res["questions"], 1):
                        try:
                            proc = subprocess.run([BASH, "-c", q["cmd"]], cwd=scen_dir,
                                                   capture_output=True, text=True, timeout=30)
                        except subprocess.TimeoutExpired:
                            failures.append((i, q, "TIMEOUT", ""))
                            continue
                        actual = proc.stdout.strip()
                        if not outputs_match(actual, q["a"], q["cmd"]):
                            failures.append((i, q, actual, proc.stderr.strip()))
                    if failures:
                        total_fail += len(failures)
                        print(f"\n=== FAIL {key} difficulty={difficulty} seed={seed} ===")
                        for i, q, actual, err in failures:
                            print(f"  Q{i}: {q['q'][:90]}")
                            print(f"    cmd:      {q['cmd']}")
                            print(f"    expected: {q['a']!r}")
                            print(f"    actual:   {actual!r}")
                            if err:
                                print(f"    stderr:   {err!r}")
                        print(f"    (scenario kept at {scen_dir})")
                    else:
                        shutil.rmtree(scen_dir, ignore_errors=True)
    finally:
        pass

    print(f"\n{total} forced scenarios checked, {total_fail} question(s) with mismatched answers.")
    print(f"Scratch root: {tmproot}")
    sys.exit(1 if total_fail else 0)


if __name__ == "__main__":
    main()
