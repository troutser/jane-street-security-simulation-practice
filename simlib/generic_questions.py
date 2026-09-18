"""
Questions that don't depend on which archetype got planted -- they're computed
straight off the final assembled log text, so they're always present and always
correct, and they guarantee coverage of -F, -P, pipelines, and -v/-r/-l every run.
"""
import re
from collections import Counter


def generic_bank(ctx, log_texts, primary_ip):
    access = log_texts.get("access", [])
    auth = log_texts.get("auth", [])
    bank = []

    ua = ctx.canary_scanner_ua
    ua_count = sum(1 for l in access if ua in l)
    bank.append(dict(
        q=f"A scanning tool identifying itself with the exact User-Agent string `{ua}` sent some noise "
          "requests mixed into the traffic. How many requests in access.log used that literal User-Agent?",
        a=str(ua_count),
        cmd=f"grep -F -c '{ua}' access.log",
        explain="-F matches the User-Agent as a literal string; without it, characters like '(', ')', '.', '#', "
                "and '/' in the string would be interpreted as regex metacharacters.",
        skills=["-F", "-c"],
    ))

    p_pat = re.compile(r'invalid user \w+\d{2}\b')
    p_count = sum(1 for l in auth if p_pat.search(l))
    bank.append(dict(
        q="Some SSH login attempts target throwaway usernames that end in exactly two digits (e.g. temp84, "
          "guest23). How many such invalid-user attempts appear in auth.log?",
        a=str(p_count),
        cmd=r"grep -Pc 'invalid user \w+\d{2}\b' auth.log",
        explain="\\d and \\w are PCRE shorthand classes not available in POSIX/ERE grep, so -P is required to "
                "express 'exactly two digits at the end of the word'.",
        skills=["-P", "-c"],
    ))

    ip_lines = [l for l in access if l.strip()]
    ip_counts = Counter(l.split()[0] for l in ip_lines)
    if ip_counts:
        # match the tiebreak `sort | uniq -c | sort -rn` actually produces: -r doesn't just flip
        # the count comparison, it reverses the whole (stable) ascending-by-IP order, so among
        # tied counts the alphabetically LAST IP ends up on top. Verified empirically with GNU sort.
        top_ip, top_n = max(ip_counts.items(), key=lambda kv: (kv[1], kv[0]))
        bank.append(dict(
            q="Which single IP address made the most total requests in access.log, and how many requests "
              "did it make?",
            a=f"{top_ip} ({top_n} requests)",
            cmd="awk '{print $1}' access.log | sort | uniq -c | sort -rn | head -1",
            explain="sort | uniq -c | sort -rn | head is the standard 'rank by frequency' pipeline for finding "
                    "a top talker in a field too noisy to eyeball.",
            skills=["pipeline", "sort|uniq -c"],
        ))

    fail_pat = re.compile(r'Failed password')
    internal_pat = re.compile(r'from 10\.')
    ext_fail = sum(1 for l in auth if fail_pat.search(l) and not internal_pat.search(l))
    bank.append(dict(
        q="Excluding failed logins that came from the organization's own internal 10.x.x.x address range, "
          "how many failed SSH password attempts in auth.log came from outside the network entirely?",
        a=str(ext_fail),
        cmd=r"grep 'Failed password' auth.log | grep -vP 'from 10\.' | wc -l",
        explain="-v inverts the match to drop the internal-range noise (typos from real employees), isolating "
                "externally-sourced failures.",
        skills=["-v", "-P", "pipeline"],
    ))

    if primary_ip:
        ip_word_pat = re.compile(r'\b' + re.escape(primary_ip) + r'\b')
        files_with_ip = sorted(name for name, lines in log_texts.items()
                                if any(ip_word_pat.search(l) for l in lines))
        bank.append(dict(
            q=f"Across all the log files in this scenario, which file(s) mention the IP `{primary_ip}` at all?",
            a=", ".join(f"{f}.log" for f in files_with_ip) if files_with_ip else "(none)",
            cmd=f"grep -rl -F -w '{primary_ip}' .",
            explain="-r recurses into every file in the current directory and -l prints just the matching "
                    "filenames instead of the matching lines.",
            skills=["-r", "-l", "-F"],
        ))

    return bank
