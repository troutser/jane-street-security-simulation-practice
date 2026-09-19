# security-sim-practice

An infinite generator of randomized "simulated investigation" scenarios for practicing
`grep`, `less`, and shell pipelines on realistic-looking log data — built for drilling
the kind of exercise you'd get in a Cybersecurity Engineer Intern technical interview.

Every run creates a **fresh, randomized** incident: different IPs, usernames, hostnames,
domains, timestamps, and a different attack pattern (or combination of patterns) planted
into thousands of lines of fake-but-realistic log data. Nothing here is a real IP, real
person, or real domain — all "public" IPs are drawn from the RFC 5737 documentation
ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

## Quick start

```bash
./practice.sh                 # generate a medium scenario and drop into its directory
./practice.sh --hard          # harder: more archetypes layered + decoys + more noise
./practice.sh --easy --seed 42   # reproduce a specific scenario later
```

`practice.sh` generates the scenario, `cat`s the briefing, and opens a shell inside
`scenarios/run-<timestamp>/` so `auth.log`, `access.log`, `firewall.log`, `dns.log`, and
`exec.log` are all right there for `grep`/`less`. Type `exit` to leave that shell.

When you want to check your work **without spoiling anything**, run:

```bash
./quiz.sh
```

from inside the scenario directory (or anywhere, via the `SECURITY_SIM_SCENARIO` env
var `practice.sh` sets up). It asks each question from `questions.md` one at a time and
grades your typed answer against `answers.md` — it never shows the answer, the
pipeline, or the explanation unless you ask. Type `?` on a question to reveal just that
answer, `skip` to move on without seeing it, or `quit` to stop early. You get a score
out of the total at the end.

When you're ready to see everything (or stuck), run:

```bash
./check.sh
```

from inside the scenario directory (or anywhere, via the `SECURITY_SIM_ROOT` env var
`practice.sh` sets up) to see `answers.md` for the **current** scenario — the exact
answer, the exact pipeline that finds it, and a one-line explanation of why each flag
matters.

You can also skip the wrapper and call the generator directly:

```bash
python3 generate.py [--easy|--medium|--hard] [--seed N]
```

## Reproducibility

- Run **without** `--seed`: the seed is derived from the current time + OS entropy, so
  two runs are never the same scenario (archetype, IPs, usernames, everything shifts).
- Run **with** `--seed N`: fully deterministic — the exact same scenario is rebuilt
  every time, so you can retry one you want another shot at. `generate.py` prints the
  seed it used on every run in case you didn't set one and want to save it.

## What's in a scenario

```
scenarios/run-20260917-142301/
  auth.log             SSH/sudo/cron activity, syslog format
  access.log           Apache/Nginx combined log format
  firewall.log         iptables/netfilter-style DROP/ACCEPT entries
  dns.log              BIND-style DNS query log
  exec.log             auditd-style EXECVE process log
  briefing.md          the incident backstory
  questions.md         4-6 investigative questions with checkable answers
  answers.md           the answers + exact pipelines + why each flag matters
  scenario_meta.json   which archetypes were planted, for the progress log
```

Each log file has thousands of lines of realistic background noise (regular visitor
traffic, benign SSH logins, cron jobs, normal DNS lookups, background internet port
scanning) with one or more attack patterns planted inside. You cannot eyeball these —
you have to `grep`/`less`/pipe your way through them.

## The archetype library

Fifteen attack/incident patterns are in rotation, so scenarios don't repeat:

1. SSH brute force
2. Password spraying
3. Credential stuffing (web login)
4. Web shell upload
5. SQL injection probing
6. Directory traversal
7. DNS tunneling
8. DGA beaconing
9. C2 beaconing at a regular interval
10. Data exfiltration via abnormally large responses
11. Privilege escalation via sudo abuse
12. Lateral movement
13. Insider after-hours data access
14. Port scanning
15. Log tampering (doubled-word artifacts, suspicious restart markers)

**Easy** plants one archetype. **Medium** plants one or two. **Hard** plants two or
three *plus* one or two additional "decoy" archetypes — their traffic is in the logs
and adds realistic noise/red herrings, but they're not asked about directly, so you
have to confirm what's actually relevant instead of assuming every anomaly matters.

## Guaranteed skill coverage

Every single scenario includes a few "generic" questions computed straight from the
data (independent of which archetype got planted), so no matter what you draw you'll
always get practice with:

- **`grep -F`** — literal-string matching against IPs, User-Agents, and paths full of
  regex metacharacters (`.`, `(`, `)`, `?`, `/`, `#`...)
- **`grep -P`** — PCRE features POSIX/ERE grep can't do: `\d`/`\w`/`\s` shorthand,
  lookahead/lookbehind, `\K`, backreferences, alternation
- **Multi-stage pipelines** — `grep | sort | uniq -c | sort -rn | head` to rank a field
  too noisy to eyeball, `grep -v` to exclude known-benign noise
- **`-r` / `-l`** — searching every log file at once and just listing which ones match

On top of that, most archetypes' own questions specifically exercise `-c`, `-o`,
`-w`, `-i`, and `-A`/`-B`/`-C` context lines. At least one question per scenario is
designed so a naive first-pass `grep` returns far too many hits, forcing you to add
filters or aggregate before you can pin down the real answer.

## grep cheat-sheet

| Flag | Meaning | When to reach for it |
|---|---|---|
| `-F` | Fixed string (no regex) | Matching an IP, URL, path, or query string literally — anything with `.`, `?`, `(`, `)`, `+`, `*`, `[`, `]` in it |
| `-P` | PCRE mode | `\d`, `\w`, `\s`, lookahead `(?=...)`, lookbehind `(?<=...)`, `\K`, backreferences `\1`, alternation, non-greedy `*?` |
| `-i` | Case-insensitive | User-Agents, hostnames, anything that might vary in case |
| `-w` | Whole word | Avoids `22` matching `220` or `2222`, or `10.0.0.1` matching `10.0.0.10` |
| `-v` | Invert match | Strip out known-benign noise so what's left is suspicious |
| `-c` | Count matching lines | "How many..." questions |
| `-o` | Print only the match | Extract just the IP/username/port instead of the whole line |
| `-A n` / `-B n` / `-C n` | n lines after/before/around | See what happened right after a suspicious event |
| `-r` | Recurse into a directory | Search every log file at once |
| `-l` | List matching filenames only | "Which file(s) mention X" |
| `\K` | Reset match start (PCRE) | Like a lookbehind, but works even when what precedes it is variable-length (a true lookbehind must be fixed-length) |

Useful pipeline partners: `sort`, `uniq -c`, `sort -rn`, `head`/`tail`, `wc -l`, `cut`,
`awk` (especially `awk -F'"'` for quoted Apache/Nginx log fields, since the User-Agent
field has a variable number of words and breaks naive `awk '{print $N}'` column math).

## Files

- `generate.py` — the generator (Python; everything downstream is plain grep/less/pipes)
- `simlib/` — the pools of random data, the 15 archetypes, the generic question bank
- `practice.sh` — generate + drop into the scenario directory
- `quiz.sh` — self-check your answers one question at a time, no spoilers
- `check.sh` — reveal `answers.md` for the current scenario
- `progress.md` — auto-appended log of every scenario you've generated, so you can spot
  which archetypes you haven't drilled yet
- `scenarios/` — where generated runs land (safe to delete anytime; nothing here is
  meant to be kept long-term except whichever run you're actively working)
