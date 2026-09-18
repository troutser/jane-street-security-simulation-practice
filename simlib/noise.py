"""Baseline benign traffic generators for each log, plus a couple of always-present
'canary' patterns that the generic question bank relies on for grep -F / -P practice."""
from .pool import (rand_internal_ip, DOMAINS_LEGIT, UA_LEGIT,
                    PATHS_LEGIT, SUDO_COMMANDS_BENIGN)
from .logfmt import auth_line, access_line, iptables_line, dns_line, exec_line

VOLUME = {
    "easy":   dict(access=1500, auth=800,  firewall=900,  dns=700,  exec=500),
    "medium": dict(access=3000, auth=1400, firewall=1800, dns=1500, exec=900),
    "hard":   dict(access=5000, auth=2200, firewall=3200, dns=2500, exec=1500),
}


def volumes(difficulty):
    return VOLUME[difficulty]


def gen_access_noise(ctx, n):
    rng = ctx.rng
    events = []
    # a rotating cast of "regular visitor" ips, weighted so some visit far more than others
    regulars = [ctx.safe_noise_public_ip() for _ in range(rng.randint(20, 45))]
    weights = [rng.randint(1, 12) for _ in regulars]
    for _ in range(n):
        dt = ctx.random_ts()
        ip = rng.choices(regulars, weights=weights, k=1)[0]
        path = rng.choice(PATHS_LEGIT)
        method = rng.choices(["GET", "POST", "HEAD"], weights=[85, 12, 3])[0]
        status = rng.choices([200, 304, 404, 301, 500], weights=[80, 8, 7, 3, 2])[0]
        size = rng.randint(180, 15000) if status == 200 else rng.randint(0, 500)
        ref = rng.choice(["-", f"https://{rng.choice(DOMAINS_LEGIT)}/"])
        ua = ctx.canary_scanner_ua if rng.random() < 0.012 else rng.choice(UA_LEGIT)
        events.append((dt, access_line(dt, ip, method, path, "HTTP/1.1", status, size, ref, ua)))
    return events


def gen_auth_noise(ctx, n):
    rng = ctx.rng
    events = []
    host = ctx.primary_bastion
    for i in range(n):
        dt = ctx.random_ts()
        pid = rng.randint(1000, 32000)
        kind = rng.choices(["accept", "sudo", "cron", "typo", "session"], weights=[35, 20, 25, 8, 12])[0]
        user = ctx.noise_user()
        ip = ctx.user_ips[user]
        if kind == "accept":
            msg = f"Accepted password for {user} from {ip} port {rng.randint(30000, 60000)} ssh2"
        elif kind == "sudo":
            cmd = rng.choice(SUDO_COMMANDS_BENIGN)
            msg = f"{user} : TTY=pts/{rng.randint(0,4)} ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}"
            events.append((dt, auth_line(dt, host, "sudo", pid, msg)))
            continue
        elif kind == "cron":
            events.append((dt, auth_line(dt, host, "CRON", pid, f"({rng.choice(ctx.service_accounts)}) CMD (/usr/local/bin/backup_check.sh)")))
            continue
        elif kind == "typo":
            # a single benign failed login (fat-fingered password), from the user's own known IP
            msg = f"Failed password for {user} from {ip} port {rng.randint(30000,60000)} ssh2"
        else:
            msg = f"pam_unix(sshd:session): session opened for user {user}(uid={rng.randint(1000,1050)}) by (uid=0)"
        events.append((dt, auth_line(dt, host, "sshd", pid, msg)))
    # a couple of oddly-shaped usernames (invalid user, ending in exactly 2 digits) - PCRE canary
    for _ in range(rng.randint(6, 22)):
        dt = ctx.random_ts()
        pid = rng.randint(1000, 32000)
        fake_user = rng.choice(["test", "guest", "temp", "backup", "demo", "user"]) + f"{rng.randint(10,99)}"
        ip = ctx.safe_noise_public_ip()
        msg = f"Failed password for invalid user {fake_user} from {ip} port {rng.randint(30000,60000)} ssh2"
        events.append((dt, auth_line(dt, host, "sshd", pid, msg)))
    return events


def gen_firewall_noise(ctx, n):
    rng = ctx.rng
    events = []
    host = ctx.primary_fw
    scan_ips = [ctx.safe_noise_public_ip() for _ in range(rng.randint(25, 60))]
    for _ in range(n):
        dt = ctx.random_ts()
        ident = rng.randint(10000, 99999)
        mac = ":".join(f"{rng.randint(0,255):02x}" for _ in range(6))
        outbound = rng.random() < 0.4
        if outbound:
            src = rand_internal_ip(rng, ctx.internal_octet)
            dst = ctx.safe_noise_public_ip()
            action, spt, dpt = "ACCEPT", rng.randint(1024, 65000), rng.choice([443, 80, 53])
        else:
            # low-volume background internet scan noise, spread across many source ips
            src = rng.choice(scan_ips)
            dst = rand_internal_ip(rng, ctx.internal_octet)
            dpt = rng.choice([22, 23, 80, 443, 445, 3389, 8080, 8443, 3306])
            action, spt = "DROP", rng.randint(1024, 65000)
        flags = rng.choice(["SYN", "SYN ACK", "ACK", "FIN ACK"])
        events.append((dt, iptables_line(dt, host, action, "eth0", "eth0" if outbound else "", mac,
                                          src, dst, "TCP", spt, dpt, flags, ident)))
    return events


def gen_dns_noise(ctx, n):
    rng = ctx.rng
    events = []
    host = ctx.primary_dns
    for _ in range(n):
        dt = ctx.random_ts()
        client = rand_internal_ip(rng, ctx.internal_octet)
        qname = rng.choice(DOMAINS_LEGIT)
        if rng.random() < 0.3:
            qname = f"{rng.choice(['www', 'api', 'cdn', 'static', 'mail'])}.{qname}"
        qtype = rng.choices(["A", "AAAA", "CNAME", "MX"], weights=[60, 20, 15, 5])[0]
        events.append((dt, dns_line(dt, host, client, rng.randint(1024, 65000), qname, qtype, "127.0.0.1")))
    return events


def gen_exec_noise(ctx, n):
    rng = ctx.rng
    events = []
    host = rng.choice(ctx.hosts["app"] + ctx.hosts["web"])
    cmds = [
        ("/usr/bin/apt-get", "apt-get install -y curl"), ("/usr/bin/git", "git pull origin main"),
        ("/usr/bin/systemctl", "systemctl restart app.service"), ("/usr/bin/docker", "docker ps -a"),
        ("/usr/bin/python3", "python3 manage.py migrate"), ("/usr/bin/npm", "npm install"),
        ("/usr/bin/tar", "tar -czf /backup/nightly.tar.gz /var/www"),
    ]
    for _ in range(n):
        dt = ctx.random_ts()
        user = rng.choice(ctx.all_local_accounts)
        exe, cmd = rng.choice(cmds)
        uid = 0 if user in ctx.service_accounts else rng.randint(1000, 1050)
        events.append((dt, exec_line(dt, host, uid, user, exe, cmd, rng.randint(1000, 32000))))
    return events
