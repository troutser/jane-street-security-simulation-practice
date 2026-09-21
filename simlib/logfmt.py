"""Line formatters for each fake log format."""

MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def syslog_ts(dt):
    day = f"{dt.day:2d}"
    return f"{MONTHS[dt.month - 1]} {day} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"


def apache_ts(dt):
    return f"{dt.day:02d}/{MONTHS[dt.month - 1]}/{dt.year}:{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"


def auth_line(dt, host, proc, pid, msg):
    return f"{syslog_ts(dt)} {host} {proc}[{pid}]: {msg}"


def access_line(dt, ip, method, path, proto, status, size, referer, ua):
    return (f'{ip} - - [{apache_ts(dt)}] "{method} {path} {proto}" {status} {size} '
            f'"{referer}" "{ua}"')


def iptables_line(dt, host, action, in_if, out_if, mac, src, dst, proto, spt, dpt, flags, ident):
    flagstr = f" {flags}" if flags else ""
    return (f"{syslog_ts(dt)} {host} kernel: [{ident}] IPTABLES-{action}: IN={in_if} OUT={out_if} "
            f"MAC={mac} SRC={src} DST={dst} LEN=60 TOS=0x00 PREC=0x00 TTL=64 ID={ident % 65535} "
            f"PROTO={proto} SPT={spt} DPT={dpt} WINDOW=1024 RES=0x00{flagstr} URGP=0")


def dns_line(dt, host, client_ip, port, qname, qtype, server):
    return f"{syslog_ts(dt)} {host} named[2381]: client {client_ip}#{port}: query: {qname} IN {qtype} + ({server})"


def exec_line(dt, host, uid, user, exe, cmd, pid):
    return f"{syslog_ts(dt)} {host} audit: EXECVE pid={pid} uid={uid}({user}) exe=\"{exe}\" cmd=\"{cmd}\""


def endpoint_line(dt, host, user, pid, ppid, image, parent_image, cmdline):
    """A workstation EDR/Sysmon-style process-creation record -- distinct from exec_line
    (server-side auditd) in that it carries the PARENT process too, so investigating it
    means walking a process tree (image spawned by parent_image) rather than reading one
    flat event."""
    return (f"{syslog_ts(dt)} {host} endpointd: user={user} pid={pid} ppid={ppid} "
            f"image=\"{image}\" parent=\"{parent_image}\" cmdline=\"{cmdline}\"")
