"""
Crips Framework — banner_mod.py
Service Banner Grabbing — reads protocol greetings via TCP socket
Educational: shows how network protocols identify themselves
"""

import socket
import ssl
import time
from modules.colors import *
from modules.utils import prompt, resolve


# Per-protocol probes and response parsers
PROTOCOL_PROBES = {
    21:   (b"",             "FTP"),
    22:   (b"",             "SSH"),
    23:   (b"",             "Telnet"),
    25:   (b"EHLO crips\r\n","SMTP"),
    80:   (b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n", "HTTP"),
    110:  (b"",             "POP3"),
    143:  (b"",             "IMAP"),
    443:  (None,            "HTTPS (TLS)"),   # None = use SSL
    465:  (None,            "SMTPS (TLS)"),
    587:  (b"EHLO crips\r\n","SMTP Submission"),
    993:  (None,            "IMAPS (TLS)"),
    995:  (None,            "POP3S (TLS)"),
    1433: (b"",             "MSSQL"),
    1521: (b"",             "Oracle"),
    3306: (b"",             "MySQL"),
    3389: (b"",             "RDP"),
    5432: (b"",             "PostgreSQL"),
    5900: (b"",             "VNC"),
    6379: (b"PING\r\n",     "Redis"),
    8080: (b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n", "HTTP-Alt"),
    9200: (b"GET / HTTP/1.0\r\nHost: target\r\n\r\n",  "Elasticsearch"),
    11211:(b"stats\r\n",    "Memcached"),
    27017:(b"",             "MongoDB"),
}


def _grab(host: str, port: int, timeout: float = 4.0,
          use_ssl: bool = False) -> str:
    """Connect and read the initial service response (banner)."""
    probe, _ = PROTOCOL_PROBES.get(port, (b"", ""))
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw.settimeout(timeout)

        if use_ssl or probe is None:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            s = ctx.wrap_socket(raw, server_hostname=host)
        else:
            s = raw

        s.connect((host, port))

        # Some services send greeting first, others need a probe
        if probe:
            send = probe.replace(b"target", host.encode())
            s.sendall(send)

        data = b""
        s.settimeout(2.0)
        try:
            while True:
                chunk = s.recv(1024)
                if not chunk:
                    break
                data += chunk
                if len(data) > 4096:
                    break
        except (socket.timeout, ssl.SSLError):
            pass
        finally:
            s.close()

        return data.decode("utf-8", errors="replace").strip()
    except (ConnectionRefusedError, socket.timeout):
        return ""
    except Exception:
        return ""


def _parse_banner(port: int, banner: str) -> dict:
    """Extract structured info from a raw banner string."""
    info = {"raw": banner, "protocol": "", "software": "", "version": "", "notes": ""}
    lower = banner.lower()

    if port == 22 or banner.startswith("SSH"):
        info["protocol"] = "SSH"
        parts = banner.split("-", 2)
        if len(parts) >= 3:
            info["software"] = parts[2].split(" ")[0]
        elif len(parts) == 2:
            info["version"] = parts[1]

    elif port in (21,) or "ftp" in lower or "220" in banner[:10]:
        info["protocol"] = "FTP"
        if "220" in banner:
            info["software"] = banner.split("220", 1)[-1].strip()[:80]

    elif port in (25, 587) or "smtp" in lower or "esmtp" in lower:
        info["protocol"] = "SMTP"
        for line in banner.splitlines():
            if line.startswith("220"):
                info["software"] = line[3:].strip()[:80]
                break

    elif port in (110,) or "pop3" in lower or "+ok" in lower:
        info["protocol"] = "POP3"
        info["software"] = banner.splitlines()[0][:80]

    elif port in (143,) or "imap" in lower:
        info["protocol"] = "IMAP"
        info["software"] = banner.splitlines()[0][:80]

    elif "HTTP" in banner:
        info["protocol"] = "HTTP"
        for line in banner.splitlines():
            if line.lower().startswith("server:"):
                info["software"] = line.split(":", 1)[1].strip()
            if "HTTP/" in line:
                info["version"] = line.split()[0] if " " in line else line

    elif port == 6379 or "+pong" in lower:
        info["protocol"] = "Redis"
        info["software"] = "Redis"

    elif port == 3306 or "mysql" in lower or "mariadb" in lower:
        info["protocol"] = "MySQL/MariaDB"
        # MySQL sends binary greeting; look for version string
        import re
        m = re.search(r"(\d+\.\d+\.\d+[^\x00]*)", banner)
        if m:
            info["version"] = m.group(1)

    elif port == 5432 or "postgresql" in lower:
        info["protocol"] = "PostgreSQL"

    elif port == 27017 or "mongodb" in lower:
        info["protocol"] = "MongoDB"

    elif port == 11211:
        info["protocol"] = "Memcached"
        for line in banner.splitlines():
            if line.startswith("STAT version"):
                info["version"] = line.split()[-1]

    elif port == 9200 or ('"name"' in banner and '"cluster_name"' in banner):
        info["protocol"] = "Elasticsearch"
        import re
        m = re.search(r'"number"\s*:\s*"([^"]+)"', banner)
        if m:
            info["version"] = m.group(1)

    return info


def banner_grab():
    title_box("SERVICE BANNER GRABBER",
              "Reads protocol greetings — identifies service versions")
    info("Connects to open ports and reads what services announce about themselves.")
    info("Same as:  nc host port  or  telnet host port\n")

    target = prompt("Enter IP or Domain")
    if not target:
        return
    port_input = prompt("Ports (comma-list, range, or group)", "21,22,25,80,110,143,443,3306,6379")
    timeout    = prompt("Timeout seconds", "4")
    try:
        timeout = float(timeout)
    except ValueError:
        timeout = 4.0

    ip = resolve(target)
    if not ip:
        return

    # Parse ports
    from modules.portscan_mod import _parse_ports
    ports = _parse_ports(port_input)
    if not ports:
        err("No valid ports.")
        return

    sep()
    print(f"    {WHITE}Target  :{RST} {CYAN}{target}{RST} ({ip})")
    print(f"    {WHITE}Ports   :{RST} {', '.join(str(p) for p in ports[:20])}"
          f"{'...' if len(ports) > 20 else ''}")
    print()

    results = []
    for port in ports:
        # Quick connectivity check
        s = socket.socket()
        s.settimeout(timeout)
        reachable = s.connect_ex((ip, port)) == 0
        s.close()

        if not reachable:
            continue

        _, proto_name = PROTOCOL_PROBES.get(port, (b"", ""))
        use_ssl = PROTOCOL_PROBES.get(port, (b"", ""))[0] is None

        banner = _grab(ip, port, timeout=timeout, use_ssl=use_ssl)
        parsed = _parse_banner(port, banner)

        proto  = parsed["protocol"] or proto_name or "unknown"
        soft   = parsed["software"] or parsed["version"] or ""

        results.append({
            "port":    port,
            "proto":   proto,
            "soft":    soft,
            "banner":  banner,
            "parsed":  parsed,
        })

        # Live print
        status_icon = GREEN + "●" + RST if banner else YELLOW + "○" + RST
        soft_str = f"  {DIM}{soft[:50]}{RST}" if soft else ""
        print(f"    {status_icon}  {YELLOW}{port:<7}{RST} {CYAN}{proto:<18}{RST}{soft_str}")

    if not results:
        warn("No open/responding ports found.")
        sep()
        return

    # Detailed view
    show_detail = prompt("\nShow full banners? (y/n)", "y")
    if show_detail.lower() == "y":
        for r in results:
            if not r["banner"]:
                continue
            header(f"Port {r['port']}  ({r['proto']})")
            lines = r["banner"].splitlines()
            for line in lines[:20]:
                printable = "".join(c if c.isprintable() else "." for c in line)
                if printable.strip():
                    print(f"    {CYAN}{printable}{RST}")
            if len(lines) > 20:
                print(f"    {GRAY}... {len(lines)-20} more lines{RST}")
    sep()


def multi_host_banner():
    title_box("MULTI-HOST BANNER SCAN", "Check a single port across multiple hosts")
    info("Enter one IP/host per line. Empty line to start scan.")
    print()

    hosts = []
    while True:
        try:
            line = input(f"  {WHITE}Host (empty to start): {RST}").strip()
        except (KeyboardInterrupt, EOFError):
            break
        if not line:
            break
        hosts.append(line)

    if not hosts:
        return

    port = prompt("Port to check", "22")
    try:
        port = int(port)
    except ValueError:
        err("Invalid port.")
        return

    _, proto_name = PROTOCOL_PROBES.get(port, (b"", str(port)))
    sep()
    print(f"    {DIM}Grabbing banners on port {port} ({proto_name}) from {len(hosts)} hosts{RST}\n")

    for host in hosts:
        ip = resolve(host)
        if not ip:
            print(f"    {RED}✗{RST}  {host:<20} — could not resolve")
            continue

        s = socket.socket()
        s.settimeout(2)
        if s.connect_ex((ip, port)) != 0:
            s.close()
            print(f"    {GRAY}○{RST}  {host:<20} port {port} — closed")
            continue
        s.close()

        use_ssl = PROTOCOL_PROBES.get(port, (b"", ""))[0] is None
        banner  = _grab(ip, port, timeout=3.0, use_ssl=use_ssl)
        parsed  = _parse_banner(port, banner)
        soft    = parsed["software"] or parsed["version"] or (banner.splitlines()[0][:60] if banner else "no banner")

        icon = GREEN + "●" + RST if banner else YELLOW + "○" + RST
        print(f"    {icon}  {CYAN}{host:<20}{RST} {WHITE}{soft}{RST}")

    sep()
