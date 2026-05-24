"""
Crips Framework — portscan_mod.py
TCP Connect Port Scanner — pure Python socket, no root required
Teaches TCP 3-way handshake and service discovery concepts
"""

import socket
import threading
import time
import queue
from modules.colors import *
from modules.utils import prompt, resolve, human_port
import ipaddress


# Common port → service + description mapping
SERVICE_INFO = {
    20:   ("FTP-DATA",  "FTP data transfer"),
    21:   ("FTP",       "File Transfer Protocol"),
    22:   ("SSH",       "Secure Shell"),
    23:   ("TELNET",    "Telnet (cleartext)"),
    25:   ("SMTP",      "Mail Transfer"),
    53:   ("DNS",       "Domain Name System"),
    67:   ("DHCP",      "DHCP Server"),
    68:   ("DHCP",      "DHCP Client"),
    69:   ("TFTP",      "Trivial FTP"),
    80:   ("HTTP",      "Web Server"),
    88:   ("KERBEROS",  "Kerberos auth"),
    110:  ("POP3",      "Mail retrieval"),
    111:  ("RPCBIND",   "RPC portmapper"),
    119:  ("NNTP",      "Usenet news"),
    123:  ("NTP",       "Network Time Protocol"),
    135:  ("MSRPC",     "Windows RPC"),
    137:  ("NETBIOS",   "NetBIOS name"),
    138:  ("NETBIOS",   "NetBIOS datagram"),
    139:  ("NETBIOS",   "NetBIOS session"),
    143:  ("IMAP",      "Internet Mail Access"),
    161:  ("SNMP",      "Simple Network Mgmt"),
    162:  ("SNMPTRAP",  "SNMP Trap"),
    179:  ("BGP",       "Border Gateway Protocol"),
    194:  ("IRC",       "Internet Relay Chat"),
    389:  ("LDAP",      "Directory Service"),
    443:  ("HTTPS",     "Secure Web Server"),
    445:  ("SMB",       "Windows File Sharing"),
    465:  ("SMTPS",     "Secure Mail (legacy)"),
    514:  ("SYSLOG",    "System logging"),
    515:  ("LPD",       "Line Printer Daemon"),
    587:  ("SUBMISSION","Mail submission"),
    631:  ("IPP",       "Internet Printing"),
    636:  ("LDAPS",     "Secure LDAP"),
    993:  ("IMAPS",     "Secure IMAP"),
    995:  ("POP3S",     "Secure POP3"),
    1080: ("SOCKS",     "SOCKS proxy"),
    1194: ("OPENVPN",   "OpenVPN"),
    1433: ("MSSQL",     "MS SQL Server"),
    1521: ("ORACLE",    "Oracle DB"),
    1723: ("PPTP",      "VPN tunnel"),
    2049: ("NFS",       "Network File System"),
    2181: ("ZOOKEEPER", "Apache ZooKeeper"),
    2375: ("DOCKER",    "Docker daemon (unsafe!)"),
    2376: ("DOCKER-TLS","Docker TLS"),
    2379: ("ETCD",      "etcd key-value"),
    3000: ("DEV-HTTP",  "Dev web server"),
    3306: ("MYSQL",     "MySQL Database"),
    3389: ("RDP",       "Remote Desktop"),
    3690: ("SVN",       "Subversion"),
    4000: ("ICQ",       "ICQ messaging"),
    4444: ("METASPLOIT","Metasploit default"),
    4848: ("GLASSFISH", "GlassFish admin"),
    5000: ("DEV-HTTP",  "Flask/dev server"),
    5432: ("POSTGRESQL","PostgreSQL DB"),
    5900: ("VNC",       "Virtual Network Computing"),
    5984: ("COUCHDB",   "CouchDB"),
    6379: ("REDIS",     "Redis in-memory DB"),
    6443: ("K8S-API",   "Kubernetes API"),
    7001: ("WEBLOGIC",  "WebLogic admin"),
    8080: ("HTTP-ALT",  "Alt HTTP / Tomcat"),
    8443: ("HTTPS-ALT", "Alt HTTPS"),
    8888: ("JUPYTER",   "Jupyter Notebook"),
    9000: ("PHP-FPM",   "PHP FastCGI"),
    9090: ("PROMETHEUS","Prometheus metrics"),
    9200: ("ELASTIC",   "Elasticsearch HTTP"),
    9300: ("ELASTIC",   "Elasticsearch cluster"),
    9418: ("GIT",       "Git protocol"),
    10250:("KUBELET",   "Kubernetes kubelet"),
    11211:("MEMCACHED", "Memcached"),
    27017:("MONGODB",   "MongoDB"),
    27018:("MONGODB",   "MongoDB shard"),
    50070:("HADOOP",    "Hadoop NameNode"),
}

PORT_GROUPS = {
    "top20":   [21,22,23,25,53,80,110,111,135,139,
                143,443,445,993,995,1723,3306,3389,5900,8080],
    "top100":  sorted(SERVICE_INFO.keys())[:100],
    "web":     [80,443,8080,8443,8000,8008,8888,3000,5000,9000],
    "db":      [1433,1521,3306,5432,6379,9200,9300,11211,27017,27018,5984],
    "mail":    [25,110,143,465,587,993,995],
    "remote":  [22,23,3389,5900,4444,1080,1194],
    "infra":   [53,67,123,161,179,389,636,2049,2181,6443,10250],
    "common":  [21,22,23,25,53,80,110,143,443,445,3306,3389,8080],
}


def _scan_port(ip: str, port: int, timeout: float,
               results: dict, semaphore: threading.Semaphore):
    """Try TCP connect to a single port."""
    semaphore.acquire()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        t0 = time.time()
        code = s.connect_ex((ip, port))
        rtt = (time.time() - t0) * 1000
        s.close()
        if code == 0:
            results[port] = {"state": "open", "rtt": rtt}
        else:
            results[port] = {"state": "closed"}
    except socket.timeout:
        results[port] = {"state": "filtered"}
    except Exception:
        results[port] = {"state": "error"}
    finally:
        semaphore.release()


def port_scan():
    title_box("TCP PORT SCANNER", "Multi-threaded TCP connect scan — no root needed")

    target = prompt("Enter IP or Domain")
    if not target:
        return

    ip = resolve(target)
    if not ip:
        return

    # Port selection
    print(f"\n    {YELLOW}Port groups:{RST}  "
          + "  ".join(f"{CYAN}{k}{RST}" for k in PORT_GROUPS))
    port_input = prompt("Ports / group / range", "top20")
    threads    = prompt("Threads (1-500)", "150")
    timeout    = prompt("Timeout seconds per port", "1.0")

    try:
        threads = min(500, max(1, int(threads)))
        timeout = float(timeout)
    except ValueError:
        threads, timeout = 150, 1.0

    # Parse ports
    ports = _parse_ports(port_input)
    if not ports:
        err("No valid ports specified.")
        return

    sep()
    print(f"    {WHITE}Target   :{RST} {CYAN}{target}{RST} ({ip})")
    print(f"    {WHITE}Ports    :{RST} {len(ports)} ports")
    print(f"    {WHITE}Threads  :{RST} {threads}")
    print(f"    {WHITE}Timeout  :{RST} {timeout}s\n")

    # Threaded scan
    results = {}
    semaphore = threading.Semaphore(threads)
    thread_list = []
    t_start = time.time()

    for port in ports:
        t = threading.Thread(
            target=_scan_port,
            args=(ip, port, timeout, results, semaphore),
            daemon=True
        )
        thread_list.append(t)
        t.start()

    # Progress bar
    total = len(ports)
    while any(t.is_alive() for t in thread_list):
        done = len(results)
        pct  = done / total * 100 if total else 100
        bar  = GREEN + "█" * int(pct // 5) + GRAY + "░" * (20 - int(pct // 5)) + RST
        print(f"\r    {bar} {CYAN}{done}/{total}{RST} ports scanned", end="", flush=True)
        time.sleep(0.1)
    for t in thread_list:
        t.join()
    elapsed = time.time() - t_start
    print(f"\r    {GREEN}{'█'*20}{RST} {total}/{total} done in {elapsed:.1f}s          ")

    # Print results
    open_ports = {p: v for p, v in results.items() if v["state"] == "open"}
    filtered   = {p: v for p, v in results.items() if v["state"] == "filtered"}

    if open_ports:
        header(f"Open Ports ({len(open_ports)} found)")
        rows = []
        for port in sorted(open_ports):
            rtt = open_ports[port].get("rtt", 0)
            svc_name, svc_desc = SERVICE_INFO.get(port, ("", ""))
            if not svc_name:
                try:
                    svc_name = socket.getservbyport(port)
                except Exception:
                    svc_name = "unknown"
            rows.append((str(port), "tcp", "open", svc_name, f"{rtt:.1f}ms", svc_desc))

        print_table(
            rows,
            ["PORT", "PROTO", "STATE", "SERVICE", "RTT", "DESCRIPTION"],
            [7, 6, 8, 14, 9, 30]
        )
    else:
        warn("No open ports found in scanned range.")

    if filtered:
        print(f"\n    {GRAY}Filtered (no response): "
              f"{', '.join(str(p) for p in sorted(filtered)[:20])}"
              f"{'...' if len(filtered) > 20 else ''}{RST}")

    print(f"\n    {DIM}Scanned {len(results)} ports in {elapsed:.1f}s  |  "
          f"{len(open_ports)} open  |  {len(filtered)} filtered  |  "
          f"{len(results)-len(open_ports)-len(filtered)} closed{RST}")
    sep()


# ── Port range scanner for a subnet ──────────────────────────
def network_port_scan():
    title_box("NETWORK PORT SCAN", "Scan a port across an entire subnet")
    cidr  = prompt("Enter CIDR (e.g. 192.168.1.0/24)")
    port  = prompt("Port to check on all hosts", "22")
    conc  = prompt("Concurrent checks", "100")

    try:
        port = int(port)
        conc = min(300, max(1, int(conc)))
    except ValueError:
        err("Invalid port or concurrency value.")
        return
    if not cidr:
        return

    try:
        net   = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
    except ValueError as e:
        err(f"Invalid CIDR: {e}")
        return
    if len(hosts) > 65536:
        err("Network too large (max /16).")
        return

    sep()
    step(f"Checking port {port} on {len(hosts)} hosts ...\n")

    open_hosts = []
    lock = threading.Lock()
    sem  = threading.Semaphore(conc)

    def check(ip_obj):
        ip_str = str(ip_obj)
        sem.acquire()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.0)
            if s.connect_ex((ip_str, port)) == 0:
                with lock:
                    open_hosts.append(ip_str)
            s.close()
        except Exception:
            pass
        finally:
            sem.release()

    threads = [threading.Thread(target=check, args=(h,), daemon=True)
               for h in hosts]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    svc_name, svc_desc = SERVICE_INFO.get(port, ("", ""))
    header(f"Hosts with port {port} ({svc_name}) open: {len(open_hosts)}")
    for h in sorted(open_hosts, key=lambda x: ipaddress.ip_address(x)):
        try:
            hostname = socket.gethostbyaddr(h)[0]
        except Exception:
            hostname = ""
        hn = f"  {GRAY}{hostname}{RST}" if hostname else ""
        print(f"    {GREEN}●{RST}  {CYAN}{h:<18}{RST}{hn}")

    if not open_hosts:
        warn(f"No hosts with port {port} open found.")
    sep()


def _parse_ports(spec: str) -> list[int]:
    """Parse port spec: group name, range, comma list, or 'all'."""
    spec = spec.strip().lower()
    if spec in PORT_GROUPS:
        return PORT_GROUPS[spec]
    if spec == "all":
        return list(range(1, 65536))

    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            try:
                a, b = part.split("-", 1)
                ports.update(range(int(a), int(b) + 1))
            except ValueError:
                pass
        elif part.isdigit():
            ports.add(int(part))
    return sorted(p for p in ports if 1 <= p <= 65535)
