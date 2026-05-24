"""
Crips Framework — iface_mod.py
Local Network Interfaces, Routing, MAC tools — netifaces + netaddr
"""

import socket
import subprocess
import shutil
import ipaddress
from modules.colors import *
from modules.utils import prompt, get_local_ip, get_hostname


def local_interfaces():
    title_box("NETWORK INTERFACES", "Show all local network adapters and addresses")

    try:
        import netifaces
    except ImportError:
        err("netifaces not installed → pip install netifaces")
        return

    sep()
    ifaces = netifaces.interfaces()
    gws    = netifaces.gateways()
    default_gw = gws.get("default", {}).get(netifaces.AF_INET, [None])[0]

    print(f"    {WHITE}Hostname        :{RST} {CYAN}{get_hostname()}{RST}")
    print(f"    {WHITE}Default Gateway :{RST} {CYAN}{default_gw or 'N/A'}{RST}\n")

    for iface in ifaces:
        addrs  = netifaces.ifaddresses(iface)
        ipv4   = addrs.get(netifaces.AF_INET, [])
        ipv6   = addrs.get(netifaces.AF_INET6, [])
        mac    = addrs.get(netifaces.AF_LINK, [{}])[0].get("addr", "")

        if not (ipv4 or ipv6 or mac):
            continue

        print(f"\n    {YELLOW}{BOLD}{iface}{RST}")
        if mac:
            print(f"      {GRAY}MAC     :{RST} {WHITE}{mac.upper()}{RST}")

        for a in ipv4:
            addr     = a.get("addr", "")
            netmask  = a.get("netmask", "")
            bcast    = a.get("broadcast", "")
            # Calculate CIDR prefix
            prefix = ""
            if netmask:
                try:
                    prefix = f"/{sum(bin(int(o)).count('1') for o in netmask.split('.'))}"
                except Exception:
                    prefix = ""
            gw_marker = f"  {GREEN}← default gw via {default_gw}{RST}" if \
                default_gw and _same_subnet(addr, netmask, default_gw) else ""
            print(f"      {CYAN}IPv4    :{RST} {WHITE}{addr}{prefix}{RST}  "
                  f"{GRAY}bcast {bcast}{RST}{gw_marker}")

        for a in ipv6:
            addr     = a.get("addr", "")
            prefix   = a.get("netmask", "")
            # Strip scope
            addr = addr.split("%")[0]
            print(f"      {BLUE}IPv6    :{RST} {WHITE}{addr}{RST}")
    sep()


def mac_lookup():
    title_box("MAC ADDRESS ANALYZER", "OUI vendor lookup + MAC info")
    mac_input = prompt("Enter MAC address (any format)")
    if not mac_input:
        return
    sep()

    # Normalize MAC
    mac_clean = mac_input.upper().replace(":", "").replace("-", "").replace(".", "")
    if len(mac_clean) != 12 or not all(c in "0123456789ABCDEF" for c in mac_clean):
        err("Invalid MAC address format.")
        return

    # Format variants
    mac_colon = ":".join(mac_clean[i:i+2] for i in range(0, 12, 2))
    mac_dash   = "-".join(mac_clean[i:i+2] for i in range(0, 12, 2))
    mac_dot    = ".".join(mac_clean[i:i+4] for i in range(0, 12, 4))
    oui        = mac_clean[:6]

    header("MAC Formats")
    kv("Colon",   mac_colon)
    kv("Dash",    mac_dash)
    kv("Dot",     mac_dot)
    kv("OUI",     oui)

    header("Flags")
    first_byte = int(mac_clean[:2], 16)
    is_multicast = bool(first_byte & 0x01)
    is_local     = bool(first_byte & 0x02)
    kv("Multicast bit", "Set (group address)"   if is_multicast else "Not set (unicast)")
    kv("Local/Admin bit", "Set (locally administered)" if is_local else "Not set (globally unique)")

    # OUI vendor lookup
    header("Vendor / OUI Lookup")
    vendor = _oui_lookup(oui)
    if vendor:
        ok(f"Vendor: {vendor}")
    else:
        # Try with netaddr library
        try:
            from netaddr import EUI
            mac_eui = EUI(mac_colon)
            org = mac_eui.oui.registration().org
            ok(f"Vendor (netaddr): {org}")
        except Exception:
            warn("Vendor not found in local OUI database.")
            info("Install netaddr for extended lookups: pip install netaddr")
    sep()


def network_speed_test():
    """Measure local DNS and gateway latency as a basic connectivity check."""
    title_box("CONNECTIVITY CHECK", "DNS resolution + gateway latency")
    import time

    targets = [
        ("Google DNS",     "8.8.8.8",        53),
        ("Cloudflare DNS", "1.1.1.1",         53),
        ("OpenDNS",        "208.67.222.222",  53),
        ("Google HTTP",    "google.com",      80),
        ("Cloudflare HTTP","cloudflare.com",  80),
    ]

    sep()
    print(f"    {YELLOW}{'Target':<22} {'Host':<22} {'Port':<6} {'Latency':<12} {'Status'}{RST}")
    print(f"    {GRAY}{'─'*70}{RST}")

    for name, host, port in targets:
        try:
            ip = socket.gethostbyname(host)
        except Exception:
            ip = host

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)
        t0 = time.time()
        code = s.connect_ex((ip, port))
        rtt  = (time.time() - t0) * 1000
        s.close()

        if code == 0:
            color = GREEN if rtt < 50 else YELLOW if rtt < 200 else RED
            print(f"    {WHITE}{name:<22}{RST} {CYAN}{ip:<22}{RST} "
                  f"{GRAY}{port:<6}{RST} {color}{rtt:6.1f} ms{RST}   {GREEN}OK{RST}")
        else:
            print(f"    {WHITE}{name:<22}{RST} {CYAN}{ip:<22}{RST} "
                  f"{GRAY}{port:<6}{RST} {'---':>10}     {RED}UNREACHABLE{RST}")

    # DNS resolution speed
    print()
    header("DNS Resolution Speed")
    domains = ["google.com", "cloudflare.com", "github.com", "amazon.com"]
    for domain in domains:
        import time
        t0 = time.time()
        try:
            ip = socket.gethostbyname(domain)
            rtt = (time.time() - t0) * 1000
            color = GREEN if rtt < 50 else YELLOW if rtt < 200 else RED
            print(f"    {CYAN}{domain:<20}{RST}  {WHITE}{ip:<18}{RST}  {color}{rtt:.1f} ms{RST}")
        except Exception as e:
            print(f"    {CYAN}{domain:<20}{RST}  {RED}FAILED: {e}{RST}")
    sep()


def open_connections():
    """Show current machine's active network connections (cross-platform)."""
    title_box("ACTIVE CONNECTIONS", "Current machine's open network sockets")

    try:
        import psutil
        has_psutil = True
    except ImportError:
        has_psutil = False

    sep()

    if has_psutil:
        import psutil
        connections = psutil.net_connections(kind="inet")
        rows = []
        for c in connections:
            la = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            ra = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            pid = str(c.pid or "")
            try:
                name = psutil.Process(int(pid)).name() if pid else ""
            except Exception:
                name = ""
            rows.append((c.type.name if hasattr(c.type, "name") else str(c.type),
                         la, ra, c.status, pid, name))
        if rows:
            print_table(rows, ["PROTO", "LOCAL", "REMOTE", "STATUS", "PID", "PROCESS"],
                        [6, 25, 25, 12, 7, 20])
        else:
            warn("No active connections found.")
        sep()
        return

    # Fallback: ss or netstat
    for cmd in (["ss", "-tunapH"], ["netstat", "-tunapl"]):
        if shutil.which(cmd[0]):
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.stdout:
                lines = result.stdout.splitlines()
                for line in lines[:50]:
                    if line.strip():
                        print(f"    {CYAN}{line}{RST}")
                if len(lines) > 50:
                    warn(f"... {len(lines)-50} more lines")
            sep()
            return

    warn("Install psutil for detailed connection info: pip install psutil")
    sep()


# ── Helpers ───────────────────────────────────────────────────

def _same_subnet(ip: str, mask: str, gw: str) -> bool:
    try:
        net1 = ipaddress.ip_network(f"{ip}/{mask}", strict=False)
        return ipaddress.ip_address(gw) in net1
    except Exception:
        return False


def _oui_lookup(oui: str) -> str:
    """Small curated OUI table."""
    OUI = {
        "000000": "Xerox Corp.",
        "000569": "VMware Inc.",
        "000C29": "VMware Inc.",
        "005056": "VMware Inc.",
        "080027": "Oracle VirtualBox",
        "0A0027": "Oracle VirtualBox",
        "28D244": "Raspberry Pi Trading",
        "B827EB": "Raspberry Pi Foundation",
        "DCA632": "Raspberry Pi Trading",
        "E45F01": "Raspberry Pi Trading",
        "001A11": "Google Inc.",
        "94EB2C": "Google Inc.",
        "3C5AB4": "Google Inc.",
        "F4F5D8": "Google Inc.",
        "001C25": "Intel Corporate",
        "001D6A": "Intel Corporate",
        "001E67": "Intel Corporate",
        "001B21": "Intel Corporate",
        "FCFBFB": "Apple Inc.",
        "001CB3": "Apple Inc.",
        "002332": "Apple Inc.",
        "0026B0": "Apple Inc.",
        "003EE1": "Apple Inc.",
        "74D02B": "Dell Inc.",
        "001422": "Dell Inc.",
        "001E4F": "Dell Inc.",
        "002564": "Dell Inc.",
        "001A4B": "Netgear",
        "001F33": "Netgear",
        "CC40D0": "Netgear",
        "14F65A": "TP-Link Technologies",
        "50C7BF": "TP-Link Technologies",
        "E8DE27": "TP-Link Technologies",
        "001D0F": "ASUS",
        "001E8C": "ASUS",
        "002215": "ASUS",
        "0050F2": "Microsoft Corporation",
        "00155D": "Microsoft Corporation",
        "4CCC6A": "Microsoft Corporation",
        "001122": "Cisco Systems",
        "00000C": "Cisco Systems",
        "001A2B": "Cisco Systems",
        "001FB5": "Cisco Systems",
        "C42502": "Cisco Systems",
        "001B21": "Intel Corp.",
    }
    return OUI.get(oui.upper(), "")
