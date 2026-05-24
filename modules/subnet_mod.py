"""
Crips Framework — subnet_mod.py
Subnet Calculator, IP Info, CIDR tools — netaddr + ipaddress
"""

import ipaddress
from modules.colors import *
from modules.utils import prompt, require, is_valid_ip, is_valid_cidr


def subnet_calculator():
    title_box("SUBNET CALCULATOR", "Network math — addresses, masks, ranges")

    target = prompt("Enter IP, CIDR, or IP/mask (e.g. 192.168.1.50/24)")
    if not target:
        return
    sep()

    # Support "IP mask" format → convert to CIDR
    if " " in target:
        parts = target.split()
        try:
            net_obj = ipaddress.ip_network(f"{parts[0]}/{parts[1]}", strict=False)
            target = str(net_obj)
        except Exception:
            pass

    try:
        # Try network first
        if "/" in target:
            host_ip = target.split("/")[0]
            net = ipaddress.ip_network(target, strict=False)
            host_obj = ipaddress.ip_interface(target)
        else:
            host_ip = target
            net = ipaddress.ip_network(target + "/32")
            host_obj = ipaddress.ip_interface(target + "/32")

        addr = ipaddress.ip_address(host_ip)

        header("Network Info")
        kv("Input",            target)
        kv("IP Address",       str(addr))
        kv("Network",          str(net.network_address))
        kv("Broadcast",        str(net.broadcast_address))
        kv("Netmask",          str(net.netmask))
        kv("Wildcard",         str(net.hostmask))
        kv("Prefix Length",    f"/{net.prefixlen}")
        kv("Total Addresses",  f"{net.num_addresses:,}")
        usable = max(0, net.num_addresses - 2) if net.prefixlen < 31 else net.num_addresses
        kv("Usable Hosts",     f"{usable:,}")
        kv("First Host",       str(net.network_address + 1) if net.prefixlen < 31 else str(net.network_address))
        kv("Last Host",        str(net.broadcast_address - 1) if net.prefixlen < 31 else str(net.broadcast_address))
        kv("IP Class",         _ip_class(str(net.network_address)))
        kv("IP Version",       f"IPv{net.version}")
        kv("Private",          "Yes" if net.is_private else "No")
        kv("Global",           "Yes" if addr.is_global else "No")
        kv("Multicast",        "Yes" if addr.is_multicast else "No")
        kv("Loopback",         "Yes" if addr.is_loopback else "No")
        kv("Link-local",       "Yes" if addr.is_link_local else "No")

        # Binary representations
        header("Binary Representation")
        addr_bin = _ip_to_binary(str(addr))
        mask_bin = _ip_to_binary(str(net.netmask))
        net_bin  = _ip_to_binary(str(net.network_address))
        bcast_bin= _ip_to_binary(str(net.broadcast_address))
        prefix   = net.prefixlen

        print(f"    {YELLOW}IP Address{RST} : {GREEN}{addr_bin[:prefix]}{RST}{RED}{addr_bin[prefix:]}{RST}  ({addr})")
        print(f"    {YELLOW}Netmask   {RST} : {GREEN}{mask_bin[:prefix]}{RST}{RED}{mask_bin[prefix:]}{RST}  ({net.netmask})")
        print(f"    {YELLOW}Network   {RST} : {GREEN}{net_bin[:prefix]}{RST}{RED}{net_bin[prefix:]}{RST}  ({net.network_address})")
        print(f"    {YELLOW}Broadcast {RST} : {GREEN}{bcast_bin[:prefix]}{RST}{RED}{bcast_bin[prefix:]}{RST}  ({net.broadcast_address})")

        # Hex
        header("Hexadecimal")
        kv("IP (hex)",    " ".join(f"{int(o):02X}" for o in str(addr).split(".")))
        kv("Mask (hex)",  " ".join(f"{int(o):02X}" for o in str(net.netmask).split(".")))

        # In-addr.arpa
        rev = ".".join(reversed(str(net.network_address).split(".")))
        kv("Reverse DNS", f"{rev}.in-addr.arpa")

    except ValueError as e:
        err(f"Invalid input: {e}")
    sep()


def subnet_split():
    title_box("SUBNET SPLITTER", "Divide a network into equal sub-networks")
    cidr = prompt("Enter network CIDR (e.g. 10.0.0.0/8)")
    new_prefix = prompt("New prefix length (e.g. 24 to split into /24s)")
    if not cidr or not new_prefix:
        return

    try:
        net = ipaddress.ip_network(cidr, strict=False)
        new_prefix = int(new_prefix)
        if new_prefix <= net.prefixlen:
            err("New prefix must be larger (more specific) than the original.")
            return
        subnets = list(net.subnets(new_prefix=new_prefix))
        total = len(subnets)
    except Exception as e:
        err(f"Error: {e}")
        return

    sep()
    hosts_per = max(0, 2 ** (32 - new_prefix) - 2) if new_prefix < 31 else 1
    print(f"    {WHITE}Original:{RST}    {CYAN}{cidr}{RST}")
    print(f"    {WHITE}Subnets: {RST}    {YELLOW}{total}{RST}  (/{new_prefix} each, {hosts_per} usable hosts)")
    print()

    LIMIT = 256
    display = subnets[:LIMIT]
    rows = []
    for i, s in enumerate(display):
        rows.append((
            str(i+1),
            str(s),
            str(s.network_address),
            str(s.broadcast_address),
            str(s.netmask),
            str(hosts_per),
        ))

    print_table(rows, ["#", "Network/Prefix", "Network Addr", "Broadcast", "Netmask", "Hosts"],
                [5, 20, 16, 16, 16, 7])
    if total > LIMIT:
        warn(f"  ... {total - LIMIT} more subnets not displayed.")
    sep()


def ip_info():
    title_box("IP ADDRESS INFO", "Classify and analyze a single IP address")
    ip_str = prompt("Enter IP address")
    if not ip_str:
        return
    sep()

    try:
        addr = ipaddress.ip_address(ip_str)
        net  = ipaddress.ip_network(ip_str + "/32")

        header("IP Classification")
        kv("Address",     str(addr))
        kv("Version",     f"IPv{addr.version}")
        kv("Type",        _classify_ip(addr))
        kv("Class",       _ip_class(ip_str) if addr.version == 4 else "N/A (IPv6)")
        kv("Private",     "Yes" if addr.is_private else "No")
        kv("Global",      "Yes" if addr.is_global else "No")
        kv("Loopback",    "Yes" if addr.is_loopback else "No")
        kv("Multicast",   "Yes" if addr.is_multicast else "No")
        kv("Link-local",  "Yes" if addr.is_link_local else "No")
        kv("Reserved",    "Yes" if addr.is_reserved else "No")
        kv("Unspecified", "Yes" if addr.is_unspecified else "No")

        if addr.version == 4:
            header("Format Representations")
            octs = str(addr).split(".")
            kv("Dotted Decimal", str(addr))
            kv("Decimal (int)",  str(int(addr)))
            kv("Hex",           " ".join(f"0x{int(o):02X}" for o in octs))
            kv("Binary",        _ip_to_binary(str(addr)))
            kv("Octal",         ".".join(f"{int(o):o}" for o in octs))

            # RFC info
            rfc = _get_rfc(addr)
            if rfc:
                print()
                header("RFC Reference")
                for r in rfc:
                    print(f"    {CYAN}  {r}{RST}")

    except ValueError as e:
        err(f"Invalid IP: {e}")
    sep()


def cidr_range_list():
    title_box("CIDR → IP RANGE", "Expand CIDR to first/last and optionally list all IPs")
    cidr = prompt("Enter CIDR")
    if not cidr:
        return
    if not is_valid_cidr(cidr):
        err("Invalid CIDR.")
        return
    sep()

    try:
        net   = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        kv("Network",   str(net.network_address))
        kv("Broadcast", str(net.broadcast_address))
        kv("First",     str(hosts[0]) if hosts else str(net.network_address))
        kv("Last",      str(hosts[-1]) if hosts else str(net.broadcast_address))
        kv("Count",     f"{len(hosts):,} usable hosts")
        print()

        if len(hosts) <= 256:
            show = prompt(f"List all {len(hosts)} IPs? (y/n)", "n")
            if show.lower() == "y":
                for h in hosts:
                    print(f"    {CYAN}{h}{RST}")
        else:
            warn(f"Too many IPs to list ({len(hosts):,}) — showing first/last only.")
    except Exception as e:
        err(f"Error: {e}")
    sep()


def ipv6_info():
    title_box("IPv6 TOOLS", "IPv6 address analysis and expansion")
    ip_str = prompt("Enter IPv6 address (compressed or full)")
    if not ip_str:
        return
    sep()

    try:
        addr = ipaddress.IPv6Address(ip_str)

        header("IPv6 Info")
        kv("Compressed",   str(addr))
        kv("Expanded",     addr.exploded)
        kv("Integer",      str(int(addr)))
        kv("Private",      "Yes" if addr.is_private else "No")
        kv("Global",       "Yes" if addr.is_global else "No")
        kv("Loopback",     "Yes" if addr.is_loopback else "No")
        kv("Link-local",   "Yes" if addr.is_link_local else "No")
        kv("Multicast",    "Yes" if addr.is_multicast else "No")
        kv("IPv4 mapped",  str(addr.ipv4_mapped) if addr.ipv4_mapped else "No")
        kv("Scope",        str(getattr(addr, 'scope_id', 'N/A')))

        # Reverse DNS form
        rev = ".".join(reversed(addr.exploded.replace(":", ""))) + ".ip6.arpa"
        kv("Reverse DNS",  rev)

        # Common IPv6 ranges
        kv("Type", _classify_ipv6(addr))

    except ValueError as e:
        err(f"Invalid IPv6: {e}")
    sep()


# ── Helpers ───────────────────────────────────────────────────

def _ip_to_binary(ip: str) -> str:
    return "".join(f"{int(o):08b}" for o in ip.split("."))


def _ip_class(ip: str) -> str:
    first = int(ip.split(".")[0])
    if first < 128:    return "A"
    if first < 192:    return "B"
    if first < 224:    return "C"
    if first < 240:    return "D (Multicast)"
    return "E (Reserved)"


def _classify_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    if addr.is_loopback:    return "Loopback"
    if addr.is_multicast:   return "Multicast"
    if addr.is_link_local:  return "Link-local"
    if addr.is_private:     return "Private (RFC1918)"
    if addr.is_reserved:    return "Reserved"
    if addr.is_global:      return "Public / Routable"
    return "Unknown"


def _classify_ipv6(addr: ipaddress.IPv6Address) -> str:
    s = str(addr)
    if addr.is_loopback:                  return "Loopback (::1)"
    if s.startswith("fe80"):              return "Link-local (fe80::/10)"
    if s.startswith("fc") or s.startswith("fd"): return "Unique Local (fc00::/7)"
    if s.startswith("ff"):                return "Multicast (ff00::/8)"
    if s == "::":                         return "Unspecified (::)"
    if addr.ipv4_mapped:                  return "IPv4-mapped (::ffff:x.x.x.x)"
    return "Global Unicast"


def _get_rfc(addr: ipaddress.IPv4Address) -> list[str]:
    RFC_RANGES = [
        ("0.0.0.0/8",        "RFC 1122 — This network"),
        ("10.0.0.0/8",       "RFC 1918 — Private (Class A)"),
        ("100.64.0.0/10",    "RFC 6598 — Shared address space"),
        ("127.0.0.0/8",      "RFC 1122 — Loopback"),
        ("169.254.0.0/16",   "RFC 3927 — Link-local (APIPA)"),
        ("172.16.0.0/12",    "RFC 1918 — Private (Class B)"),
        ("192.0.0.0/24",     "RFC 6890 — IETF protocol"),
        ("192.168.0.0/16",   "RFC 1918 — Private (Class C)"),
        ("198.18.0.0/15",    "RFC 2544 — Benchmarking"),
        ("198.51.100.0/24",  "RFC 5737 — Documentation (TEST-NET-2)"),
        ("203.0.113.0/24",   "RFC 5737 — Documentation (TEST-NET-3)"),
        ("224.0.0.0/4",      "RFC 1112 — Multicast"),
        ("240.0.0.0/4",      "RFC 1112 — Reserved / Future use"),
        ("255.255.255.255/32","RFC 919  — Limited broadcast"),
    ]
    matches = []
    for cidr, desc in RFC_RANGES:
        try:
            if addr in ipaddress.ip_network(cidr):
                matches.append(f"{cidr}  →  {desc}")
        except Exception:
            pass
    return matches
