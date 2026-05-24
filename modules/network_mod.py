"""
Crips Framework — network_mod.py
Ping, Ping Sweep, Traceroute, ARP Scan — scapy
Note: ICMP/ARP functions require root/sudo
"""

import time
import socket
import threading
from modules.colors import *
from modules.utils import prompt, resolve, is_valid_cidr, tcp_connect
import ipaddress


# ── 1. ICMP Ping ──────────────────────────────────────────────
def ping():
    title_box("ICMP PING", "Send ICMP echo requests — requires sudo")
    target = prompt("Enter IP or Domain")
    if not target:
        return
    count = prompt("Number of pings", "4")
    try:
        count = int(count)
    except ValueError:
        count = 4

    ip = resolve(target)
    if not ip:
        return
    sep()
    print(f"    {DIM}PING {target} ({ip}) — {count} packets{RST}\n")

    try:
        from scapy.layers.inet import IP, ICMP
        from scapy.sendrecv import sr1
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

        sent = 0
        recv = 0
        rtts = []

        for seq in range(1, count + 1):
            pkt = IP(dst=ip) / ICMP(id=0x1234, seq=seq)
            t0  = time.time()
            reply = sr1(pkt, verbose=0, timeout=2)
            rtt  = (time.time() - t0) * 1000
            sent += 1

            if reply is None:
                print(f"    {RED}Request timeout for seq={seq}{RST}")
            else:
                recv += 1
                rtts.append(rtt)
                icmp_type = reply.getlayer(ICMP).type
                if icmp_type == 0:
                    print(f"    {GREEN}Reply from {reply.src:<15}{RST}  "
                          f"seq={seq}  ttl={reply.ttl}  "
                          f"time={CYAN}{rtt:.2f} ms{RST}")
                elif icmp_type == 3:
                    print(f"    {YELLOW}Destination unreachable from {reply.src}{RST}")
                else:
                    print(f"    {YELLOW}ICMP type={icmp_type} from {reply.src}{RST}")
            time.sleep(0.5)

        loss = 100 * (sent - recv) // sent if sent else 100
        print()
        print(f"    {DIM}--- {target} ping statistics ---{RST}")
        print(f"    {YELLOW}{sent} transmitted, {GREEN}{recv} received{RST}, "
              f"{RED if loss else GREEN}{loss}% packet loss{RST}")
        if rtts:
            print(f"    rtt min/avg/max = "
                  f"{CYAN}{min(rtts):.2f}{RST}/"
                  f"{CYAN}{sum(rtts)/len(rtts):.2f}{RST}/"
                  f"{CYAN}{max(rtts):.2f}{RST} ms")

    except PermissionError:
        err("Root required for ICMP. Run: sudo python3 crips.py")
    except ImportError:
        err("scapy not installed → pip install scapy")
    except Exception as e:
        err(f"Ping error: {e}")
    sep()


# ── 2. Ping Sweep ─────────────────────────────────────────────
def ping_sweep():
    title_box("PING SWEEP", "Discover live hosts in a subnet — requires sudo")
    cidr = prompt("Enter CIDR (e.g. 192.168.1.0/24)")
    if not cidr:
        return
    if not is_valid_cidr(cidr):
        err("Invalid CIDR notation.")
        return

    timeout_ms = prompt("Timeout ms per host", "500")
    try:
        timeout = int(timeout_ms) / 1000
    except ValueError:
        timeout = 0.5

    sep()

    try:
        from scapy.layers.inet import IP, ICMP
        from scapy.sendrecv import sr
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

        net = ipaddress.ip_network(cidr, strict=False)
        hosts = list(net.hosts())
        if len(hosts) > 1024:
            warn("Subnet > 1024 hosts — limiting to first 1024.")
            hosts = hosts[:1024]

        step(f"Sweeping {len(hosts)} hosts in {cidr} ...\n")
        pkts = [IP(dst=str(h)) / ICMP() for h in hosts]
        answered, _ = sr(pkts, timeout=timeout, verbose=0)

        alive = []
        for sent_pkt, reply_pkt in answered:
            src = reply_pkt.src
            try:
                hostname = socket.gethostbyaddr(src)[0]
            except Exception:
                hostname = ""
            alive.append((src, hostname))

        alive.sort(key=lambda x: ipaddress.ip_address(x[0]))

        header(f"Live Hosts ({len(alive)} / {len(hosts)})")
        for ip_str, hostname in alive:
            hn = f"  {DIM}{hostname}{RST}" if hostname else ""
            print(f"    {GREEN}●{RST}  {CYAN}{ip_str:<18}{RST}{hn}")

        if not alive:
            warn("No live hosts found.")

    except PermissionError:
        err("Root required for ICMP sweep. Run: sudo python3 crips.py")
    except ImportError:
        err("scapy not installed → pip install scapy")
    except Exception as e:
        err(f"Sweep error: {e}")
    sep()


# ── 3. Traceroute ─────────────────────────────────────────────
def traceroute():
    title_box("TRACEROUTE", "ICMP/UDP hop-by-hop path discovery — requires sudo")
    target = prompt("Enter IP or Domain")
    if not target:
        return
    max_hops = prompt("Max hops", "30")
    proto    = prompt("Protocol (icmp/udp)", "icmp")
    try:
        max_hops = int(max_hops)
    except ValueError:
        max_hops = 30

    ip = resolve(target)
    if not ip:
        return
    sep()
    print(f"    {DIM}Traceroute to {target} ({ip}), max {max_hops} hops{RST}\n")
    print(f"    {'HOP':<5} {'IP':<18} {'RTT':<12} {'HOSTNAME'}")
    print(f"    {GRAY}{'─'*56}{RST}")

    try:
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        from scapy.sendrecv import sr1
        from scapy.layers.inet import IP, ICMP, UDP

        for ttl in range(1, max_hops + 1):
            if proto.lower() == "udp":
                pkt = IP(dst=ip, ttl=ttl) / UDP(dport=33434 + ttl)
            else:
                pkt = IP(dst=ip, ttl=ttl) / ICMP(id=0x4321, seq=ttl)

            t0    = time.time()
            reply = sr1(pkt, verbose=0, timeout=2)
            rtt   = f"{(time.time()-t0)*1000:.1f} ms"

            if reply is None:
                print(f"    {YELLOW}{ttl:<5}{RST} {'* * *':<18} {DIM}{rtt}{RST}")
                continue

            src = reply.src
            try:
                hostname = socket.gethostbyaddr(src)[0]
            except Exception:
                hostname = ""

            color = GREEN if src == ip else CYAN
            print(f"    {color}{ttl:<5}{RST} {CYAN}{src:<18}{RST} {WHITE}{rtt:<12}{RST} "
                  f"{GRAY}{hostname}{RST}")

            if src == ip:
                print(f"\n    {GREEN}[✓] Destination reached in {ttl} hops.{RST}")
                break

    except PermissionError:
        err("Root required. Run: sudo python3 crips.py")
    except ImportError:
        err("scapy not installed → pip install scapy")
    except Exception as e:
        err(f"Traceroute error: {e}")
    sep()


# ── 4. ARP Scan (local network) ───────────────────────────────
def arp_scan():
    title_box("ARP SCAN", "Discover devices on local network — requires sudo")
    info("ARP works only on your local subnet (Layer 2).")

    # Show local interfaces
    try:
        import netifaces
        ifaces = netifaces.interfaces()
        print(f"\n    {YELLOW}Available interfaces:{RST}")
        for iface in ifaces:
            addrs = netifaces.ifaddresses(iface)
            ipv4 = addrs.get(netifaces.AF_INET, [])
            for a in ipv4:
                addr = a.get("addr","")
                mask = a.get("netmask","")
                if addr and not addr.startswith("127."):
                    print(f"    {CYAN}{iface:<12}{RST} {WHITE}{addr}{RST}  mask {GRAY}{mask}{RST}")
    except ImportError:
        pass

    print()
    cidr = prompt("Enter CIDR to scan (e.g. 192.168.1.0/24)")
    if not cidr:
        return
    if not is_valid_cidr(cidr):
        err("Invalid CIDR.")
        return
    sep()

    try:
        import logging
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        from scapy.layers.l2 import ARP, Ether
        from scapy.sendrecv import srp

        step(f"Sending ARP requests to {cidr} ...\n")
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=cidr)
        answered, _ = srp(pkt, timeout=3, verbose=0)

        devices = []
        for sent_pkt, recv_pkt in answered:
            ip_addr = recv_pkt.psrc
            mac     = recv_pkt.hwsrc.upper()
            # Vendor lookup via OUI
            vendor = _mac_vendor(mac)
            try:
                hostname = socket.gethostbyaddr(ip_addr)[0]
            except Exception:
                hostname = ""
            devices.append((ip_addr, mac, vendor, hostname))

        devices.sort(key=lambda x: ipaddress.ip_address(x[0]))

        header(f"Devices Found ({len(devices)})")
        if devices:
            print_table(
                devices,
                ["IP Address", "MAC Address", "Vendor", "Hostname"],
                [16, 20, 25, 30]
            )
        else:
            warn("No devices responded to ARP requests.")

    except PermissionError:
        err("Root required for ARP. Run: sudo python3 crips.py")
    except ImportError:
        err("scapy not installed → pip install scapy")
    except Exception as e:
        err(f"ARP scan error: {e}")
    sep()


def _mac_vendor(mac: str) -> str:
    """Lookup MAC vendor from OUI prefix."""
    oui = mac.replace(":", "").replace("-", "")[:6].upper()
    # Small curated OUI table of the most common vendors
    OUI_TABLE = {
        "000000": "Xerox", "00000C": "Cisco", "0000E8": "Accton",
        "000569": "VMware", "000C29": "VMware", "005056": "VMware",
        "080027": "VirtualBox", "0A0027": "VirtualBox",
        "001A2B": "Cisco", "001B21": "Intel", "001C25": "Intel",
        "001D6A": "Intel", "001E67": "Intel", "001F3C": "Intel",
        "0026B9": "Intel", "0050F2": "Microsoft",
        "001122": "Cimsys", "002248": "iRobot",
        "28D244": "Raspberry Pi", "B827EB": "Raspberry Pi",
        "DC:A6:32": "Raspberry Pi", "E4:5F:01": "Raspberry Pi",
        "F4:F2:6D": "Apple", "00:1C:B3": "Apple", "00:23:32": "Apple",
        "00:26:B0": "Apple", "00:3E:E1": "Apple",
        "00:1A:11": "Google", "94:EB:2C": "Google",
        "3C:5A:B4": "Google", "F4:F5:D8": "Google",
        "74:D0:2B": "Dell", "00:14:22": "Dell", "00:1E:4F": "Dell",
        "00:25:64": "Dell", "F0:4D:A2": "Dell",
        "00:1B:44": "SanDisk", "00:90:A9": "Western Digital",
        "00:1A:4B": "Netgear", "00:1F:33": "Netgear",
        "00:26:F2": "Netgear", "CC:40:D0": "Netgear",
        "14:F6:5A": "TP-Link", "50:C7:BF": "TP-Link",
        "E8:DE:27": "TP-Link", "F4:F2:6D": "TP-Link",
        "00:1D:0F": "ASUS", "00:1E:8C": "ASUS", "00:22:15": "ASUS",
        "00:24:8C": "ASUS", "74:D0:2B": "ASUS",
    }
    for prefix, vendor in OUI_TABLE.items():
        clean = prefix.replace(":", "").replace("-", "").upper()
        if oui.startswith(clean):
            return vendor
    return ""


# ── 5. TCP Ping (no root) ─────────────────────────────────────
def tcp_ping():
    title_box("TCP PING", "Check host reachability via TCP connect — no root needed")
    target = prompt("Enter IP or Domain")
    if not target:
        return
    port = prompt("TCP Port", "80")
    count = prompt("Count", "4")
    try:
        port  = int(port)
        count = int(count)
    except ValueError:
        port, count = 80, 4

    ip = resolve(target)
    if not ip:
        return
    sep()
    print(f"    {DIM}TCP-PING {target} ({ip}) port {port} — {count} attempts{RST}\n")

    recv, rtts = 0, []
    for i in range(1, count + 1):
        t0 = time.time()
        reachable = tcp_connect(ip, port, timeout=2)
        rtt = (time.time() - t0) * 1000
        if reachable:
            recv += 1
            rtts.append(rtt)
            print(f"    {GREEN}Connected to {ip}:{port}{RST}  "
                  f"seq={i}  time={CYAN}{rtt:.2f} ms{RST}")
        else:
            print(f"    {RED}No response from {ip}:{port}{RST}  seq={i}")
        time.sleep(0.4)

    loss = 100 * (count - recv) // count if count else 100
    print()
    if rtts:
        print(f"    rtt min/avg/max = "
              f"{CYAN}{min(rtts):.2f}{RST}/"
              f"{CYAN}{sum(rtts)/len(rtts):.2f}{RST}/"
              f"{CYAN}{max(rtts):.2f}{RST} ms  |  "
              f"{RED if loss else GREEN}{loss}% loss{RST}")
    sep()
