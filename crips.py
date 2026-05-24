#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          CRIPS FRAMEWORK v2.0 — Network Learning Kit         ║
║  Rebuilt from Manisso/Crips using pure pip-installable libs  ║
╚══════════════════════════════════════════════════════════════╝

Commands:
  1–31 → run a tool          0   → exit
  ?    → help                !   → AI configuration
  cls  → clear screen

Run:  python3 crips.py
Root: sudo python3 crips.py   (ICMP / ARP / raw-socket tools)
"""

import os, sys, io, contextlib, socket

if sys.version_info < (3, 8):
    print("[!] Python 3.8+ required.")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from modules.colors import *
from modules.utils  import get_local_ip, get_hostname

# ─────────────────────────────────────────────────────────────
# MENU STRUCTURE  { category: { choice: (label, mod, func) } }
# ─────────────────────────────────────────────────────────────
MENU = {
    "WHOIS & DOMAIN": {
        "1":  ("Whois Lookup",             "whois_mod",   "whois_lookup"),
    },
    "DNS TOOLS": {
        "2":  ("DNS Lookup (all types)",   "dns_mod",     "dns_lookup"),
        "3":  ("Reverse DNS",              "dns_mod",     "reverse_dns"),
        "4":  ("DNS Propagation Check",    "dns_mod",     "dns_propagation"),
        "5":  ("Zone Transfer (AXFR)",     "dns_mod",     "zone_transfer"),
    },
    "GEO & ASN": {
        "6":  ("GeoIP + ASN Lookup",       "geoip_mod",   "geoip_lookup"),
        "7":  ("Bulk GeoIP",               "geoip_mod",   "bulk_geoip"),
        "8":  ("ASN / BGP Info",           "geoip_mod",   "asn_lookup"),
    },
    "NETWORK DIAGNOSTICS": {
        "9":  ("ICMP Ping",                "network_mod", "ping"),
        "10": ("Ping Sweep (subnet)",      "network_mod", "ping_sweep"),
        "11": ("TCP Ping  (no root)",      "network_mod", "tcp_ping"),
        "12": ("Traceroute",               "network_mod", "traceroute"),
        "13": ("ARP Scan  (LAN)",          "network_mod", "arp_scan"),
    },
    "PORT SCANNING": {
        "14": ("TCP Port Scan (threaded)", "portscan_mod","port_scan"),
        "15": ("Subnet Port Scan",         "portscan_mod","network_port_scan"),
    },
    "HTTP & WEB": {
        "16": ("HTTP Headers Analysis",    "http_mod",    "http_headers"),
        "17": ("Redirect Chain",           "http_mod",    "redirect_chain"),
        "18": ("Robots.txt & Sitemap",     "http_mod",    "robots_sitemap"),
        "19": ("HTTP Methods Check",       "http_mod",    "http_methods"),
    },
    "SSL / TLS": {
        "20": ("SSL Certificate Inspector","ssl_mod",     "ssl_inspect"),
    },
    "SUBNET & IP TOOLS": {
        "21": ("Subnet Calculator",        "subnet_mod",  "subnet_calculator"),
        "22": ("Subnet Splitter",          "subnet_mod",  "subnet_split"),
        "23": ("IP Address Info",          "subnet_mod",  "ip_info"),
        "24": ("CIDR → IP Range",          "subnet_mod",  "cidr_range_list"),
        "25": ("IPv6 Tools",               "subnet_mod",  "ipv6_info"),
    },
    "BANNERS & SERVICES": {
        "26": ("Service Banner Grabber",   "banner_mod",  "banner_grab"),
        "27": ("Multi-Host Banner Scan",   "banner_mod",  "multi_host_banner"),
    },
    "LOCAL NETWORK": {
        "28": ("Network Interfaces",       "iface_mod",   "local_interfaces"),
        "29": ("MAC Address Analyzer",     "iface_mod",   "mac_lookup"),
        "30": ("Connectivity Check",       "iface_mod",   "network_speed_test"),
        "31": ("Active Connections",       "iface_mod",   "open_connections"),
    },
}

CATEGORY_COLORS = {
    "WHOIS & DOMAIN":       MAGENTA,
    "DNS TOOLS":            BLUE,
    "GEO & ASN":            GREEN,
    "NETWORK DIAGNOSTICS":  CYAN,
    "PORT SCANNING":        YELLOW,
    "HTTP & WEB":           GREEN,
    "SSL / TLS":            MAGENTA,
    "SUBNET & IP TOOLS":    BLUE,
    "BANNERS & SERVICES":   YELLOW,
    "LOCAL NETWORK":        CYAN,
}

# Flat lookup
FLAT: dict[str, tuple] = {k: v for cat in MENU.values() for k, v in cat.items()}

# ─────────────────────────────────────────────────────────────
# BANNER / MENU PRINT
# ─────────────────────────────────────────────────────────────
LOGO = f"""
{GREEN}{BOLD}   ██████╗██████╗ ██╗██████╗ ███████╗
  ██╔════╝██╔══██╗██║██╔══██╗██╔════╝
  ██║     ██████╔╝██║██████╔╝███████╗
  ██║     ██╔══██╗██║██╔═══╝ ╚════██║
  ╚██████╗██║  ██║██║██║     ███████║
   ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚══════╝{RST}
{RED}{BOLD}         Network Learning Framework  v2.0{RST}
{DIM}  pip-powered · no external APIs · 31 tools · AI-powered{RST}
"""

def _ai_status_badge() -> str:
    """Show a small AI status badge based on config."""
    try:
        from modules.ai_mod import load_config
        cfg = load_config()
        if not cfg.get("ai_enabled"):
            return f"  {GRAY}[AI off]{RST}"
        if not cfg.get("api_key"):
            return f"  {YELLOW}[AI: no key — use !]{RST}"
        model = cfg.get("model","").split("/")[-1][:22]
        auto  = f" {GREEN}auto{RST}" if cfg.get("auto_explain") else ""
        return f"  {MAGENTA}[AI: {model}{auto}{MAGENTA}]{RST}"
    except Exception:
        return ""

def print_menu():
    os.system("clear" if os.name != "nt" else "cls")
    print(LOGO)

    local_ip = get_local_ip()
    hostname = get_hostname()
    is_root  = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    root_str = f"{GREEN}root{RST}" if is_root else f"{YELLOW}user{RST}"

    print(f"  {DIM}Host: {WHITE}{hostname}{RST}  {DIM}IP: {WHITE}{local_ip}{RST}"
          f"  {DIM}Mode: {root_str}{_ai_status_badge()}\n")

    if not is_root:
        print(f"  {YELLOW}[!]{RST} {DIM}Tools 9,10,12,13 need sudo (ICMP/ARP){RST}\n")

    for category, items in MENU.items():
        cat_color = CATEGORY_COLORS.get(category, YELLOW)
        print(f"  {cat_color}{BOLD}── {category} ──{RST}")
        keys = list(items.keys())
        for i in range(0, len(keys), 2):
            lk = keys[i];   lv = items[lk][0]
            rpart = ""
            if i + 1 < len(keys):
                rk = keys[i+1]; rv = items[rk][0]
                rpart = f"  {GRAY}[{WHITE}{rk:>2}{GRAY}]{RST} {DIM}{rv}{RST}"
            print(f"  {GRAY}[{WHITE}{lk:>2}{GRAY}]{RST} {DIM}{lv:<32}{RST}{rpart}")
        print()

    print(f"  {GRAY}[{RED} 0{GRAY}]{RST} {DIM}Exit{RST}   "
          f"{GRAY}[{CYAN}  ?{GRAY}]{RST} {DIM}Help{RST}   "
          f"{GRAY}[{MAGENTA}  !{GRAY}]{RST} {DIM}AI Config{RST}   "
          f"{GRAY}[{CYAN}cls{GRAY}]{RST} {DIM}Clear{RST}\n")


# ─────────────────────────────────────────────────────────────
# TOOL RUNNER — captures output + passes to AI hook
# ─────────────────────────────────────────────────────────────
def run_tool(choice: str):
    entry = FLAT.get(choice)
    if not entry:
        err(f"Unknown option: {choice}")
        return

    label, module_name, func_name = entry

    try:
        import importlib
        mod  = importlib.import_module(f"modules.{module_name}")
        func = getattr(mod, func_name)
    except (ImportError, AttributeError) as e:
        err(f"Could not load module '{module_name}': {e}")
        warn("Run: python3 install.py")
        return

    # ── Run tool + tee output (screen AND capture buffer) ──
    buf = io.StringIO()
    try:
        # Tee: write to both real stdout and buffer
        class Tee:
            def __init__(self, real, buf):
                self._real = real
                self._buf  = buf
            def write(self, data):
                self._real.write(data)
                self._buf.write(data)
                return len(data)
            def flush(self):
                self._real.flush()
                self._buf.flush()
            def fileno(self):
                return self._real.fileno()

        tee = Tee(sys.stdout, buf)
        old_stdout = sys.stdout
        sys.stdout = tee
        try:
            func()
        finally:
            sys.stdout = old_stdout

    except KeyboardInterrupt:
        sys.stdout = sys.__stdout__
        print(f"\n  {YELLOW}[^C] Interrupted.{RST}")
    except Exception as e:
        sys.stdout = sys.__stdout__
        err(f"Error in '{label}': {e}")
        import traceback
        print(f"{GRAY}{traceback.format_exc()}{RST}")

    # ── AI explanation hook ───────────────────────────────────
    captured = buf.getvalue()
    try:
        from modules.ai_mod import maybe_explain
        maybe_explain(label, captured)
    except Exception:
        pass  # AI is always optional — never break the tool


# ─────────────────────────────────────────────────────────────
# HELP
# ─────────────────────────────────────────────────────────────
def print_help():
    title_box("CRIPS HELP", "31 network tools + AI-powered explanations")

    help_items = [
        ("1",  "Whois Lookup",           "WHOIS registration for domains/IPs",         "python-whois"),
        ("2",  "DNS Lookup",             "Query all DNS types (A,MX,NS,TXT,SOA...)",   "dnspython"),
        ("3",  "Reverse DNS",            "IP→hostname PTR, supports CIDR ranges",      "dnspython"),
        ("4",  "DNS Propagation",        "Check record across 8 public resolvers",     "dnspython"),
        ("5",  "Zone Transfer",          "Attempt AXFR — misconfiguration check",      "dnspython"),
        ("6",  "GeoIP + ASN",            "Country/city/ASN/BGP info for any IP",       "ipwhois geoip2"),
        ("7",  "Bulk GeoIP",             "GeoIP lookup for multiple IPs at once",      "ipwhois"),
        ("8",  "ASN / BGP",              "Autonomous system & network objects",        "ipwhois"),
        ("9",  "ICMP Ping",              "Standard ICMP echo (like system ping)",      "scapy+root"),
        ("10", "Ping Sweep",             "Discover live hosts in a subnet",            "scapy+root"),
        ("11", "TCP Ping",               "TCP connect test — no root needed",          "stdlib"),
        ("12", "Traceroute",             "Hop-by-hop path to destination",             "scapy+root"),
        ("13", "ARP Scan",               "Discover devices on local LAN",              "scapy+root"),
        ("14", "TCP Port Scan",          "Multi-threaded TCP connect scan",            "stdlib"),
        ("15", "Subnet Port Scan",       "Check one port across entire subnet",        "stdlib"),
        ("16", "HTTP Headers",           "Analyze headers + security posture",         "requests"),
        ("17", "Redirect Chain",         "Trace all HTTP redirects step-by-step",      "requests"),
        ("18", "Robots/Sitemap",         "Parse robots.txt + sitemap.xml",             "requests"),
        ("19", "HTTP Methods",           "Test which HTTP verbs server accepts",       "requests"),
        ("20", "SSL Inspector",          "Certificate, chain, ciphers, TLS ver.",      "pyOpenSSL"),
        ("21", "Subnet Calc",            "Network/broadcast/mask/binary breakdown",   "stdlib"),
        ("22", "Subnet Splitter",        "Divide a network into sub-networks",         "stdlib"),
        ("23", "IP Info",                "Full analysis of a single IP address",       "stdlib"),
        ("24", "CIDR Range",             "Expand CIDR to full IP list",                "stdlib"),
        ("25", "IPv6 Tools",             "Expand, analyze, classify IPv6",             "stdlib"),
        ("26", "Banner Grabber",         "Read protocol greetings from open ports",    "stdlib"),
        ("27", "Multi-Host Banner",      "Banner scan across many hosts",              "stdlib"),
        ("28", "Interfaces",             "Local network adapters and IPs",             "netifaces"),
        ("29", "MAC Analyzer",           "OUI vendor lookup + MAC flags",              "netaddr"),
        ("30", "Connectivity",           "Latency to public DNS/HTTP endpoints",       "stdlib"),
        ("31", "Active Connections",     "This machine's open network sockets",        "psutil opt"),
    ]

    print_table(
        help_items,
        ["#", "Tool", "What it does", "Requires"],
        [3, 22, 45, 18]
    )

    sep()
    print(f"""  {YELLOW}{BOLD}── Commands ──{RST}
  {GRAY}[1–31]{RST}  Run a tool
  {GRAY}[0]   {RST}  Exit
  {GRAY}[?]   {RST}  This help screen
  {GRAY}[!]   {RST}  AI configuration (OpenRouter / any OpenAI-compatible API)
  {GRAY}[cls] {RST}  Clear and redraw menu

  {YELLOW}{BOLD}── AI Feature ──{RST}
  After every tool, Crips can send the output to an AI for explanation.
  The AI generates a learning report: what the output means, key findings,
  networking concepts, and suggested next steps.

  Setup: press {MAGENTA}[!]{RST} to enter your OpenRouter API key.
  Free key: {CYAN}https://openrouter.ai/keys{RST}
  Default model: {WHITE}mistralai/mistral-7b-instruct:free{RST} (no credits needed)
""")
    sep()


# ─────────────────────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────────────────────
def main():
    print_menu()

    while True:
        try:
            raw = input(f"  {GREEN}crips{RST}~{RED}#{RST} ").strip()
        except (KeyboardInterrupt, EOFError):
            print(f"\n  {RED}Goodbye!{RST}\n")
            sys.exit(0)

        if not raw:
            continue

        # ── Built-in commands ─────────────────────────────────
        if raw == "0":
            print(f"\n  {RED}Goodbye!{RST}\n")
            sys.exit(0)

        if raw in ("?", "help"):
            print()
            print_help()
            input(f"\n  {DIM}Press Enter to continue...{RST}")
            print_menu()
            continue

        if raw == "!":
            try:
                from modules.ai_mod import config_menu
                config_menu()
            except ImportError as e:
                err(f"AI module error: {e}")
            print_menu()
            continue

        if raw.lower() in ("cls", "clear"):
            print_menu()
            continue

        # ── Tool dispatch ─────────────────────────────────────
        if raw in FLAT:
            print()
            run_tool(raw)
            input(f"\n  {DIM}Press Enter to return to menu...{RST}")
            print_menu()
        else:
            print(f"  {RED}[!]{RST} Unknown command '{raw}'. "
                  f"Enter 1–31, {MAGENTA}!{RST} (AI), {CYAN}?{RST} (help), or 0 (exit).")


if __name__ == "__main__":
    main()
