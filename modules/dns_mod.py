"""
Crips Framework — dns_mod.py
DNS Lookup, Reverse DNS, Zone Transfer attempt — dnspython
"""

from modules.colors import *
from modules.utils import prompt, require, is_valid_ip, resolve
import ipaddress


def _resolver():
    dns = require("dns.resolver", "dnspython")
    if not dns:
        return None
    import dns.resolver
    return dns.resolver


# ── 1. Full DNS Lookup ────────────────────────────────────────
def dns_lookup():
    title_box("DNS LOOKUP", "Query all record types via dnspython")
    import dns.resolver as R
    import dns.exception

    target = prompt("Enter Domain")
    if not target:
        return

    custom_ns = prompt("Custom DNS server (leave blank for system default)", "")
    resolver = R.Resolver()
    if custom_ns:
        resolver.nameservers = [custom_ns]
        step(f"Using nameserver: {custom_ns}")

    record_types = ["A", "AAAA", "MX", "NS", "TXT", "SOA",
                    "CNAME", "PTR", "SRV", "CAA", "NAPTR", "DS", "DNSKEY"]
    sep()
    found = False

    for rtype in record_types:
        try:
            answers = resolver.resolve(target, rtype, lifetime=5)
            header(f"{rtype} Records")
            for rdata in answers:
                print(f"    {CYAN}{rdata.to_text()}{RST}")
            found = True
        except (R.NoAnswer, R.NXDOMAIN, R.NoNameservers,
                R.Timeout, dns.exception.DNSException):
            pass
        except Exception:
            pass

    if not found:
        warn(f"No DNS records found for '{target}'")

    # TTL info
    try:
        ans = R.resolve(target, "A")
        kv("TTL", f"{ans.rrset.ttl} seconds", indent=4)
    except Exception:
        pass

    sep()


# ── 2. Reverse DNS ────────────────────────────────────────────
def reverse_dns():
    title_box("REVERSE DNS LOOKUP", "IP → Hostname via PTR records")
    import dns.resolver as R
    import dns.reversename

    target = prompt("Enter IP or CIDR (e.g. 8.8.8.8 or 8.8.8.0/24)")
    if not target:
        return
    sep()

    def rdns_single(ip_str: str):
        try:
            rev = dns.reversename.from_address(ip_str)
            answers = R.resolve(rev, "PTR", lifetime=4)
            return [a.to_text().rstrip(".") for a in answers]
        except Exception:
            return []

    if "/" in target:
        try:
            net = ipaddress.ip_network(target, strict=False)
            hosts = list(net.hosts())
            if len(hosts) > 512:
                warn("Range > 512 hosts — limiting to first 512.")
                hosts = hosts[:512]
            step(f"Scanning {len(hosts)} addresses...\n")
            found = 0
            for ip in hosts:
                results = rdns_single(str(ip))
                if results:
                    for r in results:
                        print(f"    {CYAN}{str(ip):<20}{RST}→  {WHITE}{r}{RST}")
                    found += 1
            print()
            ok(f"Found {found} PTR records out of {len(hosts)} addresses.")
        except ValueError as e:
            err(f"Invalid CIDR: {e}")
    else:
        results = rdns_single(target)
        if results:
            header("PTR Records")
            for r in results:
                print(f"    {CYAN}{target:<20}{RST}→  {WHITE}{r}{RST}")
        else:
            warn(f"No PTR record found for {target}")

    sep()


# ── 3. DNS Zone Transfer (educational) ───────────────────────
def zone_transfer():
    title_box("DNS ZONE TRANSFER", "Attempt AXFR — educational / misconfiguration check")
    info("Most servers block AXFR — this tests for misconfiguration.")
    import dns.zone
    import dns.query
    import dns.resolver as R
    import dns.exception

    domain = prompt("Enter Domain")
    if not domain:
        return
    sep()

    # Get NS records first
    try:
        ns_records = R.resolve(domain, "NS", lifetime=5)
        nameservers = [str(r.target).rstrip(".") for r in ns_records]
        header(f"Nameservers for {domain}")
        for ns in nameservers:
            print(f"    {CYAN}{ns}{RST}")
        print()
    except Exception as e:
        err(f"Could not get NS records: {e}")
        return

    # Try AXFR on each NS
    success = False
    for ns in nameservers:
        step(f"Trying AXFR on {ns} ...")
        try:
            ns_ip = resolve(ns)
            if not ns_ip:
                continue
            z = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=8))
            header(f"Zone Transfer SUCCESS — {ns}")
            ok("Server is misconfigured! Full zone data:")
            print()
            names = sorted(z.nodes.keys())
            for name in names:
                for rdataset in z[name]:
                    for rdata in rdataset:
                        print(f"    {CYAN}{str(name):<30}{RST} "
                              f"{YELLOW}{rdataset.rdtype}{RST}  "
                              f"{WHITE}{rdata.to_text()}{RST}")
            success = True
            break
        except dns.exception.FormError:
            warn(f"  {ns} — AXFR refused (server correctly configured).")
        except Exception as e:
            warn(f"  {ns} — {e}")

    if not success:
        ok("All nameservers correctly block zone transfers.")

    sep()


# ── 4. DNS Propagation Check ──────────────────────────────────
def dns_propagation():
    title_box("DNS PROPAGATION CHECK", "Query multiple public DNS resolvers")
    import dns.resolver as R

    PUBLIC_DNS = {
        "Google (Primary)":     "8.8.8.8",
        "Google (Secondary)":   "8.8.4.4",
        "Cloudflare":           "1.1.1.1",
        "Cloudflare Alt":       "1.0.0.1",
        "OpenDNS":              "208.67.222.222",
        "Quad9":                "9.9.9.9",
        "Comodo":               "8.26.56.26",
        "Level3":               "209.244.0.3",
    }

    domain = prompt("Enter Domain")
    rtype  = prompt("Record type", "A")
    if not domain:
        return
    sep()

    header(f"{rtype} record for {domain}")
    results_seen = {}

    for name, ns_ip in PUBLIC_DNS.items():
        resolver = R.Resolver()
        resolver.nameservers = [ns_ip]
        try:
            answers = resolver.resolve(domain, rtype, lifetime=5)
            vals = sorted(set(a.to_text() for a in answers))
            key = tuple(vals)
            results_seen.setdefault(key, []).append(name)
            result_str = ", ".join(vals)
            print(f"    {GREEN}✓{RST}  {YELLOW}{name:<25}{RST} {CYAN}{ns_ip:<16}{RST}  {WHITE}{result_str}{RST}")
        except R.NXDOMAIN:
            print(f"    {RED}✗{RST}  {YELLOW}{name:<25}{RST} {CYAN}{ns_ip:<16}{RST}  {GRAY}NXDOMAIN{RST}")
        except Exception as e:
            print(f"    {RED}✗{RST}  {YELLOW}{name:<25}{RST} {CYAN}{ns_ip:<16}{RST}  {GRAY}{e}{RST}")

    print()
    if len(results_seen) == 1:
        ok("DNS is fully propagated — all resolvers agree!")
    elif len(results_seen) > 1:
        warn("DNS not fully propagated — resolvers disagree!")

    sep()
