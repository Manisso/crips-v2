"""
Crips Framework — geoip_mod.py
GeoIP via ipwhois (RDAP) + geoip2 (MaxMind DB)
"""

import os
from modules.colors import *
from modules.utils import prompt, resolve, require, is_private_ip


DB_PATHS = [
    "GeoLite2-City.mmdb",
    os.path.expanduser("~/GeoLite2-City.mmdb"),
    "/usr/share/GeoIP/GeoLite2-City.mmdb",
    "/var/lib/GeoIP/GeoLite2-City.mmdb",
    "/etc/GeoIP/GeoLite2-City.mmdb",
]

ASN_DB_PATHS = [
    "GeoLite2-ASN.mmdb",
    os.path.expanduser("~/GeoLite2-ASN.mmdb"),
    "/usr/share/GeoIP/GeoLite2-ASN.mmdb",
    "/var/lib/GeoIP/GeoLite2-ASN.mmdb",
]


def _find_db(paths):
    return next((p for p in paths if os.path.exists(p)), None)


# ── 1. GeoIP + ASN Full Lookup ────────────────────────────────
def geoip_lookup():
    title_box("GEOIP + ASN LOOKUP", "ipwhois RDAP  +  MaxMind GeoLite2")

    target = prompt("Enter IP or Domain")
    if not target:
        return

    ip = resolve(target)
    if not ip:
        return

    sep()
    print(f"    {BOLD}{WHITE}Target  : {RST}{target}")
    print(f"    {BOLD}{WHITE}Resolved: {RST}{ip}")

    if is_private_ip(ip):
        warn("Private/reserved IP — no public GeoIP data available.")
        sep()
        return

    # ── ipwhois RDAP (no DB file needed) ─────────────────────
    header("ASN / BGP / Network Info  [ipwhois RDAP]")
    try:
        from ipwhois import IPWhois
        from ipwhois.exceptions import IPDefinedError
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=2, inc_raw=False)

        net = res.get("network", {})
        fields = [
            ("ASN",              res.get("asn")),
            ("ASN CIDR",         res.get("asn_cidr")),
            ("ASN Country",      res.get("asn_country_code")),
            ("ASN Registry",     res.get("asn_registry")),
            ("ASN Description",  res.get("asn_description")),
            ("Network Name",     net.get("name")),
            ("Network CIDR",     net.get("cidr")),
            ("Network Country",  net.get("country")),
            ("Network Type",     net.get("type")),
            ("Network Handle",   net.get("handle")),
            ("Net Start",        net.get("start_address")),
            ("Net End",          net.get("end_address")),
        ]
        for k, v in fields:
            if v:
                kv(k, v)

        # Entities
        entities = res.get("entities", [])
        if entities:
            print()
            header("Entities / Contacts")
            objects = res.get("objects", {})
            for ent in entities:
                obj_data = objects.get(ent, {})
                contact  = obj_data.get("contact", {})
                roles    = obj_data.get("roles", [])
                print(f"    {CYAN}{ent}{RST}  {GRAY}({', '.join(roles)}){RST}")
                if contact:
                    for key in ("name", "organization", "email", "address", "phone"):
                        val = contact.get(key)
                        if val:
                            if isinstance(val, list):
                                val = val[0].get("value", "") if val else ""
                            kv(f"  {key.title()}", str(val))
    except ImportError:
        err("ipwhois not installed → pip install ipwhois")
    except Exception as e:
        err(f"ipwhois error: {e}")

    # ── MaxMind GeoLite2 City ─────────────────────────────────
    db = _find_db(DB_PATHS)
    if db:
        header("City / Location  [MaxMind GeoLite2]")
        try:
            import geoip2.database
            with geoip2.database.Reader(db) as reader:
                r = reader.city(ip)
                geo_fields = [
                    ("Continent",   r.continent.name),
                    ("Country",     f"{r.country.name}  ({r.country.iso_code})"),
                    ("State",       r.subdivisions.most_specific.name),
                    ("City",        r.city.name),
                    ("Postal Code", r.postal.code),
                    ("Latitude",    r.location.latitude),
                    ("Longitude",   r.location.longitude),
                    ("Accuracy km", r.location.accuracy_radius),
                    ("Timezone",    r.location.time_zone),
                    ("EU member",   r.country.is_in_european_union),
                ]
                for k, v in geo_fields:
                    if v is not None and v != "":
                        kv(k, str(v))
        except Exception as e:
            err(f"GeoLite2 error: {e}")
    else:
        print()
        warn("GeoLite2-City.mmdb not found — city-level data unavailable.")
        info("Download free at: https://www.maxmind.com/en/geolite2/signup")
        info("Place GeoLite2-City.mmdb in the crips/ folder.")

    # ── MaxMind GeoLite2 ASN ──────────────────────────────────
    asn_db = _find_db(ASN_DB_PATHS)
    if asn_db:
        header("ASN Info  [MaxMind GeoLite2-ASN]")
        try:
            import geoip2.database
            with geoip2.database.Reader(asn_db) as reader:
                r = reader.asn(ip)
                kv("ASN Number", f"AS{r.autonomous_system_number}")
                kv("ASN Org",    r.autonomous_system_organization)
        except Exception as e:
            err(f"GeoLite2-ASN error: {e}")

    sep()


# ── 2. Bulk IP GeoIP ──────────────────────────────────────────
def bulk_geoip():
    title_box("BULK GEOIP LOOKUP", "Query multiple IPs at once")
    info("Enter one IP or domain per line. Empty line to start.")
    print()

    targets = []
    while True:
        try:
            line = input(f"  {WHITE}IP/Domain (empty to start): {RST}").strip()
        except (KeyboardInterrupt, EOFError):
            break
        if not line:
            break
        targets.append(line)

    if not targets:
        return
    sep()

    try:
        from ipwhois import IPWhois
        rows = []
        for t in targets:
            ip = resolve(t)
            if not ip:
                rows.append((t, "N/A", "N/A", "N/A", "N/A", "N/A"))
                continue
            try:
                res = IPWhois(ip).lookup_rdap(depth=1)
                net = res.get("network", {})
                rows.append((
                    t,
                    ip,
                    res.get("asn", ""),
                    res.get("asn_country_code", ""),
                    res.get("asn_description", "")[:30],
                    net.get("cidr", ""),
                ))
            except Exception:
                rows.append((t, ip, "error", "", "", ""))

        print_table(
            rows,
            ["Target", "IP", "ASN", "CC", "Description", "CIDR"],
            [20, 16, 8, 4, 32, 20]
        )
    except ImportError:
        err("ipwhois not installed → pip install ipwhois")

    sep()


# ── 3. ASN Peers / BGP Info ───────────────────────────────────
def asn_lookup():
    title_box("ASN / BGP LOOKUP", "Autonomous System info via ipwhois")
    target = prompt("Enter IP, Domain or ASN (e.g. AS15169)")
    if not target:
        return
    sep()

    try:
        from ipwhois import IPWhois
        from ipwhois.net import Net
        from ipwhois.asn import IPASN

        # If user entered an ASN directly
        if target.upper().startswith("AS"):
            info("ASN direct lookup — resolving via DNS Team Cymru...")
            import dns.resolver as R
            asn_num = target.upper().replace("AS", "")
            # Get ASN details via WHOIS
            import subprocess, shutil
            if shutil.which("whois"):
                result = subprocess.run(
                    ["whois", "-h", "whois.radb.net", f"AS{asn_num}"],
                    capture_output=True, text=True, timeout=15
                )
                if result.stdout:
                    for line in result.stdout.splitlines()[:30]:
                        if line.strip() and not line.startswith("%"):
                            print(f"    {CYAN}{line}{RST}")
            else:
                warn("whois binary not found for direct ASN lookup.")
            sep()
            return

        ip = resolve(target)
        if not ip:
            return

        net = Net(ip)
        obj = IPASN(net)
        results = obj.lookup()

        header("ASN Details")
        for k, v in results.items():
            if v:
                kv(k.replace("_", " ").title(), str(v))

        # Full RDAP
        rdap = IPWhois(ip).lookup_rdap(depth=1)
        entities = rdap.get("objects", {})
        if entities:
            header("Network Objects")
            for handle, obj_data in list(entities.items())[:5]:
                roles = obj_data.get("roles", [])
                contact = obj_data.get("contact", {})
                name = (contact.get("name") or [{}])[0].get("value", handle) \
                    if isinstance(contact.get("name"), list) else \
                    contact.get("name", handle)
                print(f"    {CYAN}{handle:<20}{RST} {YELLOW}{', '.join(roles)}{RST}  {WHITE}{name}{RST}")

    except ImportError:
        err("ipwhois not installed → pip install ipwhois")
    except Exception as e:
        err(f"Error: {e}")

    sep()
