"""
Crips Framework — whois_mod.py
WHOIS lookup via python-whois
"""

from modules.colors import *
from modules.utils import prompt, require


def run():
    title_box("WHOIS LOOKUP", "Domain & IP Registration Info")
    w = require("whois", "python-whois")
    if not w:
        return

    target = prompt("Enter Domain or IP")
    if not target:
        return

    step(f"Querying WHOIS for: {target} ...")
    sep()

    try:
        result = w.whois(target)
        if not result:
            warn("No WHOIS data returned.")
            return

        sections = {
            "Domain Info": [
                ("Domain Name",       result.domain_name),
                ("Registrar",         result.registrar),
                ("WHOIS Server",      result.whois_server),
                ("Status",            result.status),
            ],
            "Dates": [
                ("Created",           result.creation_date),
                ("Updated",           result.updated_date),
                ("Expires",           result.expiration_date),
            ],
            "Registrant": [
                ("Org / Name",        result.org or result.name),
                ("Country",           result.country),
                ("State",             result.state),
                ("City",              result.city),
                ("Address",           result.address),
                ("Emails",            result.emails),
            ],
            "DNS": [
                ("Name Servers",      result.name_servers),
                ("DNSSEC",            result.dnssec),
            ],
        }

        for section, fields in sections.items():
            has_data = any(v for _, v in fields)
            if not has_data:
                continue
            header(section)
            for label, value in fields:
                if not value:
                    continue
                if isinstance(value, (list, set)):
                    value = "\n" + "\n".join(
                        f"{'':28}{CYAN}{v}{RST}" for v in value
                    )
                    print(f"    {YELLOW}{label:<22}{RST}: {WHITE}{value.strip()}{RST}")
                else:
                    kv(label, str(value))

    except Exception as e:
        err(f"WHOIS error: {e}")

    sep()
