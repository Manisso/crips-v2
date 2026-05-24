"""
Crips Framework — http_mod.py
HTTP Headers, Redirect Chain, Tech Detection, robots.txt — requests
"""

import re
from modules.colors import *
from modules.utils import prompt, resolve
import urllib.parse


def _session():
    try:
        import requests
        s = requests.Session()
        s.headers.update({"User-Agent": "CripsFramework/2.0 (Network Learning Tool)"})
        return s, requests
    except ImportError:
        err("requests not installed → pip install requests")
        return None, None


# ── Security header ratings ───────────────────────────────────
SEC_HEADERS = {
    "Strict-Transport-Security": ("HSTS",         "Enforces HTTPS"),
    "Content-Security-Policy":   ("CSP",           "XSS/injection policy"),
    "X-Frame-Options":           ("X-Frame",       "Clickjacking protection"),
    "X-Content-Type-Options":    ("X-CTO",         "MIME sniffing protection"),
    "Referrer-Policy":           ("Ref-Policy",    "Referrer info control"),
    "Permissions-Policy":        ("Perm-Policy",   "Browser API permissions"),
    "X-XSS-Protection":          ("X-XSS",         "Legacy XSS filter"),
    "Cross-Origin-Opener-Policy":("COOP",          "Cross-origin isolation"),
    "Cross-Origin-Resource-Policy":("CORP",        "Resource sharing policy"),
}

# ── Server / tech fingerprints ────────────────────────────────
TECH_SIGNATURES = {
    "server": {
        "apache": "Apache HTTP Server",
        "nginx": "Nginx",
        "iis": "Microsoft IIS",
        "cloudflare": "Cloudflare",
        "litespeed": "LiteSpeed",
        "caddy": "Caddy",
        "gunicorn": "Gunicorn (Python)",
        "uvicorn": "Uvicorn (Python ASGI)",
        "werkzeug": "Flask/Werkzeug (Python)",
        "jetty": "Jetty (Java)",
        "tomcat": "Apache Tomcat (Java)",
        "openresty": "OpenResty (Nginx+Lua)",
    },
    "x-powered-by": {
        "php": "PHP",
        "asp.net": "ASP.NET",
        "express": "Node.js/Express",
        "next.js": "Next.js",
        "django": "Django (Python)",
        "ruby": "Ruby on Rails",
    },
    "set-cookie": {
        "phpsessid": "PHP",
        "laravel": "Laravel (PHP)",
        "csrf": "CSRF protection present",
        "django": "Django (Python)",
        "jsessionid": "Java (JEE)",
        "rack.session": "Ruby Rack",
    },
}


def http_headers():
    title_box("HTTP HEADERS ANALYSIS", "Inspect response headers & security posture")
    s, req = _session()
    if not s:
        return

    url = prompt("Enter URL or Domain")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    follow = prompt("Follow redirects? (y/n)", "y").lower() == "y"
    sep()

    try:
        resp = s.get(url, allow_redirects=follow, timeout=10, verify=False)
        # Suppress InsecureRequestWarning
        import warnings
        warnings.filterwarnings("ignore")

        print(f"    {WHITE}URL         :{RST} {CYAN}{resp.url}{RST}")
        print(f"    {WHITE}Status      :{RST} {_status_color(resp.status_code)}{resp.status_code} {resp.reason}{RST}")
        print(f"    {WHITE}Elapsed     :{RST} {resp.elapsed.total_seconds()*1000:.0f} ms")
        print(f"    {WHITE}Size        :{RST} {len(resp.content)} bytes")
        print()

        # All headers
        header("Response Headers")
        for k, v in resp.headers.items():
            label_color = YELLOW if k.lower() in [h.lower() for h in SEC_HEADERS] else GRAY
            print(f"    {label_color}{k:<35}{RST}: {WHITE}{v[:120]}{RST}")

        # Security header audit
        header("Security Header Audit")
        present = []
        missing = []
        for hdr, (short, desc) in SEC_HEADERS.items():
            found = resp.headers.get(hdr) or resp.headers.get(hdr.lower())
            if found:
                present.append((hdr, short, desc, found[:60]))
            else:
                missing.append((hdr, short, desc))

        if present:
            print(f"\n    {GREEN}PRESENT ({len(present)}):{RST}")
            for hdr, short, desc, val in present:
                print(f"    {GREEN}  ✓ {short:<15}{RST} {GRAY}{desc:<30}{RST}  {DIM}{val}{RST}")
        if missing:
            print(f"\n    {RED}MISSING ({len(missing)}):{RST}")
            for hdr, short, desc in missing:
                print(f"    {RED}  ✗ {short:<15}{RST} {GRAY}{desc}{RST}")

        score = int(len(present) / len(SEC_HEADERS) * 100)
        color = GREEN if score >= 70 else YELLOW if score >= 40 else RED
        print(f"\n    {WHITE}Security Score: {color}{score}%{RST}  ({len(present)}/{len(SEC_HEADERS)} headers present)")

        # Technology detection
        header("Technology Fingerprint")
        detected = []
        for hdr_name, patterns in TECH_SIGNATURES.items():
            val = (resp.headers.get(hdr_name) or "").lower()
            if val:
                for sig, tech in patterns.items():
                    if sig in val:
                        detected.append(tech)
        # Cookie-based
        for cookie in resp.cookies:
            for sig, tech in TECH_SIGNATURES["set-cookie"].items():
                if sig in cookie.name.lower():
                    detected.append(tech)

        if detected:
            for tech in set(detected):
                print(f"    {CYAN}  ● {tech}{RST}")
        else:
            warn("  No technology signatures detected from headers.")

    except Exception as e:
        err(f"HTTP error: {e}")
    sep()


def redirect_chain():
    title_box("REDIRECT CHAIN", "Trace all HTTP redirects step by step")
    s, req = _session()
    if not s:
        return

    url = prompt("Enter URL or Domain")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    sep()

    try:
        import warnings
        warnings.filterwarnings("ignore")
        resp = s.get(url, allow_redirects=True, timeout=15, verify=False)

        chain = [url] + [r.url for r in resp.history] if resp.history else [url]
        all_responses = list(resp.history) + [resp]
        final_responses = resp.history + [resp]

        print(f"    {DIM}Tracing redirect chain for: {url}{RST}\n")
        for i, r in enumerate(final_responses):
            status = r.status_code
            loc    = r.headers.get("Location", "")
            color  = _status_color(status)
            arrow  = f" → {CYAN}{loc[:60]}{RST}" if loc else ""
            print(f"    {GRAY}{i+1}.{RST} {color}{status}{RST}  {WHITE}{r.url[:70]}{RST}{arrow}")

        print()
        ok(f"Final destination: {CYAN}{resp.url}{RST}  [{resp.status_code}]")
        if len(resp.history) == 0:
            info("No redirects — direct response.")
    except Exception as e:
        err(f"Error: {e}")
    sep()


def robots_sitemap():
    title_box("ROBOTS.TXT + SITEMAP", "Fetch and parse site crawl directives")
    s, req = _session()
    if not s:
        return

    domain = prompt("Enter Domain or URL")
    if not domain:
        return
    if not domain.startswith(("http://", "https://")):
        domain = "https://" + domain

    base = domain.rstrip("/")
    import warnings
    warnings.filterwarnings("ignore")
    sep()

    # robots.txt
    header("robots.txt")
    try:
        r = s.get(f"{base}/robots.txt", timeout=8, verify=False)
        if r.status_code == 200:
            lines = r.text.splitlines()
            current_ua = None
            for line in lines:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if line.lower().startswith("user-agent:"):
                    ua = line.split(":", 1)[1].strip()
                    current_ua = ua
                    print(f"\n    {YELLOW}[User-Agent: {ua}]{RST}")
                elif line.lower().startswith("disallow:"):
                    path = line.split(":", 1)[1].strip()
                    print(f"    {RED}  Disallow: {path}{RST}")
                elif line.lower().startswith("allow:"):
                    path = line.split(":", 1)[1].strip()
                    print(f"    {GREEN}  Allow:    {path}{RST}")
                elif line.lower().startswith("sitemap:"):
                    sm = line.split(":", 1)[1].strip()
                    print(f"    {CYAN}  Sitemap:  {sm}{RST}")
                else:
                    print(f"    {GRAY}  {line}{RST}")
        else:
            warn(f"robots.txt returned HTTP {r.status_code}")
    except Exception as e:
        err(f"robots.txt error: {e}")

    # sitemap.xml
    header("sitemap.xml")
    sitemap_urls = [f"{base}/sitemap.xml", f"{base}/sitemap_index.xml",
                    f"{base}/sitemap-index.xml"]
    for sm_url in sitemap_urls:
        try:
            r = s.get(sm_url, timeout=8, verify=False)
            if r.status_code == 200 and ("xml" in r.headers.get("content-type","")
                                          or "<urlset" in r.text or "<sitemapindex" in r.text):
                # Count URLs
                url_count = r.text.count("<url>")
                sm_count  = r.text.count("<sitemap>")
                ok(f"Found: {sm_url}")
                if url_count:
                    info(f"Contains {url_count} URL entries")
                if sm_count:
                    info(f"Contains {sm_count} sub-sitemaps")
                # Extract first few URLs
                urls_found = re.findall(r"<loc>(.*?)</loc>", r.text)[:10]
                if urls_found:
                    print(f"\n    {YELLOW}Sample URLs:{RST}")
                    for u in urls_found:
                        print(f"    {CYAN}  {u}{RST}")
                break
        except Exception:
            pass
    else:
        warn("No sitemap.xml found at common locations.")
    sep()


def http_methods():
    title_box("HTTP METHODS CHECK", "Test which HTTP verbs a server accepts")
    s, req = _session()
    if not s:
        return

    url = prompt("Enter URL or Domain")
    if not url:
        return
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    sep()

    import warnings
    warnings.filterwarnings("ignore")

    METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD",
               "OPTIONS", "TRACE", "CONNECT"]
    results = []

    for method in METHODS:
        try:
            r = s.request(method, url, timeout=5, verify=False, allow_redirects=False)
            color = GREEN if r.status_code < 400 else YELLOW if r.status_code < 500 else RED
            results.append((method, str(r.status_code), r.reason))
            print(f"    {YELLOW}{method:<10}{RST} {color}{r.status_code}{RST}  {GRAY}{r.reason}{RST}")
        except Exception as e:
            print(f"    {YELLOW}{method:<10}{RST} {RED}Error{RST}  {GRAY}{e}{RST}")

    # Check Allow header from OPTIONS
    try:
        opts = s.options(url, timeout=5, verify=False)
        allow = opts.headers.get("Allow") or opts.headers.get("access-control-allow-methods")
        if allow:
            print(f"\n    {YELLOW}Allow header:{RST} {WHITE}{allow}{RST}")
    except Exception:
        pass
    sep()


def _status_color(code: int) -> str:
    if code < 300:   return GREEN
    if code < 400:   return YELLOW
    if code < 500:   return RED
    return MAGENTA
