#!/usr/bin/env python3
"""
Crips Framework v2.0 — install.py
Auto-installs pip packages + downloads GeoLite2 databases
"""

import sys, subprocess, os, importlib, time, shutil

G="\033[92m"; R="\033[91m"; Y="\033[93m"; C="\033[96m"
W="\033[97m"; D="\033[2m";  B="\033[1m";  RST="\033[0m"

BANNER = f"""
{G}{B}  ╔═══════════════════════════════════════════╗
  ║    Crips Framework v2.0 — Installer       ║
  ║    pip packages + GeoLite2 databases      ║
  ╚═══════════════════════════════════════════╝{RST}
"""

PACKAGES = [
    # pip_name           import_name    description                          required
    ("python-whois",     "whois",       "Whois lookups",                     True),
    ("dnspython",        "dns",         "DNS queries / reverse DNS / AXFR",  True),
    ("ipwhois",          "ipwhois",     "ASN / BGP / RDAP lookups",          True),
    ("geoip2",           "geoip2",      "MaxMind GeoLite2 reader",           True),
    ("scapy",            "scapy",       "ICMP / traceroute / ARP (root)",    True),
    ("requests",         "requests",    "HTTP analysis / AI API calls",      True),
    ("pyOpenSSL",        "OpenSSL",     "SSL/TLS cert inspection",           True),
    ("cryptography",     "cryptography","Required by pyOpenSSL",             True),
    ("netaddr",          "netaddr",     "MAC OUI / subnet tools",            True),
    ("netifaces",        "netifaces",   "Local network interfaces",          True),
    ("colorama",         "colorama",    "Windows ANSI color support",        True),
    ("psutil",           "psutil",      "Active connections / process info", False),
]

# GeoLite2 databases from P3TERX (free, no signup)
GEOLITE_FILES = {
    "GeoLite2-ASN.mmdb":
        "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb",
    "GeoLite2-City.mmdb":
        "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-City.mmdb",
    "GeoLite2-Country.mmdb":
        "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
}

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))


# ── Helpers ───────────────────────────────────────────────────
def ok(msg):   print(f"  {G}[✓]{RST} {msg}")
def err(msg):  print(f"  {R}[✗]{RST} {msg}")
def warn(msg): print(f"  {Y}[!]{RST} {msg}")
def info(msg): print(f"  {C}[i]{RST} {msg}")
def hdr(msg):  print(f"\n  {Y}{B}── {msg} ──{RST}\n")


def check_python():
    maj, minor = sys.version_info[:2]
    if maj < 3 or (maj == 3 and minor < 8):
        err(f"Python 3.8+ required. You have {maj}.{minor}")
        sys.exit(1)
    ok(f"Python {maj}.{minor}")


def get_pip():
    for candidate in [[sys.executable, "-m", "pip"], ["pip3"], ["pip"]]:
        try:
            subprocess.run(candidate + ["--version"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)
            return candidate
        except Exception:
            pass
    err("pip not found — install pip first.")
    sys.exit(1)


def install_pkg(pip_cmd, name):
    for flags in [["--quiet", "--break-system-packages"], ["--quiet"], []]:
        try:
            r = subprocess.run(pip_cmd + ["install", name] + flags,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=120)
            if r.returncode == 0:
                return True
        except Exception:
            pass
    return False


def verify(import_name):
    try:
        importlib.import_module(import_name)
        return True
    except ImportError:
        return False


# ── GeoLite2 download ─────────────────────────────────────────
def download_geolite():
    hdr("GeoLite2 Databases  (P3TERX mirror — no signup needed)")

    try:
        import requests
    except ImportError:
        warn("requests not yet installed — skipping GeoLite2 download.")
        warn("Re-run install.py after packages are installed.")
        return

    for filename, url in GEOLITE_FILES.items():
        dest = os.path.join(SCRIPT_DIR, filename)

        if os.path.exists(dest):
            size_mb = os.path.getsize(dest) / 1024 / 1024
            ok(f"{filename}  {D}({size_mb:.1f} MB — already present){RST}")
            continue

        print(f"  {D}Downloading {filename} ...{RST}", end="", flush=True)
        try:
            resp = requests.get(url, stream=True, timeout=60,
                                headers={"User-Agent": "CripsInstaller/2.0"})
            resp.raise_for_status()

            total = int(resp.headers.get("content-length", 0))
            downloaded = 0
            tmp_path = dest + ".tmp"

            with open(tmp_path, "wb") as f:
                for chunk in resp.iter_content(chunk_size=65536):
                    if chunk:
                        f.write(chunk)
                        downloaded += len(chunk)
                        if total:
                            pct = downloaded / total * 100
                            print(f"\r  {D}Downloading {filename} ... {pct:.0f}%{RST}",
                                  end="", flush=True)

            os.rename(tmp_path, dest)
            size_mb = os.path.getsize(dest) / 1024 / 1024
            print(f"\r  {G}[✓]{RST} {filename}  {D}({size_mb:.1f} MB){RST}            ")

        except KeyboardInterrupt:
            if os.path.exists(dest + ".tmp"):
                os.remove(dest + ".tmp")
            print()
            warn(f"Download interrupted: {filename}")
        except Exception as e:
            if os.path.exists(dest + ".tmp"):
                os.remove(dest + ".tmp")
            print()
            err(f"{filename}: {e}")
            info(f"Manual download: {url}")


# ── Package install ───────────────────────────────────────────
def install_packages(pip_cmd):
    hdr("Installing pip packages")
    failed_req = []
    failed_opt = []

    for pip_name, imp_name, desc, required in PACKAGES:
        opt = "" if required else f"  {D}(optional){RST}"
        if verify(imp_name):
            print(f"  {G}[✓]{RST} {C}{pip_name:<22}{RST} {D}already installed{RST}")
            continue

        print(f"  {D}    {pip_name:<22}{RST}  {desc}{opt}")
        if install_pkg(pip_cmd, pip_name) and verify(imp_name):
            ok(f"{C}{pip_name}{RST}")
        else:
            err(f"{C}{pip_name}{RST}  FAILED")
            (failed_req if required else failed_opt).append(pip_name)

    return failed_req, failed_opt


# ── Create default config.json ────────────────────────────────
def create_default_config():
    cfg_path = os.path.join(SCRIPT_DIR, "config.json")
    if os.path.exists(cfg_path):
        ok(f"config.json  {D}(already exists){RST}")
        return

    import json
    default = {
        "ai_enabled":   True,
        "api_key":      "",
        "base_url":     "https://openrouter.ai/api/v1",
        "model":        "mistralai/mistral-7b-instruct:free",
        "auto_explain": False,
        "stream":       True,
        "max_tokens":   1200,
    }
    with open(cfg_path, "w") as f:
        json.dump(default, f, indent=2)
    ok(f"config.json created with default AI settings")


# ── Verify all imports ────────────────────────────────────────
def verify_all():
    hdr("Import verification")
    all_ok = True
    for pip_name, imp_name, desc, required in PACKAGES:
        if verify(imp_name):
            print(f"  {G}[✓]{RST} {C}{imp_name:<22}{RST} {D}{desc}{RST}")
        else:
            icon = R if required else Y
            extra = f"  → pip install {pip_name}"
            print(f"  {icon}[✗]{RST} {C}{imp_name:<22}{RST} {D}{desc}{RST}  {Y}{extra}{RST}")
            if required:
                all_ok = False
    return all_ok


# ── Root notice ───────────────────────────────────────────────
def print_root_notice():
    hdr("Permissions")
    is_root = (os.geteuid() == 0) if hasattr(os, "geteuid") else False
    if is_root:
        ok("Running as root — all 31 tools available.")
    else:
        warn("Running as normal user.")
        info("Tools 9,10,12,13 (ICMP/ARP) need sudo.")
        info("Tools 11,14-31 work fine without root.")


# ── Summary ───────────────────────────────────────────────────
def print_summary(failed_req, failed_opt, all_ok):
    print(f"\n  {Y}{'─'*50}{RST}")

    # Check GeoLite files
    geo_ok = all(os.path.exists(os.path.join(SCRIPT_DIR, f)) for f in GEOLITE_FILES)
    geo_str = f"{G}✓{RST}" if geo_ok else f"{Y}partial{RST}"

    if all_ok and not failed_req:
        print(f"  {G}{B}[✓] Installation complete!{RST}")
        print(f"\n  Packages:   {G}OK{RST}")
        print(f"  GeoLite2:   {geo_str}")
        print(f"\n  {W}Run:{RST}              python3 crips.py")
        print(f"  {W}With root:{RST}        sudo python3 crips.py")
        print(f"  {W}Configure AI:{RST}     press {C}!{RST} inside the tool\n")
        print(f"  {W}Free OpenRouter key:{RST}  {C}https://openrouter.ai/keys{RST}")
    else:
        print(f"  {Y}[!] Some packages failed.{RST}")
        if failed_req:
            print(f"  {R}Required failed: {', '.join(failed_req)}{RST}")
            print(f"  Retry: pip install {' '.join(failed_req)}")
        if failed_opt:
            print(f"  {Y}Optional failed: {', '.join(failed_opt)}{RST}")
    print()


def main():
    print(BANNER)
    print(f"  {D}Python: {sys.version}{RST}\n")

    check_python()
    pip_cmd = get_pip()
    ok(f"pip: {' '.join(pip_cmd)}")

    failed_req, failed_opt = install_packages(pip_cmd)

    hdr("GeoLite2 Database files")
    download_geolite()

    hdr("Default config")
    create_default_config()

    all_ok = verify_all()
    print_root_notice()
    print_summary(failed_req, failed_opt, all_ok)


if __name__ == "__main__":
    main()
