"""
Crips Framework — utils.py
Shared helpers: resolve, input validation, formatting
"""

import os
import sys
import socket
import ipaddress
import time
import re
from modules.colors import *


def clear():
    os.system("clear" if os.name != "nt" else "cls")


def resolve(target: str) -> str | None:
    """Resolve hostname to IP, return IP as-is, or None on failure."""
    if not target:
        return None
    try:
        ipaddress.ip_address(target)
        return target
    except ValueError:
        try:
            return socket.gethostbyname(target)
        except socket.gaierror as e:
            err(f"Could not resolve '{target}': {e}")
            return None


def resolve_many(target: str) -> list[str]:
    """Return all IPs for a hostname."""
    try:
        ipaddress.ip_address(target)
        return [target]
    except ValueError:
        try:
            results = socket.getaddrinfo(target, None)
            return list(dict.fromkeys(r[4][0] for r in results))
        except Exception:
            return []


def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "N/A"


def get_hostname() -> str:
    try:
        return socket.gethostname()
    except Exception:
        return "N/A"


def is_valid_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False


def is_valid_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False


def is_valid_domain(domain: str) -> bool:
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, domain))


def is_private_ip(addr: str) -> bool:
    try:
        return ipaddress.ip_address(addr).is_private
    except ValueError:
        return False


def reverse_ptr(ip: str) -> str:
    """Convert IP to in-addr.arpa PTR form."""
    parts = ip.split(".")
    return ".".join(reversed(parts)) + ".in-addr.arpa"


def human_port(port: int) -> str:
    """Return well-known service name for a port."""
    try:
        return socket.getservbyport(port)
    except Exception:
        return ""


def tcp_connect(host: str, port: int, timeout: float = 1.5) -> bool:
    """Quick TCP connect test — no root needed."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        result = s.connect_ex((host, port))
        s.close()
        return result == 0
    except Exception:
        return False


def grab_banner(host: str, port: int, timeout: float = 3.0,
                send: bytes = b"\r\n") -> str:
    """Grab raw banner from a TCP service."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.sendall(send)
        data = s.recv(1024)
        s.close()
        return data.decode(errors="replace").strip()
    except Exception:
        return ""


def require(module_name: str, pip_name: str = ""):
    """Try to import a module; print pip install hint on failure."""
    try:
        return __import__(module_name)
    except ImportError:
        pname = pip_name or module_name
        err(f"Module '{module_name}' not installed.")
        warn(f"Run:  pip install {pname}")
        return None


def ms(seconds: float) -> str:
    return f"{seconds * 1000:.2f} ms"


def rate_bar(value: float, max_val: float, width: int = 20) -> str:
    filled = int((value / max_val) * width) if max_val else 0
    bar = GREEN + "█" * filled + GRAY + "░" * (width - filled) + RST
    return bar


def paginate(lines: list[str], page_size: int = 40):
    """Print lines with pagination."""
    for i, line in enumerate(lines):
        print(line)
        if (i + 1) % page_size == 0 and i + 1 < len(lines):
            try:
                cont = input(f"\n  {DIM}-- Press Enter for more, q to quit -- {RST}")
                if cont.strip().lower() == "q":
                    break
            except (KeyboardInterrupt, EOFError):
                break
