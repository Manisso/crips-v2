"""
Crips Framework — colors.py
ANSI color constants + styled output helpers
"""

import sys

# Initialize colorama for Windows support
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=False)
except ImportError:
    pass

# ── Color codes ──────────────────────────────────────────────
RED     = "\033[91m"
GREEN   = "\033[92m"
YELLOW  = "\033[93m"
BLUE    = "\033[94m"
MAGENTA = "\033[95m"
CYAN    = "\033[96m"
WHITE   = "\033[97m"
GRAY    = "\033[90m"
DIM     = "\033[2m"
BOLD    = "\033[1m"
UNDER   = "\033[4m"
BLINK   = "\033[5m"
RST     = "\033[0m"

# ── Semantic aliases ─────────────────────────────────────────
OK      = GREEN
WARN    = YELLOW
ERR     = RED
INFO    = CYAN
LABEL   = YELLOW
VAL     = WHITE
HDR     = MAGENTA

# ── Styled print helpers ──────────────────────────────────────
def ok(msg):       print(f"  {GREEN}[✓]{RST} {msg}")
def err(msg):      print(f"  {RED}[✗]{RST} {msg}")
def warn(msg):     print(f"  {YELLOW}[!]{RST} {msg}")
def info(msg):     print(f"  {CYAN}[i]{RST} {msg}")
def step(msg):     print(f"  {GRAY}{msg}{RST}")
def header(msg):   print(f"\n  {YELLOW}── {BOLD}{msg}{RST} {YELLOW}──{RST}")
def kv(key, val, indent=4):
    pad = " " * indent
    print(f"{pad}{YELLOW}{key:<22}{RST}: {WHITE}{val}{RST}")

def sep(char="─", width=62):
    print(f"\n  {GRAY}{char * width}{RST}\n")

def title_box(text, subtitle=""):
    w = 44
    bar = "═" * w
    print(f"\n  {CYAN}╔{bar}╗{RST}")
    pad = (w - len(text)) // 2
    print(f"  {CYAN}║{RST}{' ' * pad}{BOLD}{WHITE}{text}{RST}{' ' * (w - pad - len(text))}{CYAN}║{RST}")
    if subtitle:
        pad2 = (w - len(subtitle)) // 2
        print(f"  {CYAN}║{RST}{' ' * pad2}{DIM}{subtitle}{RST}{' ' * (w - pad2 - len(subtitle))}{CYAN}║{RST}")
    print(f"  {CYAN}╚{bar}╝{RST}\n")

def print_table(rows, headers, col_widths=None):
    """Print a formatted table."""
    if not rows:
        warn("No data to display.")
        return
    if col_widths is None:
        col_widths = [max(len(str(r[i])) for r in rows + [headers]) + 2
                      for i in range(len(headers))]
    # Header row
    hdr_line = "  " + "  ".join(
        f"{BOLD}{YELLOW}{h:<{w}}{RST}" for h, w in zip(headers, col_widths)
    )
    print(hdr_line)
    print(f"  {GRAY}{'─' * (sum(col_widths) + len(col_widths) * 2)}{RST}")
    for row in rows:
        line = "  " + "  ".join(
            f"{CYAN}{str(v):<{w}}{RST}" for v, w in zip(row, col_widths)
        )
        print(line)

def prompt(msg, default=""):
    hint = f" [{DIM}{default}{RST}]" if default else ""
    try:
        val = input(f"  {WHITE}{msg}{hint}{RST}: ").strip()
        return val if val else default
    except (KeyboardInterrupt, EOFError):
        return default
