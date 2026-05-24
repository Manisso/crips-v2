"""
Crips Framework — ai_mod.py
AI-powered output explainer via OpenRouter (or any OpenAI-compatible API)
"""

import os
import sys
import json
import re
import io
import time
import contextlib
from modules.colors import *

CONFIG_FILE = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "config.json")

DEFAULTS = {
    "ai_enabled":    True,
    "api_key":       "",
    "base_url":      "https://openrouter.ai/api/v1",
    "model":         "nvidia/nemotron-3-super-120b-a12b:free",
    "auto_explain":  False,
    "stream":        True,
    "max_tokens":    1200,
}

FREE_MODELS = [
    ("nvidia/nemotron-3-super-120b-a12b:free",         "Nemotron 3 Super  (fast, good quality)"),
    ("openai/gpt-oss-120b:free",                  "GPT OSS 120B (OpenAI, very strong)"),
    ("openai/gpt-oss-20b:free",                   "GPT OSS 20B (fast OpenAI model)"),
    ("meta-llama/llama-3.3-70b-instruct:free",   "Llama 3.3 70B (Meta, excellent)"),
    ("google/gemma-4-31b:free",                  "Gemma 4 31B (Google, powerful)"),
    ("deepseek/deepseek-v4-flash:free",          "DeepSeek V4 Flash (very fast)"),
    ("qwen/qwen3-next-80b-a3b-instruct:free",    "Qwen3 Next 80B (good multilingual)"),
    ("nvidia/nemotron-3-super:free",             "Nemotron 3 Super (huge context)"),
    ("minimax/minimax-m2.5:free",                "MiniMax M2.5 (balanced)"),
    ("z-ai/glm-4.5-air:free",                    "GLM 4.5 Air (fast reasoning)"),
    ("poolside/laguna-m1:free",                  "Laguna M1 (coding oriented)"),
]

SYSTEM_PROMPT = """You are a network educator embedded inside the Crips Network Learning Framework v2.0.
A student just used one of the 31 built-in tools and received the output below.

The 31 tools available in Crips (refer to them by number when suggesting next steps):
  WHOIS & DOMAIN  : [1] Whois Lookup
  DNS TOOLS       : [2] DNS Lookup  [3] Reverse DNS  [4] DNS Propagation  [5] Zone Transfer (AXFR)
  GEO & ASN       : [6] GeoIP + ASN  [7] Bulk GeoIP  [8] ASN / BGP Info
  NETWORK DIAG    : [9] ICMP Ping  [10] Ping Sweep  [11] TCP Ping  [12] Traceroute  [13] ARP Scan
  PORT SCANNING   : [14] TCP Port Scan  [15] Subnet Port Scan
  HTTP & WEB      : [16] HTTP Headers  [17] Redirect Chain  [18] Robots.txt & Sitemap  [19] HTTP Methods
  SSL / TLS       : [20] SSL Certificate Inspector
  SUBNET & IP     : [21] Subnet Calculator  [22] Subnet Splitter  [23] IP Info  [24] CIDR Range  [25] IPv6 Tools
  BANNERS         : [26] Banner Grabber  [27] Multi-Host Banner Scan
  LOCAL NETWORK   : [28] Interfaces  [29] MAC Analyzer  [30] Connectivity Check  [31] Active Connections

Your job:
🔍 WHAT THIS MEANS
  Explain the output in plain language (2-3 sentences). Interpret it, don't repeat raw data.

🎯 KEY FINDINGS
  Highlight 2-3 specific interesting or important discoveries from the output.

📚 WHAT TO LEARN
  Explain 1-2 networking concepts this output demonstrates (e.g. BGP routing, TLS handshake, ARP table).

🚀 NEXT STEPS IN CRIPS
  Suggest exactly 2 follow-up tools from the list above using their number and name.
  Example: "Try [14] TCP Port Scan on this IP to see which services are exposed."

Rules:
- Be concise, educational, and encouraging.
- Always reference Crips tools by their number [N] when suggesting next steps.
- If output shows errors or nothing found, explain what that means and still suggest next steps.
- Never repeat raw data back — always interpret and teach."""


# ── Config I/O ────────────────────────────────────────────────
def load_config() -> dict:
    try:
        with open(CONFIG_FILE) as f:
            cfg = json.load(f)
        # Fill in any missing keys from DEFAULTS
        for k, v in DEFAULTS.items():
            cfg.setdefault(k, v)
        return cfg
    except Exception:
        return dict(DEFAULTS)


def save_config(cfg: dict):
    try:
        with open(CONFIG_FILE, "w") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        err(f"Could not save config: {e}")


# ── ANSI stripper ─────────────────────────────────────────────
def strip_ansi(text: str) -> str:
    return re.sub(r"\033\[[0-9;]*[mABCDEFGHJKLMSTfinsulh]", "", text)


# ── API call ──────────────────────────────────────────────────
def call_ai(tool_name: str, tool_output: str, cfg: dict) -> bool:
    """
    Send tool output to AI and stream the explanation.
    Returns True if successful.
    """
    try:
        import requests as req
    except ImportError:
        err("requests not installed → pip install requests")
        return False

    api_key  = cfg.get("api_key", "")
    base_url = cfg.get("base_url", DEFAULTS["base_url"]).rstrip("/")
    model    = cfg.get("model",    DEFAULTS["model"])
    stream   = cfg.get("stream",   True)
    max_tok  = cfg.get("max_tokens", 1200)

    if not api_key:
        warn("No API key configured. Use '!' to set your OpenRouter key.")
        info("Get a free key at: https://openrouter.ai/keys")
        return False

    clean_output = strip_ansi(tool_output).strip()
    if not clean_output:
        warn("No output to analyze.")
        return False

    # Truncate very long outputs
    if len(clean_output) > 6000:
        clean_output = clean_output[:6000] + "\n...[output truncated]..."

    user_msg = f"Tool used: **{tool_name}**\n\nOutput:\n```\n{clean_output}\n```"

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type":  "application/json",
        "HTTP-Referer":  "https://github.com/crips-framework",
        "X-Title":       "Crips Network Learning Framework",
    }

    payload = {
        "model":      model,
        "max_tokens": max_tok,
        "stream":     stream,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_msg},
        ],
    }

    url = f"{base_url}/chat/completions"

    print(f"\n  {MAGENTA}{'═'*60}{RST}")
    print(f"  {MAGENTA}{BOLD}🤖 AI Analysis{RST}  {DIM}({model}){RST}")
    print(f"  {MAGENTA}{'─'*60}{RST}\n")

    try:
        if stream:
            resp = req.post(url, headers=headers, json=payload,
                            stream=True, timeout=30)
            if resp.status_code != 200:
                _handle_error(resp)
                return False

            print(f"  {WHITE}", end="", flush=True)
            col = 0
            for raw_line in resp.iter_lines():
                if not raw_line:
                    continue
                line = raw_line.decode("utf-8", errors="replace")
                if line.startswith("data: "):
                    line = line[6:]
                if line == "[DONE]":
                    break
                try:
                    chunk = json.loads(line)
                    delta = chunk["choices"][0]["delta"].get("content", "")
                    if delta:
                        # Colorize markdown-like headers
                        _print_ai_chunk(delta)
                except Exception:
                    pass
            print(f"{RST}")
        else:
            resp = req.post(url, headers=headers, json=payload, timeout=45)
            if resp.status_code != 200:
                _handle_error(resp)
                return False
            data    = resp.json()
            content = data["choices"][0]["message"]["content"]
            _print_ai_full(content)

        print(f"\n  {MAGENTA}{'═'*60}{RST}\n")
        return True

    except req.exceptions.Timeout:
        err("AI request timed out. Try a faster model.")
    except req.exceptions.ConnectionError:
        err("Could not connect to AI API. Check your internet connection.")
    except KeyboardInterrupt:
        print(f"\n  {YELLOW}[^C] AI response interrupted.{RST}")
    except Exception as e:
        err(f"AI error: {e}")

    return False


def _print_ai_chunk(delta: str):
    """Print a streaming chunk with basic markdown coloring."""
    sys.stdout.write(delta)
    sys.stdout.flush()


def _print_ai_full(content: str):
    """Print full non-streamed response with formatting."""
    lines = content.splitlines()
    for line in lines:
        stripped = line.strip()
        # Emoji/markdown headers
        if stripped.startswith(("##", "###", "**", "##")):
            cleaned = stripped.lstrip("#").strip().strip("*")
            print(f"\n  {YELLOW}{BOLD}{cleaned}{RST}")
        elif stripped.startswith(("- ", "• ", "* ")):
            item = stripped[2:]
            print(f"    {CYAN}●{RST} {WHITE}{item}{RST}")
        elif stripped.startswith(("1.", "2.", "3.", "4.", "5.")):
            print(f"    {CYAN}{stripped[:2]}{RST} {WHITE}{stripped[2:].strip()}{RST}")
        elif stripped:
            print(f"  {WHITE}{line}{RST}")
        else:
            print()


def _handle_error(resp):
    try:
        data = resp.json()
        msg  = data.get("error", {}).get("message", resp.text[:200])
    except Exception:
        msg = resp.text[:200]

    if resp.status_code == 401:
        err(f"Invalid API key. Use '!' to update it.")
    elif resp.status_code == 402:
        err(f"Insufficient credits on your API account.")
    elif resp.status_code == 429:
        err(f"Rate limited. Wait a moment and try again.")
    elif resp.status_code == 404:
        err(f"Model not found: {msg}")
    else:
        err(f"API error {resp.status_code}: {msg}")


# ── Post-tool hook ────────────────────────────────────────────
def maybe_explain(tool_name: str, tool_output: str):
    """
    Called after every tool. Optionally prompts the user to get AI explanation.
    """
    cfg = load_config()
    if not cfg.get("ai_enabled", True):
        return

    if not cfg.get("api_key"):
        # Silently skip if no key configured
        return

    clean = strip_ansi(tool_output).strip()
    if not clean or len(clean) < 30:
        return  # Nothing meaningful to explain

    auto = cfg.get("auto_explain", False)
    if auto:
        call_ai(tool_name, tool_output, cfg)
    else:
        try:
            ans = input(f"\n  {MAGENTA}🤖 Ask AI to explain this output? [y/N]: {RST}").strip().lower()
            if ans in ("y", "yes"):
                call_ai(tool_name, tool_output, cfg)
        except (KeyboardInterrupt, EOFError):
            pass


# ── Configuration menu (! command) ───────────────────────────
def config_menu():
    cfg = load_config()

    while True:
        clear()
        print(f"""
  {MAGENTA}{BOLD}╔══════════════════════════════════════════╗
  ║       AI Configuration  [ ! ]           ║
  ╚══════════════════════════════════════════╝{RST}

  {YELLOW}Current Settings:{RST}
  {GRAY}─────────────────────────────────────────{RST}
  {CYAN}AI Enabled   {RST}: {GREEN if cfg['ai_enabled'] else RED}{cfg['ai_enabled']}{RST}
  {CYAN}Auto-Explain {RST}: {GREEN if cfg['auto_explain'] else GRAY}{cfg['auto_explain']}{RST}
  {CYAN}Base URL     {RST}: {WHITE}{cfg['base_url']}{RST}
  {CYAN}Model        {RST}: {WHITE}{cfg['model']}{RST}
  {CYAN}API Key      {RST}: {GREEN}{'*' * min(8, len(cfg['api_key'])) + '...' if cfg['api_key'] else RED+'[not set]'+RST}{RST}
  {CYAN}Streaming    {RST}: {WHITE}{cfg['stream']}{RST}
  {CYAN}Max Tokens   {RST}: {WHITE}{cfg['max_tokens']}{RST}
  {GRAY}─────────────────────────────────────────{RST}

  {W}[1]{RST} Set API Key
  {W}[2]{RST} Set Base URL  (default: OpenRouter)
  {W}[3]{RST} Set Model
  {W}[4]{RST} Toggle AI on/off
  {W}[5]{RST} Toggle Auto-explain
  {W}[6]{RST} Toggle Streaming
  {W}[7]{RST} Set Max Tokens
  {W}[8]{RST} Browse free models
  {W}[9]{RST} Test API connection
  {W}[r]{RST} Reset to defaults
  {W}[0]{RST} Back to menu
""")
        try:
            ch = input(f"  {MAGENTA}ai-config{RST}~{RED}#{RST} ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            break

        if ch == "0":
            break

        elif ch == "1":
            print(f"\n  {DIM}Get a free key at: https://openrouter.ai/keys{RST}")
            key = input(f"  {WHITE}Enter API Key: {RST}").strip()
            if key:
                cfg["api_key"] = key
                save_config(cfg)
                ok("API key saved.")
            else:
                warn("No key entered.")
            time.sleep(1)

        elif ch == "2":
            print(f"\n  {DIM}Presets:{RST}")
            presets = [
                ("OpenRouter",  "https://openrouter.ai/api/v1"),
                ("OpenAI",      "https://api.openai.com/v1"),
                ("Ollama",      "http://localhost:11434/v1"),
                ("LM Studio",   "http://localhost:1234/v1"),
                ("Together AI", "https://api.together.xyz/v1"),
                ("Groq",        "https://api.groq.com/openai/v1"),
                ("Custom",      ""),
            ]
            for i, (name, url) in enumerate(presets, 1):
                print(f"  {GRAY}[{i}]{RST} {CYAN}{name:<14}{RST}  {DIM}{url}{RST}")
            ch2 = input(f"\n  {WHITE}Choose preset or enter URL directly: {RST}").strip()
            if ch2.isdigit() and 1 <= int(ch2) <= len(presets):
                name, url = presets[int(ch2)-1]
                if url:
                    cfg["base_url"] = url
                    save_config(cfg)
                    ok(f"Base URL set to {name}: {url}")
                else:
                    url = input(f"  {WHITE}Enter custom URL: {RST}").strip()
                    if url:
                        cfg["base_url"] = url
                        save_config(cfg)
                        ok(f"Base URL set to: {url}")
            elif ch2.startswith("http"):
                cfg["base_url"] = ch2
                save_config(cfg)
                ok(f"Base URL set to: {ch2}")
            time.sleep(1.2)

        elif ch == "3":
            model = input(f"  {WHITE}Enter model name (e.g. mistralai/mistral-7b-instruct:free): {RST}").strip()
            if model:
                cfg["model"] = model
                save_config(cfg)
                ok(f"Model set to: {model}")
            time.sleep(1)

        elif ch == "4":
            cfg["ai_enabled"] = not cfg["ai_enabled"]
            save_config(cfg)
            state = f"{GREEN}ENABLED{RST}" if cfg["ai_enabled"] else f"{RED}DISABLED{RST}"
            print(f"  AI is now {state}")
            time.sleep(1)

        elif ch == "5":
            cfg["auto_explain"] = not cfg["auto_explain"]
            save_config(cfg)
            state = f"{GREEN}ON{RST}" if cfg["auto_explain"] else f"{GRAY}OFF{RST}"
            print(f"  Auto-explain is now {state}")
            if cfg["auto_explain"]:
                info("AI will automatically explain every tool output.")
            else:
                info("AI will ask before explaining each output.")
            time.sleep(1.2)

        elif ch == "6":
            cfg["stream"] = not cfg["stream"]
            save_config(cfg)
            print(f"  Streaming: {GREEN if cfg['stream'] else GRAY}{cfg['stream']}{RST}")
            time.sleep(1)

        elif ch == "7":
            val = input(f"  {WHITE}Max tokens [100-4000, default 1200]: {RST}").strip()
            if val.isdigit():
                cfg["max_tokens"] = max(100, min(4000, int(val)))
                save_config(cfg)
                ok(f"Max tokens set to {cfg['max_tokens']}")
            time.sleep(1)

        elif ch == "8":
            print(f"\n  {YELLOW}{BOLD}Free models on OpenRouter:{RST}\n")
            for i, (model_id, desc) in enumerate(FREE_MODELS, 1):
                cur = f"  {GREEN}← current{RST}" if model_id == cfg["model"] else ""
                print(f"  {GRAY}[{i}]{RST} {CYAN}{model_id}{RST}{cur}")
                print(f"       {DIM}{desc}{RST}")
            print()
            ch2 = input(f"  {WHITE}Select model number (or Enter to skip): {RST}").strip()
            if ch2.isdigit() and 1 <= int(ch2) <= len(FREE_MODELS):
                cfg["model"] = FREE_MODELS[int(ch2)-1][0]
                save_config(cfg)
                ok(f"Model set to: {cfg['model']}")
            time.sleep(1.2)

        elif ch == "9":
            print(f"\n  {DIM}Testing connection to {cfg['base_url']}...{RST}")
            _test_connection(cfg)
            input(f"\n  {DIM}Press Enter...{RST}")

        elif ch == "r":
            confirm = input(f"  {RED}Reset all settings to defaults? [y/N]: {RST}").strip().lower()
            if confirm == "y":
                cfg = dict(DEFAULTS)
                save_config(cfg)
                ok("Settings reset to defaults.")
            time.sleep(1)


def _test_connection(cfg: dict):
    try:
        import requests as req
        if not cfg.get("api_key"):
            warn("No API key set.")
            return

        resp = req.get(
            f"{cfg['base_url'].rstrip('/')}/models",
            headers={"Authorization": f"Bearer {cfg['api_key']}"},
            timeout=10
        )
        if resp.status_code == 200:
            data = resp.json()
            models = data.get("data", [])
            ok(f"Connection successful! {len(models)} models available.")
            # Show free models available
            free = [m["id"] for m in models if ":free" in m.get("id","")]
            if free:
                print(f"  {DIM}Free models available: {len(free)}{RST}")
                for m in free[:5]:
                    print(f"    {CYAN}· {m}{RST}")
        elif resp.status_code == 401:
            err("Authentication failed — check your API key.")
        else:
            err(f"API returned HTTP {resp.status_code}")
    except Exception as e:
        err(f"Connection failed: {e}")


def clear():
    os.system("clear" if os.name != "nt" else "cls")


# Re-export W for use in config_menu
W = WHITE
