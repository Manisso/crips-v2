<div align="center">

```
   ██████╗██████╗ ██╗██████╗ ███████╗
  ██╔════╝██╔══██╗██║██╔══██╗██╔════╝
  ██║     ██████╔╝██║██████╔╝███████╗
  ██║     ██╔══██╗██║██╔═══╝ ╚════██║
  ╚██████╗██║  ██║██║██║     ███████║
   ╚═════╝╚═╝  ╚═╝╚═╝╚═╝     ╚══════╝
```

# Crips Framework v2.0
### Network Learning & Reconnaissance Toolkit

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey?style=for-the-badge)]()
[![AI Powered](https://img.shields.io/badge/AI-OpenRouter%20Powered-purple?style=for-the-badge&logo=openai)](https://openrouter.ai)
[![Stars](https://img.shields.io/github/stars/YOUR_USERNAME/crips?style=for-the-badge)](https://github.com/YOUR_USERNAME/crips/stargazers)

**31 network tools in one terminal framework — powered entirely by pip, with built-in AI explanations via OpenRouter.**

[Features](#-features) • [Install](#-installation) • [Tools](#-all-31-tools) • [AI Setup](#-ai-powered-explanations) • [Usage](#-usage) • [Screenshots](#-screenshots)

</div>

---

## 🌟 What is Crips?

Crips is a **modular network toolkit** built for students, CTF players, sysadmins, and anyone learning how networking protocols work. Every tool is implemented in pure Python using pip-installable libraries — no compiled binaries, no complex setup.

After every scan, Crips can send the output to an **AI** (OpenRouter, OpenAI, Ollama, or any OpenAI-compatible API) which generates a full **learning report**: what the output means, key findings, networking concepts demonstrated, and suggested next steps.

> ⚡ Inspired by [Manisso/Crips](https://github.com/Manisso/Crips) — completely rebuilt in Python 3 with local tools, AI integration, and many new modules.

---

## ✨ Features

| Feature | Description |
|---|---|
| **31 Network Tools** | Whois, DNS, GeoIP, port scan, traceroute, SSL, HTTP analysis, subnet calc, banner grabbing and more |
| **Pure pip** | Every tool runs via pip-installed Python libraries — no nmap, no masscan binary required |
| **AI Explanations** | After any tool, ask AI to generate a learning report with key findings and next steps |
| **Any LLM API** | OpenRouter (default, free models), OpenAI, Ollama (local), LM Studio, Groq, Together AI |
| **Free by default** | Uses `mistralai/mistral-7b-instruct:free` — no credits needed on OpenRouter |
| **GeoLite2 Auto-download** | MaxMind databases downloaded automatically at install (no signup via P3TERX mirror) |
| **Multi-threaded scanning** | Concurrent TCP port scanner — scan 1000 ports in seconds |
| **Learning-focused** | Every tool teaches a concept — service banners, DNS hierarchy, BGP routing, TLS handshake |
| **Cross-platform** | Linux, macOS, Windows (WSL recommended for raw socket tools) |

---

## 📦 Installation

```bash
# 1. Clone the repository
git clone https://github.com/Manisso/crips-v2.git
cd crips

# 2. Install everything (packages + GeoLite2 databases)
python3 install.py

# 3. Run
python3 crips.py

# For ICMP ping, traceroute, and ARP scan (tools 9, 10, 12, 13):
sudo python3 crips.py
```

### Requirements

- Python **3.8+**
- pip

`install.py` handles everything else automatically:
- All pip packages
- `GeoLite2-ASN.mmdb`, `GeoLite2-City.mmdb`, `GeoLite2-Country.mmdb` (from [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb) — no signup needed)
- Default `config.json` for AI settings

```bash
# Or install packages manually:
pip install -r requirements.txt
```

---

## 🔧 All 31 Tools

### 🌐 Whois & Domain
| # | Tool | Description |
|---|---|---|
| 1 | **Whois Lookup** | Full WHOIS registration info — registrar, dates, nameservers, contacts |

### 🔍 DNS Tools
| # | Tool | Description |
|---|---|---|
| 2 | **DNS Lookup** | Query all record types: A, AAAA, MX, NS, TXT, SOA, CNAME, CAA, SRV, DNSKEY... |
| 3 | **Reverse DNS** | IP → hostname via PTR records, supports full CIDR range sweep |
| 4 | **DNS Propagation** | Check a record across 8 public resolvers (Google, Cloudflare, OpenDNS, Quad9...) |
| 5 | **Zone Transfer** | Attempt AXFR on all nameservers — tests for misconfiguration |

### 🌍 GeoIP & ASN
| # | Tool | Description |
|---|---|---|
| 6 | **GeoIP + ASN** | Country, city, lat/long, timezone + ASN, BGP CIDR, network owner via RDAP |
| 7 | **Bulk GeoIP** | GeoIP lookup for a list of IPs — table output |
| 8 | **ASN / BGP Info** | Autonomous system details, network objects, routing info |

### 📡 Network Diagnostics
| # | Tool | Description |
|---|---|---|
| 9 | **ICMP Ping** | Full ping with RTT stats — like system `ping` (needs root) |
| 10 | **Ping Sweep** | Discover all live hosts in a subnet using ICMP (needs root) |
| 11 | **TCP Ping** | Check host reachability via TCP connect — no root required |
| 12 | **Traceroute** | ICMP or UDP hop-by-hop path with RTT per hop (needs root) |
| 13 | **ARP Scan** | Discover all devices on local LAN — returns IP + MAC + vendor |

### 🔌 Port Scanning
| # | Tool | Description |
|---|---|---|
| 14 | **TCP Port Scan** | Multi-threaded TCP connect scanner — top20/web/db/mail groups or custom range |
| 15 | **Subnet Port Scan** | Check a single port across an entire subnet — find all SSH/HTTP servers |

### 🌐 HTTP & Web
| # | Tool | Description |
|---|---|---|
| 16 | **HTTP Headers** | Full header dump + security header audit + technology fingerprinting |
| 17 | **Redirect Chain** | Trace every redirect step-by-step with status codes |
| 18 | **Robots.txt + Sitemap** | Fetch and parse crawl directives and sitemap URL structure |
| 19 | **HTTP Methods** | Test which HTTP verbs (GET, POST, PUT, DELETE, TRACE...) a server accepts |

### 🔒 SSL / TLS
| # | Tool | Description |
|---|---|---|
| 20 | **SSL Inspector** | Certificate details, SAN names, chain, fingerprints, TLS version support matrix |

### 🧮 Subnet & IP Tools
| # | Tool | Description |
|---|---|---|
| 21 | **Subnet Calculator** | Network/broadcast/mask/wildcard/binary/hex — full breakdown |
| 22 | **Subnet Splitter** | Divide any network into equal sub-networks |
| 23 | **IP Address Info** | Classify an IP — private/public/multicast + RFC reference + binary repr |
| 24 | **CIDR → IP Range** | Expand a CIDR block to first/last addresses or full IP list |
| 25 | **IPv6 Tools** | Expand, analyze, and classify IPv6 addresses |

### 📋 Banners & Services
| # | Tool | Description |
|---|---|---|
| 26 | **Banner Grabber** | Read raw protocol greetings from open ports — SSH, FTP, SMTP, Redis, MySQL... |
| 27 | **Multi-Host Banner** | Grab the banner of a specific port across many hosts |

### 💻 Local Network
| # | Tool | Description |
|---|---|---|
| 28 | **Network Interfaces** | Show all local adapters, IPs, MACs, and default gateway |
| 29 | **MAC Analyzer** | OUI vendor lookup + multicast/local-admin flag analysis |
| 30 | **Connectivity Check** | Latency to public DNS and HTTP endpoints |
| 31 | **Active Connections** | Show this machine's open network sockets (psutil) |

---

## 🤖 AI-Powered Explanations

After every tool run, Crips asks:

```
🤖 Ask AI to explain this output? [y/N]:
```

The AI reads the raw tool output and generates a **learning report**:

```
🔍 What This Means
  The DNS lookup reveals this domain uses Google's nameservers (ns1.google.com),
  meaning DNS is managed through Google Domains or Workspace...

🎯 Key Findings
  ● MX records point to Google mail servers — this organization uses Gmail
  ● TXT record contains SPF policy limiting who can send email as this domain
  ● SOA serial number follows YYYYMMDDNN format — last updated today

📚 Concepts Demonstrated
  ● DNS hierarchy: authoritative vs recursive resolvers
  ● Email authentication: SPF, DKIM, DMARC chain of trust

🚀 Next Steps
  ● Try tool [5] Zone Transfer to check if AXFR is misconfigured
  ● Use tool [4] DNS Propagation to verify records are globally consistent
```

### Setup

```
# Inside crips, press [!] to open AI configuration:

  [1] Set API Key
  [2] Set Base URL  (OpenRouter / OpenAI / Ollama / Groq / LM Studio)
  [3] Set Model
  [4] Toggle AI on/off
  [5] Toggle Auto-explain
  [6] Toggle Streaming
  [8] Browse free models
  [9] Test API connection
```

### Supported APIs

| Provider | Base URL | Notes |
|---|---|---|
| **OpenRouter** (default) | `https://openrouter.ai/api/v1` | Free models available |
| OpenAI | `https://api.openai.com/v1` | GPT-4o, GPT-3.5... |
| Ollama | `http://localhost:11434/v1` | Run models locally |
| LM Studio | `http://localhost:1234/v1` | Local GUI + server |
| Groq | `https://api.groq.com/openai/v1` | Very fast inference |
| Together AI | `https://api.together.xyz/v1` | Many open models |

### Free Models (OpenRouter, no credits needed)

| Model | Speed | Quality |
|---|---|---|
| `openai/gpt-oss-120b:free` | Medium | ⭐⭐⭐⭐⭐ |
| `openai/gpt-oss-20b:free` | Fast | ⭐⭐⭐⭐ |
| `meta-llama/llama-3.3-70b-instruct:free` | Medium | ⭐⭐⭐⭐⭐ |
| `google/gemma-4-31b:free` | Medium | ⭐⭐⭐⭐ |
| `deepseek/deepseek-v4-flash:free` | Very fast | ⭐⭐⭐⭐ |
| `qwen/qwen3-next-80b-a3b-instruct:free` | Fast | ⭐⭐⭐⭐ |
| `nvidia/nemotron-3-super:free` | Slow | ⭐⭐⭐⭐⭐ |
| `minimax/minimax-m2.5:free` | Fast | ⭐⭐⭐⭐ |
| `z-ai/glm-4.5-air:free` | Very fast | ⭐⭐⭐⭐ |
| `poolside/laguna-m1:free` | Medium | ⭐⭐⭐⭐⭐ |
| `liquid/lfm2.5-1.2b-instruct:free` | Ultra fast | ⭐⭐ |
| `nvidia/nemotron-nano-9b-v2:free` | Very fast | ⭐⭐⭐ |

Get a free key: **https://openrouter.ai/keys**

---

## 🖥️ Usage

```
   ██████╗██████╗ ██╗██████╗ ███████╗
  ...

  Host: kali  IP: 192.168.1.100  Mode: root  [AI: mistral-7b:free]

  ── WHOIS & DOMAIN ──
  [ 1] Whois Lookup              [ 2] DNS Lookup (all types)
  ...

  crips~# 14        ← run TCP port scan
  crips~# !         ← open AI config
  crips~# ?         ← help
  crips~# cls       ← clear screen
  crips~# 0         ← exit
```

### Command Reference

| Command | Action |
|---|---|
| `1` – `31` | Run a tool |
| `!` | AI configuration menu |
| `?` | Help & tool reference |
| `cls` | Clear and redraw menu |
| `0` | Exit |

---

## 📁 Project Structure

```
crips/
├── crips.py              ← Main entry point (menu + tool runner + AI hook)
├── install.py            ← Auto-installer (packages + GeoLite2 DBs)
├── requirements.txt      ← All pip dependencies
├── config.json           ← AI settings (auto-created)
├── GeoLite2-ASN.mmdb     ← Auto-downloaded by install.py
├── GeoLite2-City.mmdb    ← Auto-downloaded by install.py
├── GeoLite2-Country.mmdb ← Auto-downloaded by install.py
└── modules/
    ├── colors.py         ← ANSI styling + print helpers
    ├── utils.py          ← Shared utilities (resolve, TCP, banner)
    ├── ai_mod.py         ← AI explanation engine + config menu
    ├── whois_mod.py      ← Tool 1
    ├── dns_mod.py        ← Tools 2–5
    ├── geoip_mod.py      ← Tools 6–8
    ├── network_mod.py    ← Tools 9–13
    ├── portscan_mod.py   ← Tools 14–15
    ├── http_mod.py       ← Tools 16–19
    ├── ssl_mod.py        ← Tool 20
    ├── subnet_mod.py     ← Tools 21–25
    ├── banner_mod.py     ← Tools 26–27
    └── iface_mod.py      ← Tools 28–31
```

---

## 📚 Dependencies

All installed automatically by `install.py` or `pip install -r requirements.txt`:

| Package | Used for |
|---|---|
| `python-whois` | WHOIS lookups |
| `dnspython` | All DNS operations |
| `ipwhois` | ASN / BGP / RDAP |
| `geoip2` | MaxMind GeoLite2 reader |
| `scapy` | ICMP ping, traceroute, ARP |
| `requests` | HTTP analysis + AI API |
| `pyOpenSSL` | SSL/TLS inspection |
| `netaddr` | MAC OUI + subnet math |
| `netifaces` | Network interfaces |
| `colorama` | Windows ANSI colors |

**Zero non-pip dependencies** for 27/31 tools. Tools 9, 10, 12, 13 need root/sudo for raw socket access.

---

## ⚠️ Legal Notice

This tool is intended for:
- **Educational use** — learning how networking protocols work
- **CTF challenges** — Capture The Flag competitions
- **Your own systems** — testing infrastructure you own or have permission to test
- **Lab environments** — isolated networks for learning

Do **not** use this tool against systems you do not own or have explicit written permission to test. The authors are not responsible for misuse.

---

## 🙏 Credits

- Original concept: [Manisso/Crips](https://github.com/Manisso/Crips)
- GeoLite2 databases: [P3TERX/GeoLite.mmdb](https://github.com/P3TERX/GeoLite.mmdb)
- AI powered by: [OpenRouter](https://openrouter.ai)

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**If this tool helped you learn something, please ⭐ star the repo!**

Made with ❤️ for the networking and cybersecurity learning community

</div>
