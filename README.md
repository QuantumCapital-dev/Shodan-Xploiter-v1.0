<div align="center">

# 🔴 SHODAN XPLOITER v1.0

**AI-powered 3-phase OSINT exploit analyzer for authorized penetration testing**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://python.org)
[![Claude AI](https://img.shields.io/badge/Claude-Sonnet%204.6-orange?style=for-the-badge&logo=anthropic)](https://anthropic.com)
[![Shodan](https://img.shields.io/badge/Shodan-API%20%2B%20Scraper-red?style=for-the-badge)](https://shodan.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

> ⚠️ **FOR AUTHORIZED ENGAGEMENTS ONLY** — Unauthorized use is illegal and unethical.

</div>


***

## 📌 Overview

**Shodan Xploiter v1.0** is a **passive security analysis tool** that performs deep
vulnerability assessment based entirely on **Shodan-indexed data** — no active scans,
no probes, no traffic to the target.

Unlike traditional pentest tools that run Nmap, Nikto, or similar scanners directly
against the target, Shodan Xploiter works **100% passively**: it pulls what Shodan
already knows about an IP (open ports, banners, service versions, CVEs) and feeds
that data into a multi-phase **Claude Sonnet 4.6** reasoning pipeline that produces
a detailed attack surface analysis and a full exploitation guide.

If the target IP has no Shodan index entry, the tool stops at Phase 1 — there is
no data to reason about, and no guesswork is introduced.

> **Key principle:** all findings are derived exclusively from Shodan-indexed data.
> No packets are sent to the target at any point during the analysis.

The tool runs a **3-phase AI pipeline**:

| Phase | Model | Input | Output |
|-------|-------|-------|--------|
| 🔵 **Phase 1** — Identity Attribution | Claude Haiku | WHOIS + IPInfo | Geolocation, ASN, hosting type, VPN/Tor flags, abuse contacts |
| 🔴 **Phase 2** — Attack Surface & CVEs | Claude Sonnet | Shodan + Phase 1 | Per-port CVE mapping, Metasploit modules, MITRE ATT&CK, CVSS v3.1 |
| 🟠 **Phase 3** — Penetration Testing Guide | Claude Sonnet | Phase 1 + Phase 2 | Full exploit chain, ready bash commands, post-exploitation, cleanup |

***

## 🚀 About This Project

Shodan Xploiter started as an internal tool built by **Quantum Capital** during security
research operations. After consistently producing detailed, actionable results that
outperformed manual analysis workflows, we decided to **isolate it as a standalone
project and release it open source**.

The core pipeline — combining passive OSINT collection with multi-phase AI reasoning —
proved effective enough that we felt the security community could benefit from it.
Contributions, improvements, and issue reports are welcome.

***

## 🖥️ Screenshots

<img width="445" height="403" alt="Screenshot from 2026-04-06 18-43-19" src="https://github.com/user-attachments/assets/a7cebe45-65a1-42a5-9930-be81f412a8e4" />

***

## ✨ Features

- 🎯 **Interactive target input** — IPv4 validation with animated boot sequence and glitch FX
- 🌐 **Triple OSINT collection** — WHOIS/RDAP, IPInfo.io, Shodan (API + passive web scraper fallback)
- 🤖 **Dual AI model strategy** — Haiku for lightweight attribution, Sonnet for deep vulnerability reasoning
- 📋 **CVE mapping with CVSS v3.1** — Exact CVEs when version is confirmed, full attack surface when unknown
- 🗂️ **MITRE ATT&CK mapping** — Every finding mapped to T-IDs
- 🔗 **Service interaction analysis** — Reasons about how Redis + SSH + PostgreSQL together change the attack chain
- 🛡️ **Shodan gate** — Automatically skips Phase 2 & 3 if IP is not indexed (no wasted API credits)
- 💾 **Auto-saved reports** — Markdown OSINT report, Markdown pentest guide, and raw JSON
- 🧹 **Cleanup commands included** — Every exploitation scenario includes artifact removal steps

***

## 📁 Project Structure

```
shodan-xploiter/
│
├── main.py                   # Entry point — CLI, logo, orchestration
├── config.py                 # ENV loader — API keys, models, output dir
├── requirements.txt          # Python dependencies
├── .env                      # Your API keys (not committed)
│
├── collectors/
│   ├── whois_collector.py    # WHOIS / RDAP via ipwhois
│   ├── ipinfo_collector.py   # IPInfo.io geolocation & privacy flags
│   └── shodan_collector.py   # Shodan API + passive web scraper fallback
│
├── analysis/
│   ├── ai_provider.py        # Anthropic Claude provider (Haiku + Sonnet)
│   └── prompts.py            # Phase 1/2/3 prompt templates 
│
└── output/
    └── report_writer.py      # Saves .md, pentest.md, .json reports to disk
```

***

## ⚙️ Installation

### 1. Clone the repository

```bash
git clone https://github.com/YOUR_USERNAME/shodan-xploiter.git
cd shodan-xploiter
```

### 2. Create a virtual environment (recommended)

```bash
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate           # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure API keys

Copy the example env file and fill in your keys:

```bash
cp .env.example .env
nano .env
```

Edit `.env` with your credentials:

```dotenv
# Required
ANTHROPIC_API_KEY=sk-ant-your-key-here

# Optional — fallback passive scraper is used automatically if not set
SHODAN_API_KEY=your-shodan-api-key
IPINFO_TOKEN=your-ipinfo-token

# Output directory for saved reports (default: .reports)
OUTPUT_DIR=.reports
```

> **Note:** `ANTHROPIC_API_KEY` is the **only required key**. Without a Shodan API key, the tool automatically falls back to a passive web scraper at no cost.

***

## 🚀 Usage

### Full run — 3-phase AI pipeline

```bash
python main.py
```

The tool displays the animated boot logo and then interactively prompts for the target IP:

```
Enter target IP address: 1.2.3.4
```

***

### Collectors only — skip AI, print raw JSON

```bash
python main.py --no-ai
```

Runs WHOIS, IPInfo, and Shodan collection only. Outputs raw JSON to stdout. Useful for quick recon or debugging without spending API credits.

***

### Custom output directory

```bash
python main.py --output-dir /tmp/pentest-reports
```

***

### All CLI options

```
usage: main.py [-h] [--no-ai] [--output-dir OUTPUT_DIR]

options:
  -h, --help             show this help message and exit
  --no-ai                Run collectors only, skip AI analysis, print raw JSON
  --output-dir DIR       Directory for saved reports (default: .reports)
```

***

## 📂 Output Files

After a full run, three files are saved to `.reports/` (or your `--output-dir`):

| File | Contents |
|------|----------|
| `<ip>_<timestamp>.md` | Phase 1 (Identity) + Phase 2 (Attack Surface) OSINT report |
| `<ip>_<timestamp>_pentest.md` | Phase 3 full penetration testing guide with bash commands |
| `<ip>_<timestamp>_raw.json` | All raw collector data + AI phase outputs in structured JSON |

**Example:**

```
.reports/
├── 1_2_3_4_20260406120000.md
├── 1_2_3_4_20260406120000_pentest.md
└── 1_2_3_4_20260406120000_raw.json
```

***

## 🧠 AI Pipeline Detail

```
┌─────────────────────────────────────────────────────────┐
│  INPUT: Target IPv4                                     │
└──────────────────────┬──────────────────────────────────┘
                       │
          ┌────────────▼────────────┐
          │   COLLECTION LAYER      │
          │  • WHOIS / RDAP         │
          │  • IPInfo.io            │
          │  • Shodan API/Scraper   │
          └────────────┬────────────┘
                       │
          ┌────────────▼────────────────┐
          │  PHASE 1 — Claude Haiku     │
          │  Identity Attribution       │
          │  Geolocation, ASN,          │
          │  VPN/Tor flags, abuse info  │
          └────────────┬────────────────┘
                       │
            [Shodan gate: IP not indexed → STOP]
                       │
          ┌────────────▼────────────────┐
          │  PHASE 2 — Claude Sonnet    │
          │  Attack Surface & CVEs      │
          │  CVE/CVSS, Metasploit,      │
          │  MITRE ATT&CK mappings      │
          └────────────┬────────────────┘
                       │
          ┌────────────▼────────────────┐
          │  PHASE 3 — Claude Sonnet    │
          │  Penetration Testing Guide  │
          │  Bash chains, post-exploit, │
          │  cleanup, checklist         │
          └────────────┬────────────────┘
                       │
          ┌────────────▼────────────┐
          │  REPORT WRITER          │
          │ .md / pentest.md / .json│
          └─────────────────────────┘
```

***

## 📦 Dependencies

```
shodan>=1.31.0          # Shodan API client
ipwhois>=1.3.0          # WHOIS / RDAP resolution
requests>=2.31.0        # HTTP client
ipinfo>=5.0.0           # IPInfo.io geolocation & privacy
anthropic>=0.29.0       # Claude AI provider (Haiku + Sonnet)
python-dotenv>=1.0.0    # .env file loader
rich>=13.7.0            # Terminal UI — colors, tables, panels, spinners
beautifulsoup4>=4.12.0  # Passive Shodan web scraper fallback
lxml>=5.0.0             # HTML parser for BeautifulSoup
```

***

## ⚠️ Legal Disclaimer

This tool is designed **exclusively for authorized security engagements** — penetration tests, CTF challenges, bug bounty programs, and security research on infrastructure you own or have explicit written permission to test.

**Using this tool against systems without authorization is illegal** under the Computer Fraud and Abuse Act (CFAA), EU Directive 2013/40/EU, and equivalent laws in most jurisdictions.

> Quantum Capital accept **zero liability** for any misuse of this software.

***

## 👤 Author

**Quantum Capital**  
🌐 [www.quantumcapital.capital](https://www.quantumcapital.capital)

***

<div align="center">

*Shodan Xploiter v1.0 — Quantum Capital*

**`UNAUTHORIZED ACCESS DETECTED — SYSTEM COMPROMISED`**

</div

