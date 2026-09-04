<div align="center">

# 🔍 ReconX v2.1

### **Unified Reconnaissance, Attack Surface Mapping & Vulnerability Assessment Framework**

[![Linux](https://img.shields.io/badge/Platform-Linux-blue?logo=linux)](https://www.linux.org/)
[![Shell](https://img.shields.io/badge/Language-Shell-green?logo=gnu-bash)](https://www.gnu.org/software/bash/)
[![Version](https://img.shields.io/badge/Version-2.1.0-orange)](https://github.com/projectquantum-sec/ReconX)
[![License](https://img.shields.io/badge/License-MIT-red)](LICENSE)

**An automated, resilient reconnaissance framework engineered for penetration testers, red teamers, and bug bounty hunters.**

[Installation](#-installation) • [Quick Start](#-quick-start) • [Features](#-key-features) • [Wordlists](#-wordlists-system--depth-scaling) • [How-To Guides](#-how-to-practical-guides) • [API Keys & OSINT](#-api-keys--osint-configuration) • [Command Reference](#-command-reference)

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [Architecture](#-architecture)
- [Installation](#-installation)
- [Wordlists System & Depth Scaling](#-wordlists-system--depth-scaling)
- [How-To Practical Guides](#-how-to-practical-guides)
- [API Keys & OSINT Configuration](#-api-keys--osint-configuration)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Scan Modules Breakdown](#-scan-modules-breakdown)
- [OPSEC & Bug Bounty Mode](#-opsec--bug-bounty-mode)
- [Reporting & Dashboard](#-reporting--dashboard)
- [Command Reference](#-command-reference)
- [Troubleshooting](#-troubleshooting)

---

## 🎯 Overview

**ReconX** is a modular, high-speed reconnaissance framework designed to automate the entire intelligence gathering and vulnerability discovery pipeline. From multi-engine passive subdomain scraping and wildcard DNS elimination to active probing, CMS auditing, and technology-targeted Nuclei scanning, ReconX produces actionable security intelligence in clean Markdown, JSON, CSV, and interactive dark-mode HTML formats.

### Why Choose ReconX?

✅ **High-Yield & Zero-Key Resilient** - Seamlessly integrates 10+ free OSINT engines (`crt.sh`, `Subdomain Center`, `RapidDNS`, `CertSpotter`, `Anubis DB`, `AlienVault OTX`) without requiring mandatory API keys.  
✅ **Curated Built-in Wordlists (~500 KB)** - Ships with clean, deduplicated dictionaries in `wordlists/` for out-of-the-box operation on any minimal VPS or container.  
✅ **Smart SecLists Integration** - Automatically detects `/usr/share/wordlists` on Kali/Parrot/Ubuntu systems and scales dictionary depth to 200,000+ words on aggressive scans.  
✅ **5 Progressive Robustness Levels** - Scalable intensity from 10-second rapid triage to exhaustive deep-dive enumeration.  
✅ **Built-in OPSEC & Evasion** - Proxy support (HTTP/SOCKS5), customizable bounty headers (`-H`), randomized User-Agents, and rate-limiting.  
✅ **Interactive Dark-Mode Dashboard** - Executive HTML report with instant client-side vulnerability search and filtering.  
✅ **Non-Root & Environment Independent** - Built-in fallbacks to Python3 and POSIX regular expressions, eliminating fragile dependencies on external tools like `jq`.  

---

## ✨ Key Features

```
┌─────────────────────────────────────────────────────────────────────────┐
│                           ReconX Pipeline Stack                         │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  📡 Passive Recon      → 10+ OSINT sources + BeVigil + AlienVault OTX   │
│  🌐 DNS Intelligence   → Wildcard DNS catch, AXFR transfers, SPF/DMARC  │
│  🔍 Active Discovery   → Masscan / RustScan / Nmap version detection    │
│  🌍 Web Probing        → HTTPX status/tech detection, Katana, FFUF fuzz │
│  🔐 Technology Audit   → WhatWeb, Wafw00f, WPScan, Arjun parameters     │
│  🛡️ Vuln Assessment    → Tech-targeted Nuclei v3, OAST, Takeover checks │
│  📊 Multi-Format Docs  → Dark HTML Dashboard, JSON, CSV, Markdown, PDF  │
│                                                                         │
└─────────────────────────────────────────────────────────────────────────┘
```

### Robustness Levels

| Level | Name | Target Use Case | Engines & Tools | Wordlist Depth | Speed |
|:---:|:---:|:---|:---|:---|:---:|
| **1** | **Quick** | Rapid perimeter check | Whois, crt.sh, RapidDNS, Top ports, Fast Nuclei | ~5k words | ⚡⚡⚡ |
| **2** | **Light** | Standard reconnaissance | + Subfinder, Assetfinder, Top 1000 ports | ~5k words | ⚡⚡ |
| **3** | **Normal** | Balanced assessment *(Default)* | + Amass, theHarvester, Technology-targeted Nuclei | ~5k words | ⚡ |
| **4** | **Thorough** | Deep-dive penetration test | + Findomain, GAU, FFUF recursion, Screenshots | ~30k words | 🐌 |
| **5** | **Aggressive** | Exhaustive bug bounty scan | + Chaos, Full port ranges, Parameter spidering | ~220k words | 🐌🐌 |

---

## 📂 Wordlists System & Depth Scaling

ReconX features a dual-layer wordlist architecture designed for maximum speed and adaptability across any deployment environment.

### 1. Built-in Curated Wordlists (`wordlists/`)
ReconX bundles optimized, deduplicated dictionaries directly in the repository (**~500 KB total**), ensuring zero-configuration execution:

| File | Purpose | Size / Entries |
|:---|:---|:---:|
| [`wordlists/subdomains-fast.txt`](wordlists/subdomains-fast.txt) | Rapid DNS & Subdomain probing | 30 KB (~5,000 entries) |
| [`wordlists/subdomains-medium.txt`](wordlists/subdomains-medium.txt) | Deep DNS brute-forcing | 133 KB (~20,000 entries) |
| [`wordlists/directories-fast.txt`](wordlists/directories-fast.txt) | Fast directory & path discovery | 36 KB (~4,600 entries) |
| [`wordlists/directories-medium.txt`](wordlists/directories-medium.txt) | Comprehensive web fuzzing | 160 KB (~20,000 entries) |
| [`wordlists/sensitive-files.txt`](wordlists/sensitive-files.txt) | `.env`, `.git`, configs, database backups | 40 KB (~2,500 entries) |
| [`wordlists/api-endpoints.txt`](wordlists/api-endpoints.txt) | Modern REST / GraphQL endpoint hunting | 4.3 KB (~200 entries) |
| [`wordlists/parameters.txt`](wordlists/parameters.txt) | Hidden GET/POST parameter names | 53 KB (~2,500 entries) |

### 2. Automatic System Wordlists Detection (`config/wordlists.conf`)
If running on Kali Linux, Parrot OS, or a system with SecLists installed in `/usr/share/wordlists`:
- **Levels 1–3**: Uses fast dictionaries for instant results.
- **Level 4**: Automatically expands to `raft-medium-directories.txt` and `subdomains-top1million-20000.txt`.
- **Level 5**: Automatically loads full SecLists `directory-list-2.3-medium.txt` (~220,000 entries) and `subdomains-top1million-110000.txt`.
- **Custom List**: Pass `-w <path>` to override all default wordlists on the fly.

---

## 📖 How-To Practical Guides

### 1. How to run a zero-noise, 100% passive scan (No target interaction)
Ideal for initial client intelligence gathering without triggering target IDS/WAF:
```bash
./reconx.sh -t example.com --passive --dns -r 3
```

### 2. How to run Bug Bounty Mode with Proxies & Custom Headers
Route web scanning through Burp Suite or Tor while attaching researcher identification:
```bash
./reconx.sh -t target.com --full --bb \
  --proxy "http://127.0.0.1:8080" \
  -H "X-Bug-Bounty: hackerone_username" \
  --exclude "admin.target.com,staging.target.com"
```

### 3. How to perform web fuzzing with a custom wordlist
Supply custom company-specific or localized wordlists:
```bash
./reconx.sh -t target.com --web -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -r 4
```

### 4. How to configure and validate API keys live
Test which API endpoints are healthy and active before launching a scan:
```bash
# Run guided interactive configuration
./reconx.sh --config-wizard

# Perform live endpoint validation test
./reconx.sh --validate-keys
```

### 5. How to audit WordPress sites with WPScan API
Automatically detect vulnerable WordPress plugins, themes, and users:
```bash
# Add your free WPScan token in config/tools.conf (WPSCAN_API_TOKEN="your_token")
./reconx.sh -t blog.target.com --enum --vuln
```

### 6. How to generate and view the interactive HTML report
Generate all export formats and open the dark-mode dashboard:
```bash
./reconx.sh -t target.com --report --export html,json,csv,md

# Open the generated report
xdg-open output/target.com/reports/report_*.html
```

---

## 🏗️ Architecture

```
ReconX/
├── reconx.sh                 # Master CLI entrypoint & orchestrator
├── install.sh                # Automated installer for tools & Go packages
├── config/
│   ├── reconx.conf           # Global scanner settings, timeouts & limits
│   ├── tools.conf            # API credentials & OPSEC proxy settings
│   └── wordlists.conf        # Dynamic wordlist fallbacks & mappings
├── modules/
│   ├── passive.sh            # Passive subdomain & OSINT intelligence
│   ├── dns.sh                # DNS records, wildcard detection & zone transfers
│   ├── active.sh             # Host discovery & multi-engine port scanning
│   ├── web.sh                # HTTP probing, crawler & directory fuzzing
│   ├── enum.sh               # Service, JS, cloud bucket & CMS enumeration
│   ├── vuln.sh               # Vulnerability scanning (Nuclei v3 / OAST / WPScan)
│   └── report.sh             # HTML/JSON/CSV/MD multi-report generation
├── utils/
│   ├── api_validator.sh      # Live endpoint validator for API keys
│   ├── config_wizard.sh      # Interactive configuration assistant
│   ├── error_handler.sh      # Graceful SIGINT traps & process cleanup
│   ├── helpers.sh            # Multi-threading, IP resolvers & user-agents
│   ├── logger.sh             # Session-based multi-level file & CLI logger
│   └── menu.sh               # Interactive terminal dashboard
├── wordlists/                # Built-in lightweight wordlists (~500 KB)
└── output/                   # Target scan results & generated reports
```

---

## 📦 Installation

### Automated Installation (Debian / Ubuntu / Kali)

```bash
# 1. Clone the repository
git clone https://github.com/projectquantum-sec/ReconX.git
cd ReconX

# 2. Run the installer
chmod +x install.sh
sudo ./install.sh
```

The installer automatically configures:
- **System packages**: `nmap`, `masscan`, `nikto`, `sqlmap`, `whois`, `golang`, `python3`.
- **Go tools**: `subfinder`, `amass`, `httpx`, `dnsx`, `katana`, `naabu`, `nuclei`, `ffuf`, `dalfox`, `gau`, `anew`, `waybackurls`, `qsreplace`, `chaos-client`.
- **Python libraries**: `wafw00f`, `dirsearch`, `sslyze`, `arjun`.
- **Templates**: Initializes and updates Nuclei vulnerability templates.
- **Global Path**: Creates symlink for global CLI execution (`reconx`).

### Updating to Latest Build (`-u` / `-U` / `--update`)

To update ReconX to the latest build without losing your custom configurations:
```bash
./install.sh -u
```
You can choose between:
- **Automatic**: Checks remote git branch, pulls latest changes, syncs files to `~/.reconx`, and updates Nuclei templates.
- **Manual**: Provides exact git commands to manually review and pull updates.


---

## 🔑 API Keys & OSINT Configuration

ReconX is designed to be **100% functional without API keys** by aggregating public certificate transparency logs and free OSINT databases. Adding free API keys unlocks elevated rate limits and enriched intelligence datasets.

### Supported API Services

| Service | Free Tier Allowance | Primary Use Case | Registration Link |
|:---|:---|:---|:---|
| **BeVigil OSINT** | 50 requests/day | Mobile package & deep endpoint subdomains | [osint.bevigil.com](https://osint.bevigil.com/) |
| **AlienVault OTX** | High rate limits | Historical passive DNS records | [otx.alienvault.com](https://otx.alienvault.com/) |
| **Chaos (ProjectDiscovery)** | Free access | Bug bounty program subdomain datasets | [cloud.projectdiscovery.io](https://cloud.projectdiscovery.io/) |
| **Shodan** | 100 queries/month | Exposed services, banners & open ports | [account.shodan.io](https://account.shodan.io/) |
| **VirusTotal** | 4 requests/minute | Passive DNS & domain threat reputation | [virustotal.com](https://www.virustotal.com/) |
| **WPScan** | 25 requests/day | WordPress core, plugin & theme CVEs | [wpscan.com/register](https://wpscan.com/register) |

> ℹ️ **Note on Legacy Services:** SecurityTrails and Censys have restricted or deprecated direct API keys on standard free community tiers. ReconX automatically replaces them with BeVigil, AlienVault OTX, crt.sh, and Subdomain Center.

### Configuring & Validating Keys

```bash
# Option 1: Interactive Wizard
./reconx.sh --config-wizard

# Option 2: Edit Configuration Directly
nano config/tools.conf

# Validate Configured API Keys Live
./reconx.sh --validate-keys
```

---

## 🚀 Quick Start

```bash
# Standard Scan (Normal Intensity)
./reconx.sh -t example.com

# Target alias (-d or -t) with specific modules
./reconx.sh -d example.com --passive --dns -r 2

# Full Attack Surface Scan with Dark-Mode HTML Report
./reconx.sh -t example.com --full --report --export html,md,json,csv
```

---

## 🛡️ OPSEC & Bug Bounty Mode

ReconX includes dedicated OPSEC features to keep your reconnaissance safe, compliant, and undetectable:

- **Bug Bounty Mode (`--bb` / `--bugbounty`)**: Automatically enforces polite Nmap scan timings (`T2`), throttles HTTP request rates, and limits port probes to standard authorized web ports.
- **Out-of-Scope Target Exclusion (`--exclude`)**: Exclude specific hostnames, IPs, or CIDRs to avoid out-of-scope violations.
- **Custom Tracking Headers (`-H` / `--header`)**: Injects identification headers (e.g., `-H "X-HackerOne-Researcher: user"`) across HTTPX, FFUF, and Nuclei.
- **Proxy Routing (`--proxy`)**: Routes all web traffic through an upstream HTTP or SOCKS5 proxy (e.g., Burp Suite or Tor).

---

## 📊 Reporting & Dashboard

ReconX generates actionable reports in `output/<target>/reports/`:

- **Interactive HTML Dashboard** (`report_<timestamp>.html`): Dark-mode executive layout with real-time keyword search for discovered vulnerabilities, open ports, and subdomains.
- **Structured JSON** (`report_<timestamp>.json` / `consolidated.json`): Comprehensive findings for SIEM/pipeline integration.
- **Spreadsheet CSVs** (`subdomains.csv`, `ports.csv`, `vulnerabilities.csv`): Ready for spreadsheet analysis.
- **Markdown Document** (`report_<timestamp>.md`): Formatted for GitHub issues or penetration test reports.

---

## 🔧 Command Reference

```bash
Usage:
  ./reconx.sh [OPTIONS]

Target Options:
  -t, -d, --target, --domain <domain>   Target domain to assess
  --exclude <list/file>                 Exclude out-of-scope subdomains or IPs

Scan Options & Controls:
  -w, --wordlist <file>                 Custom wordlist for DNS & web fuzzing
  -o, --output <dir>                    Custom output directory (Default: output/)
  --threads <num>                       Set worker threads count
  --rate-limit <rps>                    Set global request rate limit (req/sec)

Scan Modules:
  --passive                             Run passive OSINT & subdomain gathering
  --dns                                 Run DNS enumeration & zone transfer checks
  --active                              Run active port and service discovery
  --web                                 Run web discovery & directory fuzzing
  --enum                                Run service and CMS enumeration
  --vuln                                Run vulnerability assessment (Nuclei v3)
  --full                                Run all modules sequentially

Scan Intensity:
  -r, --robustness <1-5>                Scan intensity level (Default: 3)

OPSEC & Network:
  --bb, --bugbounty                     Safe mode with rate-limiting & polite timing
  --proxy <url>                         Route traffic through HTTP/SOCKS5 proxy
  -H, --header <string>                 Add custom header across HTTP tools
  --resume                              Resume an interrupted scan session

Reporting:
  --report                              Generate assessment report
  --export <formats>                    Export format: md, html, json, csv, pdf, all
                                        (Supports comma-separated: html,json,csv)

Utilities:
  -i, --interactive                     Launch interactive terminal menu
  --validate-keys                       Validate configured API keys live
  --config-wizard                       Run guided API setup wizard
  --debug                               Enable verbose debug logging
  -v, --version                         Show ReconX version
  -h, --help                            Display help menu
```

---

## 🛠️ Troubleshooting

### API Validation Warnings
Run `./reconx.sh --validate-keys` to inspect endpoint responses. If unconfigured, ReconX will automatically fallback to free zero-key OSINT engines.

### Non-Root Permission Notes
Running without `sudo` is supported. If running without raw socket privileges, ReconX will automatically swap raw `masscan` sweeps with multi-threaded `rustscan` or `nmap` connects.

---

## ⚠️ Disclaimer

This tool is designed for **authorized penetration testing and legal security research only**. Always obtain written permission prior to scanning target infrastructure.

---

<div align="center">
  <sub>Maintained with ❤️ by the Security Community</sub>
</div>