# Auto-Recon-Pipeline-Learn-Python

Security Recon Pipeline built upon Python | Subfinder | HTTPX | Nmap | JSON Report

> **Auto-Recon (v1)** — subdomain enum → HTTP probe → port scan → one structured `report.json`
> Built and tested on **Windows 11**. Future iterations: **v2, v3, …**

![Platform](https://img.shields.io/badge/platform-Windows%2011-blue)
![Language](https://img.shields.io/badge/language-Python-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

## What it does

| Phase | Tool | Role |
|-------|------|------|
| 1 | **Subfinder** | Passive subdomain enumeration (public sources / CT logs) |
| 2 | **HTTPX** | Live-host detection + status / title / tech fingerprint |
| 3 | **Nmap** | Port & service version scan on resolved IPs |
| 4 | **Python** | Merge everything into `recon_output/<target>/report.json` |

## Prerequisites

- Python 3.9+
- [Go](https://go.dev/dl/) (for ProjectDiscovery tools; binaries land in `%USERPROFILE%\go\bin`)
- [Nmap](https://nmap.org/download.html) with **Npcap** (WinPcap API-compatible mode)
- Git (optional, for version control)

Install ProjectDiscovery CLIs:

```powershell
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

Verify:

```powershell
subfinder -version
httpx -version
nmap --version
python --version
```

## Usage

Prefer an **Administrator** PowerShell so Nmap / Npcap behave correctly:

```powershell
cd "E:\Projects\Personal Projects\Auto-Recon-Pipeline-Learn-Python"
python recon.py example.com
# optional: cap noisy CT-log results (default is 100)
python recon.py example.com --limit 50
```

Only scan domains you **own** or have **written authorization** to test.

## Output layout

```text
recon_output/<target>/
  subdomains.txt   # Subfinder list
  httpx.jsonl      # Raw HTTPX JSONL
  nmap.xml         # Raw Nmap XML
  report.json      # Merged v1 report
```

## Theory (why this chain)

1. **Subfinder first** — passive discovery; low noise before any active probing.
2. **HTTPX next** — prove which names actually speak HTTP(S) and capture tech hints.
3. **Resolve → Nmap** — scan IPs of live hosts only; `-oX` XML is easy to parse into JSON.
4. **One report** — later versions (v2+) can add dirs, screenshots, diffing, etc. without changing the core idea.

## Roadmap

- **v1** (this repo): Subfinder → HTTPX → Nmap → JSON
- **v2** (planned): richer HTTPX fields, optional full-port profiles, better error recovery
- **v3** (planned): multi-target / wordlist modes, HTML summary, CI-friendly flags

## Disclaimer

This tool is intended for **authorized security testing only**. Only scan domains you own or have explicit written permission to test. Unauthorized scanning may violate laws such as the CFAA (US) or Computer Misuse Act (UK). The author assumes no liability for misuse.

