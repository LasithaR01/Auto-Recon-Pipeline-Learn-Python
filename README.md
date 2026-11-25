# Auto-Recon-Pipeline-Learn-Python

Security Recon Pipeline built upon Python | Subfinder | HTTPX | Nmap | JSON Report

> **Auto-Recon (v1.2)** — subdomain enum → HTTP probe → port scan → `report.json`  
> Run: `python -m auto_recon` · Speed modes: `--fast` / default / `--deep`

![Platform](https://img.shields.io/badge/platform-Windows%2011-blue)
![Language](https://img.shields.io/badge/language-Python-green)
![License](https://img.shields.io/badge/license-MIT-lightgrey)

## Project structure

```text
Auto-Recon-Pipeline-Learn-Python/
├── README.md
├── .gitignore
├── auto_recon/
│   ├── __init__.py
│   ├── __main__.py          # python -m auto_recon
│   ├── config.py            # Speed profiles (fast / balanced / deep)
│   ├── env.py
│   ├── ui.py
│   ├── tools.py
│   ├── dnsutil.py           # Reuse HTTPX IPs + parallel DNS fallback
│   ├── phases.py
│   ├── report.py
│   └── cli.py
└── recon_output/            # Created at runtime (gitignored)
```

## Speed modes (v1.2)

| Mode | Flag | What changes |
|------|------|----------------|
| **fast** | `--fast` | Max threads, short timeouts, skip tech-detect & Nmap `-sV` |
| **balanced** | *(default)* | Fast timeouts + light service detect |
| **deep** | `--deep` | Richer fingerprints, slower / more accurate |

Other speed wins (always on):
- HTTPX `-ip` → reuse IPs, **skip redundant DNS** when possible
- Parallel DNS only for hosts still missing an IP
- Nmap `-n` (no DNS), `--min-rate`, capped retries
- `--limit` (default 100) avoids huge CT-log floods

## Usage

```powershell
cd "E:\Projects\Personal Projects\Auto-Recon-Pipeline-Learn-Python"

# Extreme speed (recommended for quick labs)
python -m auto_recon example.com --fast --limit 30

# Default balanced
python -m auto_recon example.com --limit 50

# Thorough fingerprints
python -m auto_recon example.com --deep --limit 50

python -m auto_recon example.com --fast --verbose
python -m auto_recon example.com --fast --quiet
```

Prefer **Administrator** PowerShell for Nmap/Npcap.  
Only scan domains you **own** or have **written authorization** to test.

## Prerequisites

- Python 3.9+ (stdlib only)
- Go + ProjectDiscovery tools in `%USERPROFILE%\go\bin`
- Nmap with Npcap

```powershell
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

## Output

```text
recon_output/<target>/
  subdomains.txt
  httpx.jsonl
  nmap.xml
  report.json
```

## Roadmap

- **v1.1** — professional CLI + modular package
- **v1.2** — speed profiles (`--fast` / `--deep`), IP reuse, faster tool flags
- **v2** — caching / resume, port profiles
- **v3** — multi-target, HTML summary

## Disclaimer

This tool is intended for **authorized security testing only**. Only scan domains you own or have explicit written permission to test. Unauthorized scanning may violate laws such as the CFAA (US) or Computer Misuse Act (UK). The author assumes no liability for misuse.
