# Auto-Recon-Pipeline-Learn-Python

Security Recon Pipeline built upon Python | Subfinder | HTTPX | Nmap | JSON Report

> **Auto-Recon (v2.1)** — advanced + extremely fast recon with v1/v2 APIs  
> Run: `python -m auto_recon <domain> --fast`

## Structure

```text
auto_recon/
├── cli.py / config.py
├── core/          # UI, tools, DNS, cache
├── v1/            # recon pipeline → report.json
└── v2/            # inventory, diff, scoring, dashboard, CSV, alerts
```

## v2.1 upgrades

| Feature | Why it matters |
|---------|----------------|
| **Subfinder cache** (30m TTL) | Re-runs finish in seconds |
| **Port profiles** | `quick` / `web` / `db` / `admin` / `full` |
| **Skip flags** | `--skip-subfinder` / `--skip-httpx` / `--skip-nmap` |
| **HTML dashboard** | `dashboard.html` insight view |
| **CSV export** | `assets.csv` for sheets / tooling |
| **Faster defaults** | snappier balanced + aggressive `--fast` |

## Usage

```powershell
# Extreme speed (labs)
python -m auto_recon example.com --fast --limit 30

# Cached re-run (usually much faster)
python -m auto_recon example.com --fast --limit 30

# Force fresh Subfinder
python -m auto_recon example.com --fast --refresh

# Port profiles
python -m auto_recon example.com --fast --ports-profile quick
python -m auto_recon example.com --deep --ports-profile full

# Skip stages
python -m auto_recon example.com --fast --skip-subfinder --ports-profile web
```

### Alerts (optional)

```powershell
$env:AUTO_RECON_SLACK_WEBHOOK = "https://hooks.slack.com/services/..."
$env:AUTO_RECON_TEAMS_WEBHOOK = "https://outlook.office.com/webhook/..."
python -m auto_recon example.com --fast
```

## Output

```text
recon_output/<target>/
  report.json
  inventory.json
  changes.json / changes.md
  dashboard.html
  assets.csv
  history/
  .cache/subdomains.json
```

## Disclaimer

Authorized testing only. Scan only domains you own or have written permission to test.
