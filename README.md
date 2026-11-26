# Auto-Recon-Pipeline-Learn-Python

Security Recon Pipeline built upon Python | Subfinder | HTTPX | Nmap | JSON Report

> **Auto-Recon (v3.0) — Continuous Exposure Platform**  
> v1 discover → v2 diff/inventory → v3 uptime / health / posture / SLA / executive  
> Lean principle: **only controls that change risk posture**  
> Run: `python -m auto_recon yourdomain.com --fast`

## Structure

```text
auto_recon/
├── core/     # UI, tools, DNS, cache
├── v1/       # Subfinder → HTTPX → Nmap → report.json
├── v2/       # inventory, diff, scoring, dashboard, CSV, alerts
└── v3/       # Continuous Exposure Platform
    ├── uptime / health / posture / risk_score
    ├── tenants / graph / ownership / sla / tickets
    ├── monitor / platform / executive
```

## What each version is for

| Version | Purpose |
|---------|---------|
| **v1** | Discover attack surface now |
| **v2** | Inventory + change since last scan |
| **v3** | Continuous exposure: uptime, broken pages/SEO, login surfaces, hardening signals, exposure risk score, multi-tenant, asset graph, ownership, SLA, tickets, executive dashboard |

**Important:** v3 is **defensive monitoring / posture**. It is **not** a full vuln scanner, malware AV, or “can hack this site” exploit engine. The risk score estimates **exposure / hardening gaps**.

## Usage

```powershell
# Full platform (v1+v2+v3) on YOUR site
python -m auto_recon yourdomain.com --fast --tenant acme --owner "sec-team"

# Continuous uptime watch (1s interval lab; prefer 15–60s in prod)
python -m auto_recon yourdomain.com --fast --watch --watch-interval 1 --watch-ticks 5

# Skip platform pack
python -m auto_recon yourdomain.com --fast --no-platform
```

### Alerts / tickets (optional)

```powershell
$env:AUTO_RECON_SLACK_WEBHOOK = "https://hooks.slack.com/services/..."
$env:AUTO_RECON_TEAMS_WEBHOOK = "https://outlook.office.com/webhook/..."
$env:AUTO_RECON_TICKET_WEBHOOK = "https://your-ticket-ingest.example/hooks"
```

## Output (v3)

```text
recon_output/<target>/
  report.json / inventory.json / changes.* / dashboard.html / assets.csv
  uptime.json / uptime_history.jsonl
  monitor.json / monitor.md
  asset_graph.json
  ownership.json
  sla.json
  tickets.json
  platform.json
  executive.html          ← leadership view
```

## Lean SLA controls (risk posture only)

1. Public availability (uptime)  
2. No high-risk edge ports  
3. Fix broken customer pages  
4. Baseline security headers  

Failed controls → open tickets (file + optional webhook).

## Disclaimer

Authorized testing only. Scan only domains you own or have written permission to test.
