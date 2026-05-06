# ReconX

> Web & API recon framework for pentesters and bug bounty hunters.  
> Seven-phase automated pipeline — subdomain enumeration through content discovery — in a single command.

```
  ____                     __  __
 |  _ \ ___  ___ ___  _ __ \ \/ /
 | |_) / _ \/ __/ _ \| '_ \ \  /
 |  _ <  __/ (_| (_) | | | | /  \
 |_| \_\___|\___\___/|_| |_|/_/\_\
```

---

## Features

| Phase | Module | What it does |
|-------|--------|--------------|
| 01 | Subdomain Enumeration | crt.sh CT logs + DNS brute force + external tools (subfinder, findomain, assetfinder) |
| 02 | DNS Resolution | Resolves all subdomains to IPs, drops dead hosts |
| 03 | Port Scanning | Socket-based scan of 20 common web/API ports |
| 04 | HTTP Fingerprinting | Server, WAF, tech stack, missing security headers, cookies |
| 05 | API Endpoint Discovery | Swagger/OpenAPI hunting + JS file extraction + path fuzzing |
| 06 | GraphQL Detection | Introspection probe across 7 common GraphQL paths |
| 07 | Content Discovery | robots.txt, sensitive paths (`/.env`, `/.git/config`, `/actuator`…), `.well-known` |

**Additional:**
- Non-web hosts (SMTP, MX, NS) automatically skipped after port scan — no timeout storms
- Rich progress bars with ETA on every long operation
- Graceful Ctrl+C — partial results shown and JSON saved if `--output` was set
- `--max-subdomains` cap prevents DNS phase from hanging on 10k+ results
- Full JSON export with `--output`

---

## Installation

Clone and run the installer — it handles everything:

```bash
git clone https://github.com/KrItHiCk007/ReconX.git
cd ReconX
chmod +x install.sh && ./install.sh
```

The installer:
1. Verifies Python 3.10+
2. Installs Python dependencies (`httpx`, `dnspython`, `rich`)
3. Installs **subfinder** and **assetfinder** via `go install` (if Go is present)
4. Downloads the **findomain** binary from GitHub releases (Linux x86\_64/arm64, macOS)
5. Prints a tool availability summary

> **Go required** for subfinder and assetfinder. Install from [go.dev/dl](https://go.dev/dl/) then re-run `./install.sh`.

### Manual dependency install (no script)

```bash
pip install -r requirements.txt
```

### What each external tool adds

| Tool | What it adds |
|------|--------------|
| [subfinder](https://github.com/projectdiscovery/subfinder) | Passive OSINT enumeration |
| [findomain](https://github.com/Findomain/Findomain) | CT log aggregation (high volume) |
| [assetfinder](https://github.com/tomnomnom/assetfinder) | Additional passive sources |

All three are **optional** — ReconX runs without them using crt.sh + DNS brute force.

---

## Requirements

| Requirement | Version | Notes |
|-------------|---------|-------|
| Python | 3.10+ | `str \| None` union syntax used |
| httpx[http2] | 0.27.0 | Async HTTP client |
| dnspython | 2.6.1 | DNS resolution |
| rich | 13.7.1 | Terminal output |
| Go | 1.18+ | Only needed for subfinder/assetfinder |

---

## Usage

```
python main.py --target <domain> [options]
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--target` | required | Target domain — `example.com` or `https://example.com` |
| `--threads` | `100` | Concurrency limit for all async operations |
| `--timeout` | `5` | HTTP request timeout in seconds |
| `--no-brute` | off | Skip DNS brute force (faster, less coverage) |
| `--max-subdomains` | `2000` | Cap total subdomains before DNS phase. `0` = unlimited |
| `--output`, `-o` | — | Save full results to a JSON file |
| `--modules` | `all` | Modules to run: `subdomain dns ports http api graphql content` |

### Examples

```bash
# Standard scan
python main.py --target example.com

# Fast — no brute force, higher thread count, save output
python main.py --target example.com --no-brute --threads 200 --output results.json

# Deep — allow more subdomains, longer timeout
python main.py --target example.com --max-subdomains 5000 --timeout 10

# Both URL forms accepted
python main.py --target https://example.com
```

---

## Output

### Live terminal

Findings print as discovered. Status codes are color-coded:

| Color | Code range | Meaning |
|-------|-----------|---------|
| **Bold green** | 2xx | Accessible — potential unauthenticated exposure |
| **Bold yellow** | 3xx | Redirect |
| Dim | 4xx | Blocked but path exists |
| **Bold red** | 5xx | Server error |

### Summary tables

After all phases, ReconX prints:

1. **Live Hosts** — IP, open ports, server, WAF, tech stack, missing security headers count
2. **API Endpoints** — Swagger docs found, JS-extracted paths, fuzzed results, unauthenticated count
3. **GraphQL Findings** — hosts with introspection open, type count
4. **Critical Findings** panel — exposed paths (200), open GraphQL introspection, unauthenticated endpoints
5. **Scan Statistics** — totals and elapsed time

### JSON (`--output results.json`)

```json
{
  "timestamp": "2026-05-06T14:00:00Z",
  "results": {
    "subdomains": ["sub.example.com", "..."],
    "live_hosts": [{"host": "sub.example.com", "ip": "1.2.3.4"}],
    "open_ports": [{"host": "sub.example.com", "ip": "1.2.3.4", "open_ports": [80, 443]}],
    "fingerprints": [{"host": "...", "server": "nginx", "waf": "Cloudflare", "tech_stack": ["WordPress"]}],
    "api_endpoints": {"sub.example.com": {"swagger_docs": [], "js_extracted": [], "fuzzed_endpoints": []}},
    "graphql": [{"host": "...", "detected": true, "introspection_enabled": true}],
    "content": {"sub.example.com": {"robots": {}, "sensitive_paths": [], "well_known": []}}
  }
}
```

---

## Project Structure

```
ReconX/
├── main.py                    # CLI entrypoint
├── config.py                  # Global defaults (version, user-agent, threads)
├── requirements.txt
├── wordlists/
│   ├── subdomains.txt         # DNS brute force wordlist
│   ├── api_paths.txt          # API path fuzzing wordlist
│   └── backup_files.txt       # Backup/sensitive file paths
└── modules/
    ├── subdomain.py           # crt.sh + DNS brute force + external tools
    ├── dns_resolver.py        # Async DNS resolution with semaphore
    ├── port_scanner.py        # Socket-based port scanner (20 ports)
    ├── http_fingerprint.py    # Server / WAF / tech stack detection
    ├── api_discovery.py       # Swagger + JS extraction + path fuzzing
    ├── graphql_probe.py       # GraphQL introspection probe
    ├── content_discovery.py   # robots.txt + sensitive paths + .well-known
    ├── summary.py             # Rich summary tables + JSON export
    └── utils.py               # Shared helpers (status code coloring)
```

---

## Disclaimer

Use only on systems you own or have explicit written permission to test.  
The authors accept no liability for unauthorized use.
