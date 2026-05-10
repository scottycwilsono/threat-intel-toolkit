# Threat Intel Toolkit

A command-line tool and Claude Desktop MCP server for querying threat intelligence APIs to support security investigations and incident response.

Currently supported: **AbuseIPDB** (IP reputation) · **VirusTotal** (multi-engine analysis) · **Shodan** (host enrichment)

---

## What It Does

Looks up an IP address against three independent threat intel sources and returns a combined verdict:

**AbuseIPDB** — crowdsourced abuse database:
- Abuse confidence score (0–100)
- Total community reports
- Country and ISP

**VirusTotal** — ~70+ AV and threat intelligence engines:
- Malicious / suspicious / clean engine counts

**Shodan** — active internet scanner (empirical host data):
- Open ports and running services
- Operating system (if detected)
- Hostnames
- Known vulnerabilities (CVEs)
- Last scan date

**Combined verdict** — MALICIOUS, SUSPICIOUS, or CLEAN, using OR logic across all sources. Any source can escalate the verdict; no single source alone can clear an IP.

API keys are resolved securely — macOS Keychain is preferred, with a `.env` file as fallback. Keys are never hardcoded or committed to source control.

---

## Requirements

- Python 3.11+
- macOS (for Keychain integration) or any OS using the `.env` fallback
- An [AbuseIPDB](https://www.abuseipdb.com) API key — free tier includes 1,000 checks/day
- A [VirusTotal](https://www.virustotal.com) API key — free tier includes 4 requests/minute
- A [Shodan](https://www.shodan.io) API key — free tier includes basic host lookups

---

## Installation

```bash
git clone https://github.com/scottycwilsono/threat-intel-toolkit.git
cd threat-intel-toolkit
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## API Key Setup

**Option 1 — macOS Keychain (recommended)**

Keys are stored encrypted by the OS and never written to disk as plaintext:

```bash
# AbuseIPDB
security add-generic-password -s abuseipdb -a api_key -w YOUR_ABUSEIPDB_KEY

# VirusTotal
security add-generic-password -s threat-intel-toolkit -a virustotal -w YOUR_VT_KEY

# Shodan
security add-generic-password -s threat-intel-toolkit -a shodan -w YOUR_SHODAN_KEY
```

**Option 2 — `.env` file (fallback)**

Create a `.env` file in the project root. It is excluded from git via `.gitignore`:

```bash
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
VIRUSTOTAL_API_KEY=your_virustotal_key_here
SHODAN_API_KEY=your_shodan_key_here
```

> Never commit your API keys to source control. The tool will tell you exactly what to do if a key is missing.

---

## Usage

### CLI

```bash
python lookup.py --ip <ip_address>
```

**Example:**

```bash
python lookup.py --ip 185.220.101.45
```

### Claude Desktop (MCP)

Once configured (see below), just ask Claude in plain English:

> "Check 185.220.101.45 for threat intel"
> "Quick abuse check on 1.2.3.4"

Claude will call `check_ip` or `check_ip_quick` automatically and return the results inline.

---

## Claude Desktop Setup

`mcp_server.py` exposes the toolkit as an MCP server so Claude Desktop can call your lookup functions as tools.

**1. Find your venv Python path** (with venv activated):

```bash
which python3
```

**2. Edit the Claude Desktop config:**

```bash
vim ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

Add the `mcpServers` block alongside any existing keys:

```json
{
  "mcpServers": {
    "threat-intel-toolkit": {
      "command": "/path/to/your/venv/bin/python3",
      "args": ["/path/to/threat-intel-toolkit/mcp_server.py"]
    }
  }
}
```

**3. Validate the JSON:**

```bash
python3 -m json.tool ~/Library/Application\ Support/Claude/claude_desktop_config.json
```

**4. Restart Claude Desktop.**

The server will appear as a connector in Claude Desktop. Once connected, just ask Claude in plain English — it will call `check_ip` or `check_ip_quick` automatically.

**Troubleshooting:** If the server doesn't appear, check the logs:

```bash
ls ~/Library/Logs/Claude/
```

Common causes: wrong Python path, JSON syntax error in config, missing `mcp` package in venv.

---

## Example Output

```
Querying AbuseIPDB, VirusTotal, and Shodan for 185.220.101.45...

  IP: 185.220.101.45
  ════════════════════════════════════════════

  ABUSEIPDB
  Score:      100/100
  Reports:    4,321
  Country:    DE
  ISP:        Franken-Backbone by Michael Bredel

  VIRUSTOTAL
  Malicious:  18/94 engines
  Suspicious: 0/94 engines
  Clean:      71/94 engines

  SHODAN
  Ports:      22, 80, 443
  Services:   OpenSSH, nginx
  OS:         Unknown
  Hostnames:  mail.example.com
  Vulns:      None detected
  Last Seen:  2024-01-14

  OVERALL VERDICT: MALICIOUS ⚠️
  ════════════════════════════════════════════
```

If Shodan has no scan data for an IP:

```
  SHODAN
  No data available
```

---

## Security Design Decisions

| Decision | Why |
|---|---|
| Keychain over `.env` | API key is never written to disk as plaintext |
| HTTPS enforced | Prevents key from being sent in plaintext over the network |
| Shodan key in query param | Shodan's API design — noted in code; TLS still encrypts it in transit |
| Request timeout set | Prevents hung script in automated IR workflows |
| Exit codes on failure | SOAR playbooks and shell pipelines rely on exit codes |
| No key fragments in error output | Prevents accidental secret leakage in logs |
| Shodan 404 = no data, not failure | Absence of scan data is informative, not an error |

---

## Roadmap

- [x] AbuseIPDB IP reputation lookup
- [x] VirusTotal multi-engine IP analysis
- [x] Shodan host enrichment
- [x] Claude Desktop MCP server integration
- [ ] Batch IP lookup from a file
- [ ] JSON output flag for SIEM/SOAR integration

---

## License

MIT
