# Threat Intel Toolkit

A command-line tool for querying threat intelligence APIs to support security investigations and incident response.

Currently supported: **AbuseIPDB** (IP reputation lookup)

---

## What It Does

Looks up an IP address against AbuseIPDB's crowdsourced abuse database and returns a formatted report with:

- Abuse confidence score (0–100)
- Total number of community reports
- Country, ISP, and usage type
- Date last reported
- A MALICIOUS / CLEAN verdict

API keys are resolved securely — macOS Keychain is preferred, with a `.env` file as fallback. The key is never hardcoded or committed to source control.

---

## Requirements

- Python 3.11+
- macOS (for Keychain integration) or any OS using the `.env` fallback
- An [AbuseIPDB](https://www.abuseipdb.com) API key — free tier includes 1,000 checks/day

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/threat-intel-toolkit.git
cd threat-intel-toolkit
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

---

## API Key Setup

**Option 1 — macOS Keychain (recommended)**

The key is stored encrypted by the OS and never written to disk as plaintext:

```bash
security add-generic-password -s abuseipdb -a api_key -w YOUR_KEY_HERE
```

**Option 2 — `.env` file (fallback)**

Create a `.env` file in the project root. It is excluded from git via `.gitignore`:

```bash
echo 'ABUSEIPDB_API_KEY=your_key_here' > .env
```

> Never commit your API key to source control. The tool will tell you exactly what to do if no key is found.

---

## Usage

```bash
python lookup.py <ip_address>
```

**Example:**

```bash
python lookup.py 185.220.101.45
```

---

## Example Output

```
Looking up 185.220.101.45...

==================================================
  IP REPUTATION REPORT
==================================================
  IP Address    : 185.220.101.45
  Country       : DE
  ISP           : Franken-Backbone by Michael Bredel
  Usage Type    : Data Center/Web Hosting/Transit
  Abuse Score   : 100/100
  Total Reports : 4321
  Last Reported : 2025-05-09T22:14:00+00:00
--------------------------------------------------
  Verdict       : MALICIOUS
==================================================
```

---

## Security Design Decisions

| Decision | Why |
|---|---|
| Keychain over `.env` | API key is never written to disk as plaintext |
| HTTPS enforced | Prevents key from being sent in plaintext over the network |
| Request timeout set | Prevents hung script in automated IR workflows |
| Exit codes on failure | SOAR playbooks and shell pipelines rely on exit codes |
| No key fragments in error output | Prevents accidental secret leakage in logs |

---

## Roadmap

- [x] AbuseIPDB IP reputation lookup
- [ ] Batch IP lookup from a file
- [ ] VirusTotal domain and URL lookup
- [ ] Shodan host enrichment
- [ ] JSON output flag for SIEM/SOAR integration

---

## License

MIT
