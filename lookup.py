#!/usr/bin/env python3
# ^ This "shebang" line tells your shell which interpreter to use when you run
#   the script directly (./lookup.py). Without it, the OS doesn't know this is
#   Python. It's a Unix convention, not Python syntax.

"""
lookup.py — Combined threat intelligence lookup: AbuseIPDB + VirusTotal + Shodan.

Usage:
    python lookup.py --ip <ip_address>
    python lookup.py --ip 1.2.3.4

API key resolution order (most secure → least secure):
    1. macOS Keychain  (preferred — never touches disk as plaintext)
    2. .env file       (fallback — kept out of git via .gitignore)

WHAT MAKES SHODAN DIFFERENT FROM ABUSEIPDB AND VIRUSTOTAL:
─────────────────────────────────────────────────────────────────────────────
AbuseIPDB answers: "Has this IP been reported for malicious behavior?"
  → Community-sourced abuse reports. Reactive data. Tells you what happened.

VirusTotal answers: "Do security engines think this IP is malicious?"
  → Engine-consensus scoring. Reputation-based. Tells you what others think.

Shodan answers: "What is this IP actually running RIGHT NOW?"
  → Active scanner. Shodan continuously crawls the internet, connects to
    every routable IP on common ports, and records the raw service banners
    (the text a server sends when you connect). This is empirical, not
    opinion-based — it's a snapshot of what the host advertised to the world.

Key structural difference: Shodan's response is a FLAT dict, not a nested
envelope like VirusTotal's data→attributes chain. The ports list, hostnames,
OS, and service array are all top-level keys. This reflects that Shodan is
returning raw technical facts about a single host, not a multi-source
aggregation that needs metadata layers.

WHY OPEN PORTS AND SERVICES MATTER IN D&R:
─────────────────────────────────────────────────────────────────────────────
When you're investigating an IP that contacted your network, knowing WHAT
that IP is running tells you a lot about its likely purpose:

  • Port 3389 (RDP) open to the internet on a cloud IP:
    Almost certainly a compromised or intentionally exposed machine. RDP
    exposed to the internet is one of the top initial access vectors for
    ransomware. Seeing this on an IP that contacted your network is a red flag.

  • Port 8443/8080 with no registered product:
    Could be C2 malware using a non-standard port to blend in. Legitimate
    services don't usually run on these ports without a reason.

  • CVE entries in vulns field:
    Shodan records CVEs when its banner-grabbing identifies a service version
    with known vulnerabilities. An IP running unpatched software and contacting
    your network is either a compromised machine (used as a pivot point) or
    a deliberate attacker who hasn't maintained their infrastructure.

The combination of AbuseIPDB reputation + VirusTotal engine consensus +
Shodan active scan gives you the full picture:
  - Did it behave badly? (AbuseIPDB)
  - Do tools agree it's bad? (VirusTotal)
  - What is it, technically? (Shodan)
"""

# ── Standard library imports ──────────────────────────────────────────────────
# These come bundled with Python — no installation needed.

import sys
# sys gives us access to the program's environment: command-line arguments,
# the ability to exit with a status code, and standard streams (stdin/stdout).
# SECURITY: sys.exit(1) signals failure to the shell. Automated pipelines
# (SOAR playbooks, cron jobs) rely on exit codes to know if a tool succeeded.

import subprocess
# subprocess lets us run external shell commands from Python.
# We use it to call macOS's built-in `security` command to read from Keychain.
# SECURITY: This avoids storing the API key in a Python variable loaded from a
# file on disk. The key lives encrypted in Keychain and is only fetched at
# runtime.

import argparse
# argparse is Python's standard library for parsing command-line arguments.
# It gives us --help for free and validates that required args are provided.
# Prefer argparse over manually reading sys.argv[1] — it's more robust and
# gives users clear error messages when they misuse the tool.

import os
# os gives us access to environment variables (os.environ).
# We use it to read API keys from the shell environment, which can be
# populated by python-dotenv reading a .env file.

# ── Third-party imports ───────────────────────────────────────────────────────
# These must be installed via: pip install -r requirements.txt

import requests
# requests is the standard Python library for making HTTP calls.
# It handles the low-level TCP/SSL work so we can focus on the API logic.
# SECURITY: We always set a timeout= on every request. Without a timeout, a
# slow or unresponsive server can hang your script indefinitely — a problem
# in automated pipelines.

from dotenv import load_dotenv
# python-dotenv reads a .env file and loads its key=value pairs into
# os.environ, making them available to our script as environment variables.
# SECURITY: .env is in .gitignore, so it never gets committed to git.
# This is the standard pattern for keeping secrets out of source control.

# ── Load .env file (if present) ───────────────────────────────────────────────
# This must happen BEFORE we try to read os.environ for any API key.
# If no .env file exists, load_dotenv() silently does nothing — no error.
# SECURITY: load_dotenv() only sets a variable if it isn't already set in the
# environment. Real environment variables (set in your shell) always win.
# This prevents a malicious .env file from overwriting shell-level secrets.
load_dotenv()

# ── AbuseIPDB Constants ────────────────────────────────────────────────────────
# Define fixed values once at the top. If AbuseIPDB changes their URL or you
# want to adjust a threshold, you change it in one place — not scattered
# throughout the code.

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
# The AbuseIPDB v2 "check" endpoint. This is what we GET to look up an IP.
# SECURITY: We hardcode HTTPS — never HTTP. HTTP sends your API key in
# plaintext over the network. requests enforces TLS by default when the URL
# starts with https://.

ABUSEIPDB_KEYCHAIN_SERVICE = "abuseipdb"
# The "service" label we used when storing the AbuseIPDB key in Keychain.
# Think of it as a folder name inside Keychain.

ABUSEIPDB_KEYCHAIN_ACCOUNT = "api_key"
# The "account" label — the specific item inside that service folder.

ABUSEIPDB_MALICIOUS_THRESHOLD = 50
# AbuseIPDB score threshold for a MALICIOUS verdict. Score is 0–100.
# SECURITY CONTEXT: In a fintech SOC you might lower this to catch more
# threats at the cost of more false positives. Tune to your risk tolerance.

ABUSEIPDB_SUSPICIOUS_THRESHOLD = 20
# AbuseIPDB score threshold for a SUSPICIOUS verdict (below MALICIOUS).

LOOKBACK_DAYS = 90
# How far back to look for abuse reports. AbuseIPDB max is 365.
# 90 days is a reasonable balance: recent enough to be relevant,
# long enough to catch slow-burn C2 infrastructure.

# ── VirusTotal Constants ───────────────────────────────────────────────────────
# API DESIGN NOTE: VirusTotal v3 puts the resource (the IP) in the URL path:
#   GET /api/v3/ip_addresses/1.2.3.4
# AbuseIPDB puts it in query parameters:
#   GET /api/v2/check?ipAddress=1.2.3.4
#
# The path-based style is more "RESTful" — the URL itself identifies the
# resource you're requesting. Query params are typically for filtering or
# options, not the primary resource identifier.

VIRUSTOTAL_URL = "https://www.virustotal.com/api/v3/ip_addresses"
# Base URL. We append /{ip_address} to it at query time.

VT_KEYCHAIN_SERVICE = "threat-intel-toolkit"
# Per the requirements: security add-generic-password -s threat-intel-toolkit
# -a virustotal -w YOUR_KEY

VT_KEYCHAIN_ACCOUNT = "virustotal"

VT_MALICIOUS_THRESHOLD = 5
# How many VirusTotal engines must flag an IP as malicious to call it MALICIOUS.
# VirusTotal queries ~70+ engines. A single engine flagging an IP can be a
# false positive (some engines are noisy). 5+ is a more reliable signal.

VT_SUSPICIOUS_THRESHOLD = 1
# Even 1 malicious engine flag is worth surfacing as SUSPICIOUS.

# ── Shodan Constants ───────────────────────────────────────────────────────────
# Shodan's API design is the simplest of the three: the key goes in the query
# string (?key=...) rather than a header. This is less ideal from a security
# standpoint — query strings can appear in server access logs, browser history,
# and proxy logs. Headers are the preferred pattern for secrets in modern APIs.
# That said, Shodan's API is read-only and the key is low-privilege, so the
# practical risk is manageable.

SHODAN_URL = "https://api.shodan.io/shodan/host"
# Base URL. We append /{ip} to it, plus ?key={api_key} as a query parameter.
# SECURITY: Always HTTPS. The key is in the query string (Shodan's design),
# but TLS still encrypts it in transit — it just means the key can appear in
# server-side logs at Shodan's end and potentially in local proxy logs.

SHODAN_KEYCHAIN_SERVICE = "threat-intel-toolkit"
# We reuse the same service label as VirusTotal — both keys live under
# "threat-intel-toolkit" but with different account labels. This groups all
# toolkit secrets together in Keychain, making them easy to find.

SHODAN_KEYCHAIN_ACCOUNT = "shodan"
# The -a label used when storing the key:
#   security add-generic-password -s threat-intel-toolkit -a shodan -w YOUR_KEY

REQUEST_TIMEOUT_SECONDS = 10
# Maximum seconds to wait for any API to respond.
# SECURITY: Without this, a network issue or slow API could block your script
# forever. In incident response, a hung tool can be worse than a failed one.


# ── Keychain Retrieval (Generic) ───────────────────────────────────────────────
# We generalized this function to accept any service/account combination.
# This lets AbuseIPDB, VirusTotal, and Shodan share the same Keychain logic
# without duplicating code — the DRY principle (Don't Repeat Yourself).

def get_key_from_keychain(service, account):
    """
    Try to retrieve an API key from macOS Keychain.

    Args:
        service: The -s label used when the key was stored (e.g., "abuseipdb")
        account: The -a label used when the key was stored (e.g., "api_key")

    Returns the key as a string, or None if not found.
    """
    try:
        result = subprocess.run(
            # We call the macOS `security` CLI tool — it ships with every Mac.
            # -s = service name, -a = account name, -w = output just the password
            ["security", "find-generic-password",
             "-s", service,
             "-a", account,
             "-w"],

            capture_output=True,
            # capture_output=True means we capture stdout and stderr into
            # result.stdout / result.stderr instead of printing them.
            # Without this, Keychain's output would print to your terminal
            # and mix with our report.

            text=True,
            # text=True decodes the bytes output to a Python string automatically.
            # Without it, result.stdout would be raw bytes (b"abc\n") not "abc\n".

            check=True,
            # check=True raises a CalledProcessError if the command exits
            # with a non-zero status (i.e., if the key isn't found in Keychain).
            # This lets us handle the failure in the except block below.
        )
        return result.stdout.strip()
        # .strip() removes the trailing newline that `security -w` appends.
        # Without it, the API key would have a \n at the end, causing auth failures.

    except subprocess.CalledProcessError:
        # The `security` command returned a non-zero exit code — meaning the
        # key wasn't found in Keychain. This is expected when a user hasn't
        # set it up yet. We return None so the caller can try the .env fallback.
        return None

    except FileNotFoundError:
        # The `security` binary doesn't exist — this would happen if someone
        # runs this script on Linux or Windows. Fail gracefully.
        return None


# ── API Key Resolution ─────────────────────────────────────────────────────────
# Each function tries Keychain first, then falls back to the .env file.
# This pattern means we never have to store keys in plaintext if we don't
# want to — Keychain is always the preferred path.

def get_abuseipdb_key():
    """
    Resolve the AbuseIPDB API key using a secure priority order:
      1. macOS Keychain   (most secure — encrypted, never on disk as plaintext)
      2. ABUSEIPDB_API_KEY environment variable / .env file

    Returns the key string, or None if neither source has it.
    """
    key = get_key_from_keychain(ABUSEIPDB_KEYCHAIN_SERVICE, ABUSEIPDB_KEYCHAIN_ACCOUNT)
    if key:
        return key

    key = os.environ.get("ABUSEIPDB_API_KEY")
    if key:
        return key

    return None


def get_virustotal_key():
    """
    Resolve the VirusTotal API key using a secure priority order:
      1. macOS Keychain   (service="threat-intel-toolkit", account="virustotal")
      2. VIRUSTOTAL_API_KEY environment variable / .env file

    Returns the key string, or None if neither source has it.
    """
    key = get_key_from_keychain(VT_KEYCHAIN_SERVICE, VT_KEYCHAIN_ACCOUNT)
    if key:
        return key

    key = os.environ.get("VIRUSTOTAL_API_KEY")
    if key:
        return key

    return None


def get_shodan_key():
    """
    Resolve the Shodan API key using a secure priority order:
      1. macOS Keychain   (service="threat-intel-toolkit", account="shodan")
      2. SHODAN_API_KEY environment variable / .env file

    Returns the key string, or None if neither source has it.
    """
    key = get_key_from_keychain(SHODAN_KEYCHAIN_SERVICE, SHODAN_KEYCHAIN_ACCOUNT)
    if key:
        return key

    key = os.environ.get("SHODAN_API_KEY")
    if key:
        return key

    return None


# ── AbuseIPDB API Query ───────────────────────────────────────────────────────

def query_abuseipdb(ip_address, api_key):
    """
    Send a GET request to the AbuseIPDB v2 check endpoint.

    Returns the parsed JSON response as a Python dictionary.
    Raises requests exceptions on network or HTTP errors.

    API DESIGN: AbuseIPDB authenticates via a custom "Key" header and
    passes the IP as a query parameter (?ipAddress=...).
    """
    headers = {
        "Key": api_key,
        # AbuseIPDB uses a custom "Key" header for authentication — not the
        # more common "Authorization: Bearer <token>" pattern. This is specific
        # to their API; always read the API docs for the exact auth format.
        # SECURITY: Headers are sent over TLS (encrypted in transit). They are
        # NOT visible to network observers, but they ARE visible in server logs.
        # Never log the full headers dict in production — you'd log the API key.

        "Accept": "application/json",
        # Tell the server we want JSON back, not XML or HTML.
        # This is called "content negotiation" — good APIs can return multiple
        # formats and this header picks which one you want.
    }

    params = {
        "ipAddress": ip_address,
        # The IP we're looking up. requests will URL-encode this automatically
        # and append it as a query string: ?ipAddress=1.2.3.4&maxAgeInDays=90

        "maxAgeInDays": LOOKBACK_DAYS,
        # Only return reports from the last N days.
    }

    response = requests.get(
        ABUSEIPDB_URL,
        headers=headers,
        params=params,
        timeout=REQUEST_TIMEOUT_SECONDS,
        # SECURITY: Always set a timeout. 10 seconds is generous for a simple
        # lookup. In automated IR workflows, you don't want one slow API call
        # blocking your entire playbook.
    )

    response.raise_for_status()
    # If the HTTP status code is 4xx (client error) or 5xx (server error),
    # this raises an HTTPError exception with the status code and reason.
    # Examples:
    #   401 Unauthorized → your API key is wrong
    #   422 Unprocessable Entity → the IP address format is invalid
    #   429 Too Many Requests → you've hit the rate limit
    # Without this line, a failed request would silently return garbled data.

    return response.json()
    # Parse the response body as JSON and return it as a Python dict.
    # requests does this automatically — no need to import json or call
    # json.loads() manually.


# ── VirusTotal API Query ───────────────────────────────────────────────────────

def query_virustotal(ip_address, api_key):
    """
    Send a GET request to the VirusTotal v3 IP address endpoint.

    Returns the parsed JSON response as a Python dictionary.
    Raises requests exceptions on network or HTTP errors.

    API DESIGN DIFFERENCES FROM ABUSEIPDB:
    ┌─────────────────┬──────────────────────────────┬──────────────────────────┐
    │                 │ AbuseIPDB                    │ VirusTotal               │
    ├─────────────────┼──────────────────────────────┼──────────────────────────┤
    │ IP location     │ Query param: ?ipAddress=...  │ URL path: /ip_addresses/ │
    │ Auth header     │ Key: <token>                 │ x-apikey: <token>        │
    │ Data location   │ response["data"]             │ response["data"]         │
    │                 │                              │          ["attributes"]  │
    │ Score type      │ Single 0–100 score           │ Per-engine verdict counts│
    │ Data source     │ Community abuse reports      │ ~70+ AV/threat engines   │
    └─────────────────┴──────────────────────────────┴──────────────────────────┘

    The path-based URL style (/ip_addresses/1.2.3.4) is called "resource
    identification in the path" — a REST design pattern where the URL itself
    is the address of the specific thing you're requesting.
    """
    headers = {
        "x-apikey": api_key,
        # VirusTotal v3 uses the "x-apikey" header (lowercase, with a dash).
        # The "x-" prefix is a convention for custom/non-standard HTTP headers.
        # SECURITY: Same TLS protection applies — encrypted in transit, but
        # visible in server logs. Never log this header.

        "Accept": "application/json",
    }

    # VirusTotal puts the IP in the URL path, not in query parameters.
    # We build the full URL by joining the base URL and the IP with a slash.
    # Example: https://www.virustotal.com/api/v3/ip_addresses/1.2.3.4
    url = f"{VIRUSTOTAL_URL}/{ip_address}"

    response = requests.get(
        url,
        headers=headers,
        timeout=REQUEST_TIMEOUT_SECONDS,
        # No params= argument needed — the IP is already in the URL path above.
    )

    response.raise_for_status()
    # Same pattern as AbuseIPDB: raises HTTPError on 4xx/5xx responses.
    # VirusTotal-specific codes to know:
    #   401 → invalid API key
    #   400 → malformed IP address
    #   404 → IP not in VirusTotal's database (rarely seen for public IPs)
    #   429 → rate limit exceeded (free tier: 4 requests/minute)

    return response.json()


# ── Shodan API Query ───────────────────────────────────────────────────────────

def query_shodan(ip_address, api_key):
    """
    Send a GET request to the Shodan host endpoint for the given IP.

    Returns the parsed JSON response as a Python dict, or None if Shodan
    has no scan data for this IP (HTTP 404).

    Raises requests exceptions on network or other HTTP errors.

    API DESIGN DIFFERENCES FROM ABUSEIPDB AND VIRUSTOTAL:
    ┌─────────────────┬─────────────────────────────────────────────────────────┐
    │ Auth method     │ Query parameter: ?key=...  (not a header)               │
    │ IP location     │ URL path: /shodan/host/{ip}                             │
    │ Response shape  │ Flat dict — no data→attributes nesting                  │
    │ No-data case    │ HTTP 404 (not an error — just means no scan data)       │
    │ Data source     │ Active internet scanner — empirical, not reputation     │
    └─────────────────┴─────────────────────────────────────────────────────────┘

    The flat response shape is intentional: Shodan returns raw technical facts
    about one specific host. There's no aggregation layer, so no envelope is
    needed. You access ports, hostnames, OS, and vulns directly as top-level
    keys.

    WHY 404 IS NOT AN ERROR HERE:
    Most APIs return 404 to mean "you requested something that doesn't exist"
    in an error sense. Shodan uses it to mean "we haven't scanned this IP" or
    "this IP returned no open ports." This is legitimate data — it means the
    host is either offline, firewalled, or simply hasn't been crawled yet.
    We return None so the caller can display "No data available" rather than
    treating it as a tool failure.
    """
    url = f"{SHODAN_URL}/{ip_address}"
    # Example: https://api.shodan.io/shodan/host/1.2.3.4

    params = {
        "key": api_key,
        # Shodan passes the API key as a query parameter, not a header.
        # SECURITY: requests will append this as ?key=YOUR_KEY_HERE in the URL.
        # While TLS encrypts this in transit, query parameters can appear in:
        #   - Shodan's own server access logs
        #   - Your local proxy or debugging tool logs (e.g., Charles, mitmproxy)
        #   - Shell history if you ever construct the curl equivalent manually
        # The header-based pattern used by AbuseIPDB and VirusTotal is safer.
        # Shodan's design is a legacy choice; we follow their spec, not ours.
    }

    response = requests.get(
        url,
        params=params,
        timeout=REQUEST_TIMEOUT_SECONDS,
    )

    # Shodan 404 = no data for this IP. This is not a tool error — handle
    # it here so the caller gets None instead of an exception to catch.
    if response.status_code == 404:
        return None

    response.raise_for_status()
    # Shodan-specific HTTP codes to know:
    #   401 → invalid or missing API key
    #   403 → your plan doesn't include this feature
    #   429 → rate limit (free tier: 1 request/second)
    #   500 → Shodan internal error (retry once before giving up)

    return response.json()


# ── Verdict Logic ─────────────────────────────────────────────────────────────

def determine_verdict(abuse_score, vt_malicious, shodan_vuln_count=0):
    """
    Compute the overall verdict from all available sources.

    MALICIOUS  : AbuseIPDB score >= 50  OR  VT malicious >= 5 engines
                 OR  Shodan has detected vulnerabilities (vuln count > 0)
    SUSPICIOUS : AbuseIPDB score >= 20  OR  VT malicious >= 1 engine
    CLEAN      : All sources return clean signals

    RATIONALE FOR INCLUDING SHODAN VULNS:
    A host running publicly known, unpatched vulnerabilities contacting your
    network is a red flag regardless of whether it has abuse reports. In fintech
    incident response, an unpatched host is either:
      a) A compromised machine used as an unwitting pivot point, OR
      b) Attacker infrastructure that the operator hasn't maintained

    Either way, it warrants MALICIOUS-level scrutiny, not just SUSPICIOUS.

    Using OR logic means any source can escalate the verdict — but no single
    source alone can clear an IP. That's the conservative, defense-first
    posture you want in a fintech SOC: trust is hard to earn, easy to lose.
    """
    if (abuse_score >= ABUSEIPDB_MALICIOUS_THRESHOLD
            or vt_malicious >= VT_MALICIOUS_THRESHOLD
            or shodan_vuln_count > 0):
        return "MALICIOUS"

    if abuse_score >= ABUSEIPDB_SUSPICIOUS_THRESHOLD or vt_malicious >= VT_SUSPICIOUS_THRESHOLD:
        return "SUSPICIOUS"

    return "CLEAN"


# ── Combined Report ───────────────────────────────────────────────────────────

def print_combined_report(ip_address, abuse_data, vt_data, shodan_data):
    """
    Print a formatted combined report from AbuseIPDB, VirusTotal, and Shodan.

    shodan_data is None when Shodan has no record for this IP — we display
    a "No data available" section rather than skipping Shodan entirely.
    Showing the absence of data is itself informative: a brand-new IP with
    no Shodan history might be freshly spun-up attacker infrastructure.
    """
    # ── Pull AbuseIPDB fields ──────────────────────────────────────────────────
    ad = abuse_data["data"]
    # AbuseIPDB wraps all results in a top-level "data" key.
    # Structure: { "data": { "ipAddress": ..., "abuseConfidenceScore": ..., } }

    abuse_score = ad["abuseConfidenceScore"]
    # 0–100 weighted confidence score.

    abuse_reports = ad.get("totalReports", 0)
    abuse_country = ad.get("countryCode") or "Unknown"
    abuse_isp     = ad.get("isp") or "Unknown"

    # ── Pull VirusTotal fields ─────────────────────────────────────────────────
    # VirusTotal v3 nests everything under data → attributes.
    # This extra layer exists because the API uses a JSON:API-style envelope
    # that can carry metadata (type, id, links) alongside the actual content.
    attrs = vt_data["data"]["attributes"]

    stats = attrs.get("last_analysis_stats", {})
    # last_analysis_stats is a dict with these keys:
    #   malicious, suspicious, harmless, undetected, timeout
    # "harmless" = engines that explicitly said it's clean
    # "undetected" = engines that had no opinion (not the same as clean)
    # We only count harmless as "clean" — undetected is neutral, not exculpatory.

    vt_malicious  = stats.get("malicious", 0)
    vt_suspicious = stats.get("suspicious", 0)
    vt_harmless   = stats.get("harmless", 0)
    vt_undetected = stats.get("undetected", 0)
    vt_timeout    = stats.get("timeout", 0)

    # Total engines = all categories summed. This is what "out of N engines" means.
    vt_total = vt_malicious + vt_suspicious + vt_harmless + vt_undetected + vt_timeout

    # ── Pull Shodan fields ─────────────────────────────────────────────────────
    # Shodan's response is a flat dict — no nesting. We use .get() with safe
    # defaults throughout because many fields are optional or absent depending
    # on what the scanner found.
    shodan_vuln_count = 0

    if shodan_data:
        # ports is a list of integers: [22, 80, 443]
        shodan_ports = shodan_data.get("ports", [])

        # hostnames is a list of strings: ["mail.example.com"]
        shodan_hostnames = shodan_data.get("hostnames", [])

        # os may be null even when other data exists — many hosts don't expose
        # their OS via banners. We display "Unknown" rather than None.
        shodan_os = shodan_data.get("os") or "Unknown"

        # last_update is an ISO 8601 datetime string: "2024-01-14T12:34:56.789000"
        # We slice the first 10 characters to get just the date: "2024-01-14"
        last_update_raw = shodan_data.get("last_update") or ""
        shodan_last_seen = last_update_raw[:10] if last_update_raw else "Unknown"

        # vulns is a dict keyed by CVE ID: { "CVE-2023-1234": {...}, ... }
        # We only need the keys (CVE IDs) for display and counting.
        vulns_dict        = shodan_data.get("vulns", {})
        shodan_vuln_count = len(vulns_dict)
        shodan_cves       = sorted(vulns_dict.keys())
        # sorted() puts CVEs in alphabetical order (which sorts chronologically
        # by year since CVE IDs start with the year: CVE-YYYY-NNNNN).

        # Services: extract the `product` field from each entry in the data array.
        # `data` is a list of per-port objects; each has `port`, `transport`,
        # and optionally `product` (the identified service name).
        # We deduplicate with dict.fromkeys() which preserves insertion order
        # (unlike set()) — important for readable output.
        raw_services  = [s.get("product") for s in shodan_data.get("data", []) if s.get("product")]
        shodan_services = list(dict.fromkeys(raw_services))
        # dict.fromkeys() is a Python idiom for deduplication with order preserved.
        # A set would be faster but would scramble the order.

    # ── Determine verdict ─────────────────────────────────────────────────────
    verdict = determine_verdict(abuse_score, vt_malicious, shodan_vuln_count)

    # ── ANSI color codes ──────────────────────────────────────────────────────
    # \033[91m = bright red, \033[93m = yellow, \033[92m = bright green,
    # \033[1m = bold, \033[0m = reset all formatting.
    # SECURITY NOTE: These are display-only. SIEM systems and log files won't
    # render them — always include the text label too, which we do here.
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

    if verdict == "MALICIOUS":
        verdict_color = RED
        verdict_icon  = "⚠️"
    elif verdict == "SUSPICIOUS":
        verdict_color = YELLOW
        verdict_icon  = "⚠️"
    else:
        verdict_color = GREEN
        verdict_icon  = "✓"

    # ── Print the report ──────────────────────────────────────────────────────
    SEP = "═" * 44
    # ═ is Unicode character U+2550 "BOX DRAWINGS DOUBLE HORIZONTAL".
    # It's a cosmetic choice for readability. In a production tool that pipes
    # output to a SIEM or JSON parser, you'd output JSON instead of pretty text.

    print()
    print(f"  IP: {BOLD}{ip_address}{RESET}")
    print(f"  {SEP}")

    print(f"  {BOLD}ABUSEIPDB{RESET}")
    print(f"  Score:      {abuse_score}/100")
    print(f"  Reports:    {abuse_reports:,}")
    # The :, format spec adds thousands separators (4321 → 4,321).
    # Small detail, big readability improvement for high-report IPs.
    print(f"  Country:    {abuse_country}")
    print(f"  ISP:        {abuse_isp}")

    print()
    print(f"  {BOLD}VIRUSTOTAL{RESET}")
    print(f"  Malicious:  {vt_malicious}/{vt_total} engines")
    print(f"  Suspicious: {vt_suspicious}/{vt_total} engines")
    print(f"  Clean:      {vt_harmless}/{vt_total} engines")

    print()
    print(f"  {BOLD}SHODAN{RESET}")

    if not shodan_data:
        # Shodan returned 404 — no scan data for this IP.
        # This is worth showing, not hiding: absence of Shodan data on a
        # suspicious IP could mean it's new infrastructure (freshly deployed).
        print("  No data available")
    else:
        # Ports: join the list of integers into a comma-separated string.
        # Example: [22, 80, 443] → "22, 80, 443"
        ports_str = ", ".join(str(p) for p in sorted(shodan_ports)) or "None detected"
        print(f"  Ports:      {ports_str}")

        # Services: same join pattern.
        services_str = ", ".join(shodan_services) if shodan_services else "None identified"
        print(f"  Services:   {services_str}")

        print(f"  OS:         {shodan_os}")

        # Hostnames: print first one on the same line, subsequent ones indented.
        # This mirrors the example format in the requirements and keeps the
        # report readable even when there are many hostnames.
        if shodan_hostnames:
            first_hostname, *rest_hostnames = shodan_hostnames
            # Tuple unpacking: first_hostname = shodan_hostnames[0],
            # rest_hostnames = shodan_hostnames[1:]. Pythonic and readable.
            print(f"  Hostnames:  {first_hostname}")
            for h in rest_hostnames:
                print(f"              {h}")
        else:
            print("  Hostnames:  None")

        # Vulnerabilities: list CVEs if any, otherwise show "None detected".
        if shodan_cves:
            first_cve, *rest_cves = shodan_cves
            print(f"  Vulns:      {first_cve},") if rest_cves else print(f"  Vulns:      {first_cve}")
            for i, cve in enumerate(rest_cves):
                # Add a comma after each CVE except the last one.
                suffix = "," if i < len(rest_cves) - 1 else ""
                print(f"              {cve}{suffix}")
        else:
            print("  Vulns:      None detected")

        print(f"  Last Seen:  {shodan_last_seen}")

    print()
    print(f"  OVERALL VERDICT: {verdict_color}{BOLD}{verdict} {verdict_icon}{RESET}")
    print(f"  {SEP}")
    print()


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    # argparse builds us a proper CLI with --help and argument validation.
    parser = argparse.ArgumentParser(
        description="Look up an IP address in AbuseIPDB, VirusTotal, and Shodan."
    )

    parser.add_argument(
        "--ip",
        # Named argument with a -- flag. The user types: python lookup.py --ip 1.2.3.4
        # This is more explicit and self-documenting than a bare positional
        # argument, especially as the tool grows more flags over time.
        required=True,
        # required=True means argparse will error and print usage if --ip is omitted.
        # Without this, named arguments are optional by default.
        help="IP address to look up (e.g., 1.2.3.4)",
    )

    args = parser.parse_args()
    # args.ip now contains whatever the user passed to --ip.

    # ── Step 1: Get all API keys ───────────────────────────────────────────────
    # We fetch all keys before making any API calls so we can fail fast with
    # a clear error rather than failing halfway through the lookup.
    # "Fail fast" is a resilience pattern: detect configuration problems at
    # startup, not mid-execution.
    abuse_key  = get_abuseipdb_key()
    vt_key     = get_virustotal_key()
    shodan_key = get_shodan_key()

    if not abuse_key:
        print("\n[ERROR] No AbuseIPDB API key found.\n")
        print("To store your key in macOS Keychain (recommended):")
        print("  security add-generic-password -s abuseipdb -a api_key -w YOUR_KEY\n")
        print("Or add to your .env file:")
        print("  ABUSEIPDB_API_KEY=your_key_here\n")
        sys.exit(1)
        # SECURITY: We never print what we *tried* as a key — if something
        # partial was found, printing it could leak a fragment of a secret.

    if not vt_key:
        print("\n[ERROR] No VirusTotal API key found.\n")
        print("To store your key in macOS Keychain (recommended):")
        print("  security add-generic-password -s threat-intel-toolkit -a virustotal -w YOUR_KEY\n")
        print("Or add to your .env file:")
        print("  VIRUSTOTAL_API_KEY=your_key_here\n")
        sys.exit(1)

    if not shodan_key:
        print("\n[ERROR] No Shodan API key found.\n")
        print("To store your key in macOS Keychain (recommended):")
        print("  security add-generic-password -s threat-intel-toolkit -a shodan -w YOUR_KEY\n")
        print("Or add to your .env file:")
        print("  SHODAN_API_KEY=your_key_here\n")
        sys.exit(1)

    # ── Step 2: Query all three APIs ──────────────────────────────────────────
    print(f"\nQuerying AbuseIPDB, VirusTotal, and Shodan for {args.ip}...")

    # ── AbuseIPDB ─────────────────────────────────────────────────────────────
    try:
        abuse_data = query_abuseipdb(args.ip, abuse_key)

    except requests.exceptions.Timeout:
        print(f"[ERROR] AbuseIPDB request timed out after {REQUEST_TIMEOUT_SECONDS}s.")
        sys.exit(1)

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "unknown"
        print(f"[ERROR] AbuseIPDB returned HTTP {status}.")
        if status == 401:
            print("  → Your AbuseIPDB API key is invalid or expired.")
        elif status == 422:
            print("  → The IP address format is invalid.")
        elif status == 429:
            print("  → AbuseIPDB rate limit exceeded. Free accounts get 1,000 checks/day.")
        sys.exit(1)

    except requests.exceptions.ConnectionError:
        print("[ERROR] Could not connect to AbuseIPDB. Check your network.")
        sys.exit(1)

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Unexpected AbuseIPDB error: {e}")
        sys.exit(1)

    # ── VirusTotal ────────────────────────────────────────────────────────────
    try:
        vt_data = query_virustotal(args.ip, vt_key)

    except requests.exceptions.Timeout:
        print(f"[ERROR] VirusTotal request timed out after {REQUEST_TIMEOUT_SECONDS}s.")
        sys.exit(1)

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "unknown"
        print(f"[ERROR] VirusTotal returned HTTP {status}.")
        if status == 401:
            print("  → Your VirusTotal API key is invalid or expired.")
        elif status == 400:
            print("  → The IP address format is invalid.")
        elif status == 429:
            print("  → VirusTotal rate limit exceeded. Free tier: 4 requests/minute.")
        sys.exit(1)

    except requests.exceptions.ConnectionError:
        print("[ERROR] Could not connect to VirusTotal. Check your network.")
        sys.exit(1)

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Unexpected VirusTotal error: {e}")
        sys.exit(1)

    # ── Shodan ────────────────────────────────────────────────────────────────
    # Note: query_shodan() returns None on HTTP 404 (no data for IP).
    # That's handled inside query_shodan itself. The exceptions we catch here
    # are genuine failures: network errors, auth errors, rate limits.
    try:
        shodan_data = query_shodan(args.ip, shodan_key)

    except requests.exceptions.Timeout:
        print(f"[ERROR] Shodan request timed out after {REQUEST_TIMEOUT_SECONDS}s.")
        sys.exit(1)

    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "unknown"
        print(f"[ERROR] Shodan returned HTTP {status}.")
        if status == 401:
            print("  → Your Shodan API key is invalid or expired.")
        elif status == 403:
            print("  → Your Shodan plan does not permit this query.")
        elif status == 429:
            print("  → Shodan rate limit exceeded. Free tier: 1 request/second.")
        sys.exit(1)

    except requests.exceptions.ConnectionError:
        print("[ERROR] Could not connect to Shodan. Check your network.")
        sys.exit(1)

    except requests.exceptions.RequestException as e:
        print(f"[ERROR] Unexpected Shodan error: {e}")
        sys.exit(1)

    # ── Step 3: Display the combined report ───────────────────────────────────
    print_combined_report(args.ip, abuse_data, vt_data, shodan_data)


# This block only runs when you execute this file directly:
#   python lookup.py --ip 1.2.3.4
#
# It does NOT run when another Python file imports lookup.py as a module.
# This is the standard Python pattern for making a file both importable
# and directly executable.
if __name__ == "__main__":
    main()
