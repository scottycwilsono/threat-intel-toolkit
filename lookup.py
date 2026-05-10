#!/usr/bin/env python3
# ^ This "shebang" line tells your shell which interpreter to use when you run
#   the script directly (./lookup.py). Without it, the OS doesn't know this is
#   Python. It's a Unix convention, not Python syntax.

"""
lookup.py — AbuseIPDB threat intelligence lookup tool.

Usage:
    python lookup.py <ip_address>
    python lookup.py 1.2.3.4

API key resolution order (most secure → least secure):
    1. macOS Keychain  (preferred — never touches disk as plaintext)
    2. .env file       (fallback — kept out of git via .gitignore)
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
# We use it to read ABUSEIPDB_API_KEY from the shell environment, which can
# be populated by python-dotenv reading a .env file.

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
# This must happen BEFORE we try to read os.environ for the API key.
# If no .env file exists, load_dotenv() silently does nothing — no error.
# SECURITY: load_dotenv() only sets a variable if it isn't already set in the
# environment. Real environment variables (set in your shell) always win.
# This prevents a malicious .env file from overwriting shell-level secrets.
load_dotenv()

# ── Constants ─────────────────────────────────────────────────────────────────
# Define fixed values once at the top. If AbuseIPDB changes their URL or you
# want to adjust the threshold, you change it in one place — not scattered
# throughout the code.

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
# The AbuseIPDB v2 "check" endpoint. This is what we GET to look up an IP.
# SECURITY: We hardcode HTTPS — never HTTP. HTTP sends your API key in
# plaintext over the network. requests enforces TLS by default when the URL
# starts with https://.

KEYCHAIN_SERVICE = "abuseipdb"
# The "service" label we used when storing the key in Keychain.
# Think of it as a folder name inside Keychain.

KEYCHAIN_ACCOUNT = "api_key"
# The "account" label — the specific item inside that service folder.

MALICIOUS_THRESHOLD = 25
# AbuseIPDB returns a confidence score from 0–100.
# 0  = no reports, 100 = confirmed abuser.
# We treat anything ≥ 25 as MALICIOUS. This is a judgment call you can tune.
# SECURITY CONTEXT: In a fintech SOC, you might lower this to 10 to be more
# aggressive about blocking. For an allowlist review, you might raise it to 50.
# The threshold should match your risk tolerance and false-positive budget.

REQUEST_TIMEOUT_SECONDS = 10
# Maximum seconds to wait for AbuseIPDB to respond.
# SECURITY: Without this, a network issue or slow API could block your script
# forever. In incident response, a hung tool can be worse than a failed one.

LOOKBACK_DAYS = 90
# How far back to look for abuse reports. AbuseIPDB max is 365.
# 90 days is a reasonable balance: recent enough to be relevant,
# long enough to catch slow-burn C2 infrastructure.


# ── API Key Retrieval ─────────────────────────────────────────────────────────

def get_api_key_from_keychain():
    """
    Try to retrieve the AbuseIPDB API key from macOS Keychain.

    Returns the key as a string, or None if not found.

    To store your key in Keychain first, run this in your terminal:
        security add-generic-password -s abuseipdb -a api_key -w YOUR_KEY_HERE
    """
    try:
        result = subprocess.run(
            # We call the macOS `security` CLI tool — it ships with every Mac.
            # -s = service name, -a = account name, -w = output just the password
            ["security", "find-generic-password",
             "-s", KEYCHAIN_SERVICE,
             "-a", KEYCHAIN_ACCOUNT,
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


def get_api_key():
    """
    Resolve the API key using a secure priority order:
      1. macOS Keychain (most secure — encrypted, never on disk as plaintext)
      2. Environment variable / .env file (acceptable — kept out of git)

    Returns the key string, or None if neither source has it.
    """
    # Try Keychain first — it's the most secure option.
    key = get_api_key_from_keychain()
    if key:
        return key

    # Fall back to environment variable.
    # load_dotenv() already ran at module load time, so ABUSEIPDB_API_KEY will
    # be in os.environ if it was in the .env file.
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if key:
        return key

    # Neither source had a key. Return None so main() can print a helpful error.
    return None


# ── AbuseIPDB API Query ───────────────────────────────────────────────────────

def query_abuseipdb(ip_address, api_key):
    """
    Send a GET request to the AbuseIPDB v2 check endpoint.

    Returns the parsed JSON response as a Python dictionary.
    Raises requests exceptions on network or HTTP errors.
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


# ── Report Formatting ─────────────────────────────────────────────────────────

def format_report(data):
    """
    Print a clean, human-readable report from the AbuseIPDB API response.
    """
    d = data["data"]
    # The AbuseIPDB response wraps everything in a "data" key:
    # { "data": { "ipAddress": "...", "abuseConfidenceScore": 42, ... } }
    # We pull out the inner dict to keep the rest of the code clean.

    score = d["abuseConfidenceScore"]
    # 0–100. This is the key signal. It's a weighted average across all reports,
    # not just a raw count. An IP with 1,000 reports from one user scores lower
    # than one with 50 reports from 50 different reporters.

    verdict = "MALICIOUS" if score >= MALICIOUS_THRESHOLD else "CLEAN"
    # Binary verdict based on our threshold constant defined at the top.
    # SECURITY: In production, you'd want a third state — "SUSPICIOUS" —
    # for the gray zone (e.g., scores 10–40). Binary verdicts can create
    # false confidence in edge cases.

    # ANSI escape codes for terminal color.
    # \033[91m = bright red, \033[92m = bright green, \033[0m = reset to default.
    # SECURITY NOTE: These are display-only. Never use color coding as the sole
    # indicator in a log or SIEM — it won't render there. Always include the
    # text label ("MALICIOUS" / "CLEAN") too, which we do here.
    RED   = "\033[91m"
    GREEN = "\033[92m"
    RESET = "\033[0m"
    verdict_color = RED if verdict == "MALICIOUS" else GREEN

    last_reported = d.get("lastReportedAt") or "Never"
    # .get() returns None if the key is missing (safer than d["key"] which
    # raises a KeyError). "or 'Never'" converts None to the string "Never"
    # for clean display. An IP with no reports has lastReportedAt = null in JSON,
    # which becomes None in Python.

    # Print the report. The f-string (f"...") lets us embed variables directly
    # in strings using {curly_braces}. This is the modern Python 3.6+ approach.
    print()
    print("=" * 50)
    print("  IP REPUTATION REPORT")
    print("=" * 50)
    print(f"  IP Address    : {d['ipAddress']}")
    print(f"  Country       : {d.get('countryCode') or 'Unknown'}")
    print(f"  ISP           : {d.get('isp') or 'Unknown'}")
    print(f"  Usage Type    : {d.get('usageType') or 'Unknown'}")
    # Usage type examples: "Data Center/Web Hosting/Transit", "ISP/Mobile Carrier",
    # "Fixed Line ISP". SECURITY CONTEXT: "Data Center" IPs are higher risk than
    # residential ISPs in many threat models — attackers rent cloud VMs to mask
    # their real location.
    print(f"  Abuse Score   : {score}/100")
    print(f"  Total Reports : {d.get('totalReports', 0)}")
    print(f"  Last Reported : {last_reported}")
    print("-" * 50)
    print(f"  Verdict       : {verdict_color}{verdict}{RESET}")
    print("=" * 50)
    print()


# ── Entry Point ───────────────────────────────────────────────────────────────

def main():
    # argparse builds us a proper CLI with --help and argument validation.
    parser = argparse.ArgumentParser(
        description="Look up an IP address in AbuseIPDB threat intelligence."
    )

    parser.add_argument(
        "ip",
        # Positional argument — no flag needed, user just types: python lookup.py 1.2.3.4
        help="IP address to look up (e.g., 1.2.3.4)",
    )

    args = parser.parse_args()
    # args.ip now contains whatever the user typed after the script name.
    # argparse will print a usage error and exit automatically if ip is missing.

    # ── Step 1: Get the API key ───────────────────────────────────────────────
    api_key = get_api_key()

    if not api_key:
        # Print actionable instructions, then exit with code 1 (failure).
        # SECURITY: We never print what we *tried* as a key — if something
        # partial was found, printing it could leak a fragment of a secret.
        print("\n[ERROR] No API key found.\n")
        print("To store your key in macOS Keychain (recommended):")
        print("  security add-generic-password -s abuseipdb -a api_key -w YOUR_KEY\n")
        print("Or create a .env file in this directory:")
        print("  echo 'ABUSEIPDB_API_KEY=your_key_here' > .env\n")
        sys.exit(1)
        # sys.exit(1) terminates the program immediately with exit code 1.
        # Exit code 0 = success, anything else = failure (convention).

    # ── Step 2: Query AbuseIPDB ───────────────────────────────────────────────
    print(f"\nLooking up {args.ip}...")

    try:
        data = query_abuseipdb(args.ip, api_key)

    except requests.exceptions.Timeout:
        print(f"[ERROR] Request timed out after {REQUEST_TIMEOUT_SECONDS}s.")
        sys.exit(1)

    except requests.exceptions.HTTPError as e:
        # e.response.status_code tells us exactly what went wrong.
        status = e.response.status_code if e.response is not None else "unknown"
        print(f"[ERROR] AbuseIPDB returned HTTP {status}.")
        if status == 401:
            print("  → Your API key is invalid or expired.")
        elif status == 422:
            print("  → The IP address format is invalid.")
        elif status == 429:
            print("  → Rate limit exceeded. Free accounts get 1,000 checks/day.")
        sys.exit(1)

    except requests.exceptions.ConnectionError:
        print("[ERROR] Could not connect to AbuseIPDB. Check your network.")
        sys.exit(1)

    except requests.exceptions.RequestException as e:
        # Catch-all for any other requests error.
        print(f"[ERROR] Unexpected network error: {e}")
        sys.exit(1)

    # ── Step 3: Display the report ────────────────────────────────────────────
    format_report(data)


# This block only runs when you execute this file directly:
#   python lookup.py 1.2.3.4
#
# It does NOT run when another Python file imports lookup.py as a module.
# This is the standard Python pattern for making a file both importable
# and directly executable.
if __name__ == "__main__":
    main()
