#!/usr/bin/env python3
"""
mcp_server.py — MCP server exposing threat intel lookup tools for Claude Desktop.

WHAT THIS FILE IS:
  The communication layer that lets Claude Desktop call your existing lookup.py
  functions. It speaks the Model Context Protocol (MCP) so Claude can invoke
  check_ip and check_ip_quick the same way it uses any built-in capability.

WHAT THIS FILE IS NOT:
  A replacement for lookup.py. All API query logic, key resolution, and verdict
  logic remain in lookup.py. This file only handles the MCP plumbing and
  report formatting — it imports and reuses everything from lookup.py.

WHY TWO SEPARATE FILES (lookup.py and mcp_server.py):
  lookup.py is your CLI tool. It parses command-line arguments, prints colored
  output to a terminal, and calls sys.exit() on failure. None of those behaviors
  are compatible with an MCP server:

    - sys.exit()   → would kill the server process and disconnect Claude Desktop
    - print()      → writes to stdout, which is reserved for MCP protocol messages
    - ANSI colors  → appear as literal escape characters in Claude's response text
    - argparse     → meaningless when there's no command line to parse

  Separating them lets each file do one job well. This is the Unix philosophy
  applied to Python: small tools that compose cleanly are better than one tool
  that tries to be everything.

TRANSPORT — stdio (standard input/output):
  MCP defines several transports. "stdio" means Claude Desktop launches this
  server as a subprocess and communicates by piping JSON messages over the
  process's stdin and stdout streams:

    Claude Desktop → writes JSON to → mcp_server.py stdin
    mcp_server.py  → writes JSON to → mcp_server.py stdout → Claude Desktop reads

  This is the standard transport for local MCP servers because:
    - No network port is needed (no firewall rules, no port conflicts)
    - No authentication layer (the process is only reachable from the same machine)
    - The server's lifetime is tied to Claude Desktop — it's killed when Claude exits
    - Your API keys never leave the machine (all requests go directly from this
      process to the APIs, not through Claude's servers)

HOW CLAUDE DESKTOP DISCOVERS AND CALLS TOOLS:
  1. You add this server to claude_desktop_config.json (see README for exact format)
  2. When Claude Desktop starts, it launches: python /path/to/mcp_server.py
  3. The MCP SDK exchanges a "handshake" — Claude Desktop asks what tools are
     available; the SDK responds with the tool names, descriptions, and parameter
     schemas it extracted from your @mcp.tool() decorated functions
  4. When you ask Claude something like "check 1.2.3.4 for threats", Claude
     decides to call check_ip, sends a JSON message to stdin with {"ip": "1.2.3.4"}
  5. The SDK deserializes that JSON, calls your Python function, and writes the
     return value back to stdout as a JSON response
  6. Claude Desktop reads the response and incorporates it into its reply to you

  From your perspective as a user: you just ask in plain English and Claude does
  the lookup. The MCP protocol is invisible.

HOW THE @mcp.tool() DECORATOR WORKS:
  @mcp.tool() registers the function with the MCP server at import time. The SDK
  inspects the function to automatically build the tool definition that Claude sees:

    - Function name        → tool name (check_ip, check_ip_quick)
    - Docstring            → tool description (what Claude reads to decide when to use it)
    - Parameter names      → input field names (ip)
    - Type annotations     → input field types (str → "string" in JSON Schema)
    - Args section in docstring → per-parameter descriptions

  This is why type annotations matter here — they're not just documentation.
  The SDK uses them to generate a JSON Schema that Claude uses to validate
  its own inputs before calling the tool.
"""

# ── Imports ────────────────────────────────────────────────────────────────────

from mcp.server.fastmcp import FastMCP
# FastMCP is the high-level MCP server class from the MCP Python SDK.
# It handles the protocol details (JSON serialization, capability negotiation,
# error wrapping) so we can focus on writing regular Python functions.
# "Fast" refers to the ergonomics (fast to write), not execution speed.

import requests
# We import requests here so we can catch requests exceptions in our error
# handling. The actual HTTP calls happen inside lookup.py's query functions,
# but the exceptions bubble up to us.

# Import from lookup.py — reusing all the existing logic.
#
# WHY THIS IS SAFE: lookup.py has `if __name__ == "__main__": main()` at the
# bottom. When Python *imports* a module, __name__ is set to the module name
# ("lookup"), not "__main__". So import only loads the functions and constants
# into memory — it does NOT run main(), parse arguments, or call any APIs.
#
# This is the standard Python pattern for making a file both importable as a
# library AND runnable as a script. It's why you should always use this guard
# instead of putting code at module level.
from lookup import (
    get_abuseipdb_key,
    get_virustotal_key,
    get_shodan_key,
    # These resolve API keys from Keychain or .env — the same secure priority
    # order your CLI tool uses. The MCP server inherits all that security work.

    query_abuseipdb,
    query_virustotal,
    query_shodan,
    # The actual HTTP request functions. All timeout handling, header setup,
    # and raise_for_status() logic stays in lookup.py — we don't repeat it.

    determine_verdict,
    # The OR-logic verdict function. Reusing it ensures the MCP tool gives the
    # same verdict as the CLI tool for identical data — no behavioral drift.
)


# ── Server Definition ──────────────────────────────────────────────────────────
# FastMCP takes a server name and optional version.
# The name appears in Claude Desktop's MCP server list and in error logs —
# make it recognizable. The version helps you track which iteration is running
# when debugging (check Claude Desktop's logs if a tool stops working).

mcp = FastMCP("threat-intel-toolkit")


# ── Report Builder ─────────────────────────────────────────────────────────────
# lookup.py's print_combined_report() uses print() to write to stdout.
# In the MCP context, stdout carries the protocol wire format — writing
# plain text there would corrupt the JSON stream and break communication.
#
# Instead, we build the same report as a string. Note what we ARE reusing:
#   - query_abuseipdb / query_virustotal / query_shodan (the HTTP logic)
#   - determine_verdict (the scoring logic)
#   - The same field extraction and data access patterns
#
# What we're NOT duplicating: the API calls and the business logic.
# What we ARE writing fresh: string concatenation instead of print() calls,
# and no ANSI escape codes (Claude Desktop renders plain text, not terminals).

def _build_full_report(ip_address, abuse_data, vt_data, shodan_data) -> str:
    """
    Assemble a threat intel report as a plain-text string.

    Called by check_ip after all three APIs have responded successfully.
    The leading underscore signals this is an internal helper — the MCP
    SDK will not expose it as a tool.

    Returns the complete report as a single multi-line string.
    """
    lines = []

    # ── AbuseIPDB fields ───────────────────────────────────────────────────────
    # Same field access pattern as lookup.py — { "data": { ... } } envelope.
    ad = abuse_data["data"]
    abuse_score   = ad["abuseConfidenceScore"]
    abuse_reports = ad.get("totalReports", 0)
    abuse_country = ad.get("countryCode") or "Unknown"
    abuse_isp     = ad.get("isp") or "Unknown"

    # ── VirusTotal fields ──────────────────────────────────────────────────────
    # Same double-nesting: data → attributes → last_analysis_stats.
    attrs = vt_data["data"]["attributes"]
    stats = attrs.get("last_analysis_stats", {})
    vt_malicious  = stats.get("malicious", 0)
    vt_suspicious = stats.get("suspicious", 0)
    vt_harmless   = stats.get("harmless", 0)
    vt_undetected = stats.get("undetected", 0)
    vt_timeout    = stats.get("timeout", 0)
    vt_total = vt_malicious + vt_suspicious + vt_harmless + vt_undetected + vt_timeout

    # ── Shodan fields ──────────────────────────────────────────────────────────
    # Initialize with safe defaults so the verdict calculation below always has
    # a numeric shodan_vuln_count even when shodan_data is None.
    shodan_vuln_count = 0
    shodan_ports      = []
    shodan_hostnames  = []
    shodan_os         = "Unknown"
    shodan_last_seen  = "Unknown"
    shodan_cves       = []
    shodan_services   = []

    if shodan_data:
        # Shodan's flat dict — all top-level keys, no nesting.
        shodan_ports     = shodan_data.get("ports", [])
        shodan_hostnames = shodan_data.get("hostnames", [])
        shodan_os        = shodan_data.get("os") or "Unknown"
        last_update_raw  = shodan_data.get("last_update") or ""
        shodan_last_seen = last_update_raw[:10] if last_update_raw else "Unknown"

        vulns_dict        = shodan_data.get("vulns", {})
        shodan_vuln_count = len(vulns_dict)
        shodan_cves       = sorted(vulns_dict.keys())

        raw_services    = [s.get("product") for s in shodan_data.get("data", []) if s.get("product")]
        shodan_services = list(dict.fromkeys(raw_services))
        # dict.fromkeys() deduplicates while preserving insertion order,
        # unlike set() which would scramble the sequence.

    # ── Verdict ────────────────────────────────────────────────────────────────
    # Reuse lookup.py's determine_verdict — same thresholds, same OR logic.
    verdict = determine_verdict(abuse_score, vt_malicious, shodan_vuln_count)

    # ── Assemble lines ─────────────────────────────────────────────────────────
    SEP = "═" * 44

    lines.append(f"IP: {ip_address}")
    lines.append(SEP)

    lines.append("\nABUSEIPDB")
    lines.append(f"  Score:      {abuse_score}/100")
    lines.append(f"  Reports:    {abuse_reports:,}")
    lines.append(f"  Country:    {abuse_country}")
    lines.append(f"  ISP:        {abuse_isp}")

    lines.append("\nVIRUSTOTAL")
    lines.append(f"  Malicious:  {vt_malicious}/{vt_total} engines")
    lines.append(f"  Suspicious: {vt_suspicious}/{vt_total} engines")
    lines.append(f"  Clean:      {vt_harmless}/{vt_total} engines")

    lines.append("\nSHODAN")
    if not shodan_data:
        # query_shodan() returns None on HTTP 404 — Shodan has no scan data.
        # We surface this explicitly rather than hiding it. A fresh IP with no
        # Shodan history can mean newly deployed attacker infrastructure.
        lines.append("  No data available")
    else:
        ports_str = ", ".join(str(p) for p in sorted(shodan_ports)) or "None detected"
        lines.append(f"  Ports:      {ports_str}")

        services_str = ", ".join(shodan_services) if shodan_services else "None identified"
        lines.append(f"  Services:   {services_str}")

        lines.append(f"  OS:         {shodan_os}")

        if shodan_hostnames:
            lines.append(f"  Hostnames:  {shodan_hostnames[0]}")
            for h in shodan_hostnames[1:]:
                lines.append(f"              {h}")
        else:
            lines.append("  Hostnames:  None")

        if shodan_cves:
            lines.append(f"  Vulns:      {', '.join(shodan_cves)}")
        else:
            lines.append("  Vulns:      None detected")

        lines.append(f"  Last Seen:  {shodan_last_seen}")

    lines.append(f"\nOVERALL VERDICT: {verdict}")
    lines.append(SEP)

    return "\n".join(lines)


# ── Tool 1: check_ip ──────────────────────────────────────────────────────────

@mcp.tool()
def check_ip(ip: str) -> str:
    """Check an IP address against AbuseIPDB, VirusTotal, and Shodan for threat intelligence.

    Queries all three sources and returns a combined report with an overall verdict.
    Use this when you need the full picture: abuse history, engine consensus, and
    what the host is actually running.

    Args:
        ip: The IP address to check (e.g., 1.2.3.4 or 2001:db8::1)
    """
    # ── Resolve keys before making any API calls ───────────────────────────────
    # "Fail fast" pattern: detect missing credentials immediately rather than
    # discovering them mid-execution after some API calls have already succeeded.
    # In an IR context, a partial result is worse than a clear error — it can
    # give false confidence if the missing source would have shown a red flag.
    abuse_key  = get_abuseipdb_key()
    vt_key     = get_virustotal_key()
    shodan_key = get_shodan_key()

    if not abuse_key:
        return (
            "[ERROR] No AbuseIPDB API key found.\n\n"
            "To store it in macOS Keychain (recommended):\n"
            "  security add-generic-password -s abuseipdb -a api_key -w YOUR_KEY\n\n"
            "Or add this line to your .env file:\n"
            "  ABUSEIPDB_API_KEY=your_key_here"
        )
    if not vt_key:
        return (
            "[ERROR] No VirusTotal API key found.\n\n"
            "To store it in macOS Keychain (recommended):\n"
            "  security add-generic-password -s threat-intel-toolkit -a virustotal -w YOUR_KEY\n\n"
            "Or add this line to your .env file:\n"
            "  VIRUSTOTAL_API_KEY=your_key_here"
        )
    if not shodan_key:
        return (
            "[ERROR] No Shodan API key found.\n\n"
            "To store it in macOS Keychain (recommended):\n"
            "  security add-generic-password -s threat-intel-toolkit -a shodan -w YOUR_KEY\n\n"
            "Or add this line to your .env file:\n"
            "  SHODAN_API_KEY=your_key_here"
        )

    # ── AbuseIPDB ──────────────────────────────────────────────────────────────
    # Each API is wrapped independently so a failure in one gives a specific,
    # actionable error message rather than a generic exception traceback.
    # MCP tools must RETURN errors — raising an unhandled exception would
    # crash the tool call and give Claude Desktop a less useful error.
    try:
        abuse_data = query_abuseipdb(ip, abuse_key)
    except requests.exceptions.Timeout:
        return "[ERROR] AbuseIPDB request timed out. The API may be experiencing issues — try again in a moment."
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "unknown"
        msg = f"[ERROR] AbuseIPDB returned HTTP {status}."
        if status == 401:
            msg += " Your API key is invalid or expired."
        elif status == 422:
            msg += f" '{ip}' is not a valid IP address format."
        elif status == 429:
            msg += " Rate limit exceeded — free accounts get 1,000 checks/day."
        return msg
    except requests.exceptions.RequestException as e:
        return f"[ERROR] Could not reach AbuseIPDB: {e}"

    # ── VirusTotal ─────────────────────────────────────────────────────────────
    try:
        vt_data = query_virustotal(ip, vt_key)
    except requests.exceptions.Timeout:
        return "[ERROR] VirusTotal request timed out. Try again in a moment."
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "unknown"
        msg = f"[ERROR] VirusTotal returned HTTP {status}."
        if status == 401:
            msg += " Your API key is invalid or expired."
        elif status == 400:
            msg += f" '{ip}' is not a valid IP address format."
        elif status == 429:
            msg += " Rate limit exceeded — free tier allows 4 requests/minute."
        return msg
    except requests.exceptions.RequestException as e:
        return f"[ERROR] Could not reach VirusTotal: {e}"

    # ── Shodan ─────────────────────────────────────────────────────────────────
    # query_shodan() returns None on HTTP 404 (no scan data for this IP).
    # That case is handled inside query_shodan itself — it's not an error,
    # it's a valid result that we display as "No data available".
    # We only catch genuine failures here: auth errors, rate limits, timeouts.
    try:
        shodan_data = query_shodan(ip, shodan_key)
    except requests.exceptions.Timeout:
        return "[ERROR] Shodan request timed out. Try again in a moment."
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "unknown"
        msg = f"[ERROR] Shodan returned HTTP {status}."
        if status == 401:
            msg += " Your API key is invalid or expired."
        elif status == 403:
            msg += " Your Shodan plan does not include this feature."
        elif status == 429:
            msg += " Rate limit exceeded — free tier allows 1 request/second."
        return msg
    except requests.exceptions.RequestException as e:
        return f"[ERROR] Could not reach Shodan: {e}"

    # ── All APIs responded — build and return the report ─────────────────────
    return _build_full_report(ip, abuse_data, vt_data, shodan_data)


# ── Tool 2: check_ip_quick ────────────────────────────────────────────────────

@mcp.tool()
def check_ip_quick(ip: str) -> str:
    """Quick AbuseIPDB check for an IP address — faster than full check.

    Queries only AbuseIPDB and returns the abuse score and verdict. Use this
    when you need a fast first pass. For full threat context (VirusTotal engine
    consensus + Shodan port/service data), use check_ip instead.

    Args:
        ip: The IP address to check (e.g., 1.2.3.4)
    """
    abuse_key = get_abuseipdb_key()

    if not abuse_key:
        return (
            "[ERROR] No AbuseIPDB API key found.\n\n"
            "To store it in macOS Keychain (recommended):\n"
            "  security add-generic-password -s abuseipdb -a api_key -w YOUR_KEY\n\n"
            "Or add this line to your .env file:\n"
            "  ABUSEIPDB_API_KEY=your_key_here"
        )

    try:
        abuse_data = query_abuseipdb(ip, abuse_key)
    except requests.exceptions.Timeout:
        return "[ERROR] AbuseIPDB request timed out. Try again in a moment."
    except requests.exceptions.HTTPError as e:
        status = e.response.status_code if e.response is not None else "unknown"
        msg = f"[ERROR] AbuseIPDB returned HTTP {status}."
        if status == 401:
            msg += " Your API key is invalid or expired."
        elif status == 422:
            msg += f" '{ip}' is not a valid IP address format."
        elif status == 429:
            msg += " Rate limit exceeded — free accounts get 1,000 checks/day."
        return msg
    except requests.exceptions.RequestException as e:
        return f"[ERROR] Could not reach AbuseIPDB: {e}"

    ad = abuse_data["data"]
    abuse_score = ad["abuseConfidenceScore"]
    total_reports = ad.get("totalReports", 0)

    # Verdict based solely on the AbuseIPDB score.
    # We pass 0 for the VT and Shodan parameters because this is a single-source
    # quick check by design. The caller chose speed over completeness.
    #
    # IMPORTANT LIMITATION: An IP can be CLEAN here but MALICIOUS in the full
    # check — for example, if VirusTotal has 10 engine flags but AbuseIPDB has
    # no community reports yet (new infrastructure). Always follow up suspicious
    # IPs with check_ip before taking blocking action.
    verdict = determine_verdict(abuse_score, 0, 0)

    return (
        f"IP: {ip}\n"
        f"AbuseIPDB Score: {abuse_score}/100\n"
        f"Total Reports:   {total_reports:,}\n"
        f"Verdict:         {verdict}\n\n"
        f"Note: Quick check uses AbuseIPDB only. Use check_ip for full analysis."
    )


# ── Entry Point ────────────────────────────────────────────────────────────────
# Claude Desktop launches this file as a subprocess:
#   python /path/to/mcp_server.py
#
# mcp.run(transport="stdio") starts the server loop:
#   1. Reads a JSON message from stdin
#   2. Dispatches to the appropriate @mcp.tool() function
#   3. Writes the JSON response to stdout
#   4. Repeats indefinitely until the process is killed
#
# The server never exits on its own. Claude Desktop owns the process lifecycle —
# it starts the server on launch and kills it on exit or reconnect.
#
# DEBUGGING TIP: If a tool stops working, check Claude Desktop's logs.
# On macOS: ~/Library/Logs/Claude/mcp-server-threat-intel-toolkit.log
# Common causes: Python not found, import errors, missing .env file.

if __name__ == "__main__":
    mcp.run(transport="stdio")
