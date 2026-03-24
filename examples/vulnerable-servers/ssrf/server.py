"""
SSRF Demo — Broken private IP validation

Reproduces CVE-2025-65513: the IP check receives the full URL instead of
the extracted hostname, so it never matches.

`oxvault scan` flags:
  - mcp-ssrf-broken-check (CWE-918): startsWith("10.") on full URL
  - mcp-network-egress: requests.get outbound call
"""
import requests


def is_ip_private(value):
    return value.startswith("10.") or value.startswith("192.168.")


def fetch_url(url: str) -> str:
    # BUG: checking full URL, not extracted hostname
    # "http://169.254.169.254/..." does NOT start with "10." → check passes
    if is_ip_private(url):
        raise ValueError("Private IP blocked")
    response = requests.get(url)
    return response.text
