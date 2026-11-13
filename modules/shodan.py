"""
modules/shodan.py

IP enrichment with Shodan: open ports, known CVEs, hostnames, tags.
Takes IPs collected by the other modules (it does not take a domain).

Two backends, picked automatically:
  - SHODAN_API_KEY set   -> Shodan host API (api.shodan.io/shodan/host/<ip>).
                            Host lookups do not use query credits, even on
                            a free account. Adds org and OS info.
  - no key               -> Shodan InternetDB (internetdb.shodan.io/<ip>).
                            No key needed, free for non-commercial use,
                            data refreshed weekly.

Both are passive: they read what Shodan already scanned, nothing is
sent to the target.
"""

import ipaddress
import os
import time

import requests
from dotenv import load_dotenv

load_dotenv()

METADATA = {
    "name": "Shodan",
    "description": "IP enrichment: open ports, known CVEs, hostnames, tags (cdn, cloud...)",
    "accepted_input": ["ip"],
    "produced_output": ["open_port", "vuln", "hostname", "tag", "org"],
    "requires_api_key": False,    # optional: without it, InternetDB is used
    "cost_per_query": 0,          # host lookups don't use query credits
    "known_rate_limit": True,     # ~1 request/second with an API key
    "estimated_reliability": {
        "exposed_services": "high",   # what Shodan's scanners actually saw
        "cdn_fronted_ips": "low",     # CDN edges show the CDN, not the origin
        "freshness": "medium",        # InternetDB is updated weekly
    },
}


def _is_public_ipv4(ip: str) -> bool:
    """InternetDB only covers public IPv4; skip IPv6 and private ranges."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and addr.is_global


def _lookup_internetdb(ip: str) -> dict | None:
    response = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=15)
    if response.status_code == 404:
        return None  # Shodan has no data on this IP
    response.raise_for_status()
    data = response.json()
    return {
        "ports": data.get("ports", []),
        "vulns": data.get("vulns", []),
        "hostnames": data.get("hostnames", []),
        "tags": data.get("tags", []),
        "org": None,
    }


def _lookup_host_api(ip: str, api_key: str) -> dict | None:
    response = requests.get(
        f"https://api.shodan.io/shodan/host/{ip}",
        params={"key": api_key},
        timeout=15,
    )
    if response.status_code == 404:
        return None
    response.raise_for_status()
    data = response.json()
    vulns = data.get("vulns", [])
    if isinstance(vulns, dict):  # some responses return a dict keyed by CVE
        vulns = list(vulns.keys())
    return {
        "ports": data.get("ports", []),
        "vulns": vulns,
        "hostnames": data.get("hostnames", []),
        "tags": data.get("tags", []),
        "org": data.get("org"),
    }


def enrich_ips(ips: list[str], max_ips: int = 10) -> list[dict]:
    """
    Look up each IP on Shodan and return findings in the shared format
    {"tipo": ..., "valore": ..., "fonte": ..., "ip": ...}.

    Only the first max_ips public IPv4 addresses are checked, to keep
    the run fast and the AI prompt short.
    """
    api_key = os.getenv("SHODAN_API_KEY", "").strip()
    backend = "host API" if api_key else "InternetDB"

    targets = []
    for ip in ips:
        if _is_public_ipv4(ip) and ip not in targets:
            targets.append(ip)

    skipped = len(set(ips)) - len(targets)
    if len(targets) > max_ips:
        print(f"[*] {len(targets)} IPs to check, limiting to the first {max_ips}.")
        targets = targets[:max_ips]

    if not targets:
        print("[*] No public IPv4 addresses to enrich.")
        return []

    print(f"[*] Enriching {len(targets)} IP(s) via Shodan {backend}"
          + (f" ({skipped} skipped: IPv6/private/invalid)" if skipped else ""))

    results = []
    source = f"{METADATA['name']} ({backend})"

    def add(tipo, valore, ip):
        results.append({"tipo": tipo, "valore": valore, "fonte": source, "ip": ip})

    for i, ip in enumerate(targets):
        if i > 0 and api_key:
            time.sleep(1)  # stay under ~1 request/second

        try:
            info = _lookup_host_api(ip, api_key) if api_key else _lookup_internetdb(ip)
        except requests.exceptions.HTTPError as e:
            code = e.response.status_code if e.response is not None else "?"
            if code == 401:
                print("[!] Invalid SHODAN_API_KEY. Remove it from .env to use InternetDB instead.")
                return results
            if code == 429:
                print("[!] Shodan rate limit hit, stopping enrichment here.")
                return results
            print(f"[!] {ip}: HTTP error {code}")
            continue
        except requests.exceptions.RequestException as e:
            print(f"[!] {ip}: request error: {e}")
            continue

        if info is None:
            print(f"    {ip}: no Shodan data")
            continue

        print(f"    {ip}: ports={info['ports']} vulns={len(info['vulns'])} tags={info['tags']}")

        for port in info["ports"]:
            add("open_port", f"{ip}:{port}", ip)
        for cve in info["vulns"]:
            add("vuln", f"{cve} on {ip}", ip)
        for hostname in info["hostnames"]:
            add("hostname", f"{hostname} ({ip})", ip)
        for tag in info["tags"]:
            add("tag", f"{tag} ({ip})", ip)
        if info["org"]:
            add("org", f"{info['org']} ({ip})", ip)

    return results


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python modules/shodan.py <ip> [<ip> ...]")
        sys.exit(1)

    for r in enrich_ips(sys.argv[1:]):
        print(f"    - {r['tipo']}: {r['valore']}")
