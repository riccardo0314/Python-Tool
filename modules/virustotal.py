"""
modules/virustotal.py

Data collection module for VirusTotal (domain reputation report).
Requires an API key, loaded from a local .env file (never committed).
"""

import os
import requests
from dotenv import load_dotenv

load_dotenv()  # reads .env in the project root and loads it into os.environ

METADATA = {
    "name": "VirusTotal",
    "description": "Domain reputation, detection stats and related IPs/domains",
    "accepted_input": ["domain"],
    "produced_output": ["domain", "ip", "reputation_score"],
    "requires_api_key": True,
    "cost_per_query": 0,          # free tier
    "known_rate_limit": True,     # 4 requests/minute on free tier
    "estimated_reliability": {
        "reputation_check": "high",
        "obscure_or_new_domains": "medium",
    },
}


def check_domain(domain: str) -> list[dict]:
    """
    Query VirusTotal's domain report endpoint.
    Returns a list of entities in the shared format
    {"tipo": ..., "valore": ..., "fonte": ...}.
    """
    api_key = os.getenv("VT_API_KEY")
    if not api_key:
        print("[!] VT_API_KEY not found. Did you create a .env file from .env.example?")
        return []

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": api_key}

    print(f"[*] Querying VirusTotal for: {domain}")

    try:
        response = requests.get(url, headers=headers, timeout=30)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if response.status_code == 401:
            print("[!] Invalid API key.")
        elif response.status_code == 429:
            print("[!] Rate limit hit (free tier: 4 requests/minute). Wait and retry.")
        else:
            print(f"[!] HTTP error: {e}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[!] Request error: {e}")
        return []

    data = response.json()
    attributes = data.get("data", {}).get("attributes", {})

    stats = attributes.get("last_analysis_stats", {})
    reputation = attributes.get("reputation", "n/a")

    print(f"[*] Reputation score: {reputation}")
    print(f"[*] Detection stats: {stats}")

    results = [
        {
            "tipo": "reputation_score",
            "valore": reputation,
            "fonte": METADATA["name"],
        }
    ]

    # VirusTotal can also return resolved IPs, but that requires a
    # separate API call (the "resolutions" relationship endpoint).
    # Left as a next step, not implemented in this first version.

    return results


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python modules/virustotal.py <domain>")
        sys.exit(1)

    target = sys.argv[1]
    results = check_domain(target)

    for r in results:
        print(f"    - {r['tipo']}: {r['valore']}")
