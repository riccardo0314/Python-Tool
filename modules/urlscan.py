"""
modules/urlscan.py

Data collection module for urlscan.io Search API.
Looks up scans that already exist for a domain — does NOT submit
or actively visit anything. No API key required for search.
"""

import requests

METADATA = {
    "name": "urlscan.io (search)",
    "description": "Looks up existing scans for a domain: resolved IPs, pages, resources",
    "accepted_input": ["domain"],
    "produced_output": ["domain", "ip", "url"],
    "requires_api_key": False,
    "cost_per_query": 0,
    "known_rate_limit": True,  # public search API: 120 requests/minute
    "estimated_reliability": {
        "popular_domains": "high",      # likely to have existing scans
        "obscure_or_new_domains": "low",  # may have no scans at all
    },
}


def search_domain(domain: str, max_results: int = 20) -> list[dict]:
    """
    Search urlscan.io for existing scans of a domain.
    Returns a list of entities in the shared format
    {"tipo": ..., "valore": ..., "fonte": ...}.
    """
    url = "https://urlscan.io/api/v1/search/"
    params = {
        "q": f"domain:{domain}",
        "size": max_results,
    }

    print(f"[*] Searching urlscan.io for: {domain}")

    try:
        response = requests.get(url, params=params, timeout=30)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if response.status_code == 429:
            print("[!] Rate limit hit. Wait and retry.")
        else:
            print(f"[!] HTTP error: {e}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[!] Request error: {e}")
        return []

    data = response.json()
    raw_results = data.get("results", [])

    if not raw_results:
        print("[*] No existing scans found for this domain.")
        return []

    ips_found = set()
    urls_found = set()

    for entry in raw_results:
        page = entry.get("page", {})
        ip = page.get("ip")
        page_url = page.get("url")

        if ip:
            ips_found.add(ip)
        if page_url:
            urls_found.add(page_url)

    results = []
    for ip in sorted(ips_found):
        results.append({"tipo": "ip", "valore": ip, "fonte": METADATA["name"]})
    for page_url in sorted(urls_found):
        results.append({"tipo": "url", "valore": page_url, "fonte": METADATA["name"]})

    print(f"[*] Found {len(ips_found)} unique IP(s) and {len(urls_found)} unique URL(s) "
          f"across {len(raw_results)} existing scan(s)")

    return results


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        print("Usage: python modules/urlscan.py <domain>")
        sys.exit(1)

    target = sys.argv[1]
    results = search_domain(target)

    for r in results:
        print(f"    - {r['tipo']}: {r['valore']}")
