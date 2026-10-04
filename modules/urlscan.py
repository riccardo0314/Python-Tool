"""
modules/urlscan.py

Data collection module for urlscan.io Search API.
Looks up scans that already exist for a domain — does NOT submit
or actively visit anything. No API key required for search.
"""

import requests


def _is_same_domain(page_domain: str, target_domain: str) -> bool:
    """
    True if page_domain IS target_domain or a subdomain of it.
    False for anything else (unrelated domains that merely showed up
    in urlscan's results, e.g. phishing pages referencing the target).
    """
    if not page_domain:
        return False
    page_domain = page_domain.lower().rstrip(".")
    target_domain = target_domain.lower().rstrip(".")
    return page_domain == target_domain or page_domain.endswith("." + target_domain)


METADATA = {
    "name": "urlscan.io (search)",
    "description": "Looks up existing scans for a domain: resolved IPs, pages, resources",
    "accepted_input": ["domain"],
    "produced_output": ["domain", "ip", "url"],
    # Every result also carries "same_domain": True/False — whether the
    # scanned page actually belongs to the target domain, or merely
    # showed up in urlscan's search (e.g. a phishing page referencing it).
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

    # key: (tipo, valore) -> same_domain. If the same IP/URL shows up
    # both as same-domain and as unrelated in different scans, we keep
    # it flagged True (it's still worth knowing it touches the target).
    entities = {}

    for entry in raw_results:
        page = entry.get("page", {})
        ip = page.get("ip")
        page_url = page.get("url")
        page_domain = page.get("domain")

        same_domain = _is_same_domain(page_domain, domain)

        if ip:
            key = ("ip", ip)
            entities[key] = entities.get(key, False) or same_domain
        if page_url:
            key = ("url", page_url)
            entities[key] = entities.get(key, False) or same_domain

    results = [
        {"tipo": tipo, "valore": valore, "fonte": METADATA["name"], "same_domain": same_domain}
        for (tipo, valore), same_domain in sorted(entities.items())
    ]

    same_domain_count = sum(1 for r in results if r["same_domain"])
    print(f"[*] Found {len(results)} unique entities across {len(raw_results)} scan(s) "
          f"({same_domain_count} same-domain, {len(results) - same_domain_count} unrelated/referencing)")

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
