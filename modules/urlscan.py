"""
modules/urlscan.py

Data collection module for urlscan.io. Two separate modes:

  - search_domain(): Search API. Looks up scans that already exist for
    a domain — does NOT submit or actively visit anything. No API key.

  - submit_and_scan(): Submission API. Actively submits a URL to be
    visited and scanned in urlscan's sandbox. Requires an API key and
    generates a NEW public record (default visibility: "unlisted" —
    not indexed/searchable, but viewable by anyone with the link).
"""

import time
import os
import requests
from dotenv import load_dotenv

load_dotenv()


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


SUBMIT_METADATA = {
    "name": "urlscan.io (submission)",
    "description": "Actively submits a URL to be visited and scanned in a sandbox",
    "accepted_input": ["url"],
    "produced_output": ["ip", "domain", "screenshot", "verdict"],
    "requires_api_key": True,
    "cost_per_query": 0,          # free tier
    "known_rate_limit": True,     # 1000 scans/day on free tier
    "default_visibility": "unlisted",
    "estimated_reliability": {
        "fresh_data": "high",     # generates a new live observation
        "stealth": "low",         # the scan itself is visible to the target if it checks urlscan
    },
}


def submit_and_scan(url: str, visibility: str = "unlisted", max_wait: int = 90) -> list[dict]:
    """
    Submit a URL to urlscan.io, wait for the scan to complete, and
    return the findings in the shared format
    {"tipo": ..., "valore": ..., "fonte": ...}.

    visibility: "public", "unlisted", or "private" (private requires a
    paid plan). Defaults to "unlisted": not indexed/searchable, but
    reachable by anyone who has the direct link.
    """
    api_key = os.getenv("URLSCAN_API_KEY")
    if not api_key:
        print("[!] URLSCAN_API_KEY not found. Did you add it to your .env file?")
        return []

    submit_url = "https://urlscan.io/api/v1/scan/"
    headers = {"API-Key": api_key, "Content-Type": "application/json"}
    body = {"url": url, "visibility": visibility}

    print(f"[*] Submitting to urlscan.io ({visibility}): {url}")

    try:
        response = requests.post(submit_url, headers=headers, json=body, timeout=30)
        response.raise_for_status()
    except requests.exceptions.HTTPError as e:
        if response.status_code == 400:
            print(f"[!] Bad request — is the URL valid? {e}")
        elif response.status_code == 429:
            print("[!] Rate limit hit (free tier: 1000 scans/day).")
        else:
            print(f"[!] HTTP error: {e}")
        return []
    except requests.exceptions.RequestException as e:
        print(f"[!] Request error: {e}")
        return []

    submission = response.json()
    result_api_url = submission.get("api")  # e.g. https://urlscan.io/api/v1/result/<uuid>/

    if not result_api_url:
        print("[!] No result URL returned by urlscan.io.")
        return []

    print(f"[*] Scan submitted, waiting for results (up to {max_wait}s)...")

    # The scan is not instant. urlscan recommends waiting ~10s before the
    # first check, then polling every few seconds. The result endpoint
    # returns 404 until the scan finishes.
    time.sleep(10)
    waited = 10
    poll_interval = 5
    result_data = None

    while waited < max_wait:
        try:
            poll_response = requests.get(
                result_api_url, headers={"API-Key": api_key}, timeout=30
            )
        except requests.exceptions.RequestException as e:
            print(f"[!] Polling error: {e}")
            poll_response = None

        if poll_response is not None:
            if poll_response.status_code == 200:
                result_data = poll_response.json()
                break
            elif poll_response.status_code == 404:
                pass  # not ready yet, keep polling
            elif poll_response.status_code == 429:
                print("[!] Rate limited while polling, backing off...")
                time.sleep(10)
                waited += 10
            else:
                print(f"[!] Unexpected status while polling: {poll_response.status_code}")
                break

        time.sleep(poll_interval)
        waited += poll_interval

    if result_data is None:
        print(f"[!] Scan did not complete within {max_wait}s. Check manually: "
              f"{submission.get('result', result_api_url)}")
        return []

    page = result_data.get("page", {})
    verdicts = result_data.get("verdicts", {}).get("overall", {})
    lists = result_data.get("lists", {})

    results = []

    if page.get("ip"):
        results.append({"tipo": "ip", "valore": page["ip"], "fonte": SUBMIT_METADATA["name"]})
    if page.get("domain"):
        results.append({"tipo": "domain", "valore": page["domain"], "fonte": SUBMIT_METADATA["name"]})

    for ip in lists.get("ips", []):
        results.append({"tipo": "ip", "valore": ip, "fonte": SUBMIT_METADATA["name"]})
    for dom in lists.get("domains", []):
        results.append({"tipo": "domain", "valore": dom, "fonte": SUBMIT_METADATA["name"]})

    malicious = verdicts.get("malicious", False)
    score = verdicts.get("score", "n/a")
    results.append({
        "tipo": "verdict",
        "valore": f"malicious={malicious} score={score}",
        "fonte": SUBMIT_METADATA["name"],
    })

    report_link = submission.get("result", "")
    print(f"[*] Scan complete. Verdict: malicious={malicious}, score={score}")
    print(f"[*] Full report: {report_link}")

    return results


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage:")
        print("  python modules/urlscan.py <domain>              (search existing scans)")
        print("  python modules/urlscan.py --submit <url>        (submit a new scan)")
        sys.exit(1)

    if sys.argv[1] == "--submit":
        if len(sys.argv) != 3:
            print("Usage: python modules/urlscan.py --submit <url>")
            sys.exit(1)
        results = submit_and_scan(sys.argv[2])
    else:
        results = search_domain(sys.argv[1])

    for r in results:
        print(f"    - {r['tipo']}: {r['valore']}")
