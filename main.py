"""
main.py

Entry point of the tool. Runs all available modules against a target
domain, tags results, and saves everything to a JSON file.
"""

import sys
import json

from modules.crtsh import cerca_subdomains, METADATA as CRTSH_METADATA
from modules.virustotal import check_domain, METADATA as VT_METADATA
from modules.urlscan import search_domain, METADATA as URLSCAN_METADATA
from utils.ip_validator import is_valid_ip
from utils.url_defanger import defang


def print_source_info(metadata: dict) -> None:
    """Print a short summary of a source before querying it."""
    print(f"[*] Source: {metadata['name'] if 'name' in metadata else metadata.get('nome')}")
    print(f"    Cost per query: {metadata.get('cost_per_query', metadata.get('costo_per_query'))}")
    print()


def main():
    if len(sys.argv) != 2:
        print("Usage: python main.py <domain>")
        sys.exit(1)

    domain = sys.argv[1]
    all_results = []

    # --- crt.sh: subdomain enumeration ---
    print_source_info(CRTSH_METADATA)
    crtsh_results = cerca_subdomains(domain)
    all_results.extend(crtsh_results)

    for r in crtsh_results:
        value = r["valore"]
        tag = "IP" if is_valid_ip(value) else "DOMAIN"
        print(f"    [{tag}] {value}")

    # --- VirusTotal: domain reputation ---
    print()
    print_source_info(VT_METADATA)
    vt_results = check_domain(domain)
    all_results.extend(vt_results)

    # --- urlscan.io: existing scans (IPs, pages) ---
    print()
    print_source_info(URLSCAN_METADATA)
    urlscan_results = search_domain(domain)
    all_results.extend(urlscan_results)

    for r in urlscan_results:
        print(f"    [{r['tipo'].upper()}] {r['valore']}")

    if not all_results:
        print("[!] No results collected from any source.")
        return

    # Example: defang the target domain for a shareable report line
    print(f"\n[*] Defanged target for reporting: {defang(f'https://{domain}')}")

    # Save everything to a single JSON file
    output_file = f"output/{domain.replace('.', '_')}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"[*] Results saved to {output_file}")


if __name__ == "__main__":
    main()
