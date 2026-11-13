"""
main.py

Entry point of the tool. Runs all available modules against a target
domain, tags results, and saves everything to a JSON file.
"""

import argparse
import json

from modules.crtsh import cerca_subdomains, METADATA as CRTSH_METADATA
from modules.virustotal import check_domain, METADATA as VT_METADATA
from modules.urlscan import (
    search_domain,
    submit_and_scan,
    METADATA as URLSCAN_METADATA,
    SUBMIT_METADATA as URLSCAN_SUBMIT_METADATA,
)
from modules.shodan import enrich_ips, METADATA as SHODAN_METADATA
from utils.ip_validator import is_valid_ip
from utils.url_defanger import defang
from ai.debate import run_debate


def print_source_info(metadata: dict) -> None:
    """Print a short summary of a source before querying it."""
    print(f"[*] Source: {metadata['name'] if 'name' in metadata else metadata.get('nome')}")
    print(f"    Cost per query: {metadata.get('cost_per_query', metadata.get('costo_per_query'))}")
    print()


def parse_args():
    parser = argparse.ArgumentParser(description="OSINT/CTI recon aggregator")
    parser.add_argument("domain", help="target domain, e.g. example.com")
    parser.add_argument(
        "--submit",
        action="store_true",
        help="also run an ACTIVE urlscan.io scan of https://<domain> "
             "(creates a new unlisted scan; off by default)",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    domain = args.domain
    all_results = []

    # --- crt.sh: subdomain enumeration ---
    print_source_info(CRTSH_METADATA)
    crtsh_results = cerca_subdomains(domain)
    all_results.extend(crtsh_results)

    # Big targets return hundreds of names: print a short preview only
    # (the full list goes to the JSON file). Names that are not subdomains
    # of the target are always shown, since they may be look-alikes.
    outside = [r for r in crtsh_results if not r.get("same_domain", True)]
    inside = [r for r in crtsh_results if r.get("same_domain", True)]
    preview = 20

    print(f"[*] crt.sh: {len(inside)} subdomain(s), {len(outside)} other name(s)")
    for r in outside:
        print(f"    [NOT A SUBDOMAIN] {r['valore']}")
    for r in inside[:preview]:
        value = r["valore"]
        tag = "IP" if is_valid_ip(value) else "DOMAIN"
        print(f"    [{tag}] {value}")
    if len(inside) > preview:
        print(f"    ... and {len(inside) - preview} more (full list in the JSON output)")

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
        tag = "same-domain" if r.get("same_domain") else "unrelated/referencing"
        print(f"    [{r['tipo'].upper()}] {r['valore']}  ({tag})")

    # --- urlscan.io: active scan (only when explicitly requested) ---
    if args.submit:
        print()
        print_source_info(URLSCAN_SUBMIT_METADATA)
        submit_results = submit_and_scan(f"https://{domain}", target_domain=domain)
        all_results.extend(submit_results)

        for r in submit_results:
            if "same_domain" in r:
                tag = "same-domain" if r["same_domain"] else "unrelated/referencing"
                print(f"    [{r['tipo'].upper()}] {r['valore']}  ({tag})")
            else:
                print(f"    [{r['tipo'].upper()}] {r['valore']}")

    # --- Shodan: enrich the target's own IPs ---
    # Only IPs marked as the target's (same_domain=True): same-domain
    # urlscan search results, and the IP that served the page in an
    # active scan. Unrelated and third-party IPs are skipped.
    target_ips = [
        r["valore"] for r in all_results
        if r["tipo"] == "ip" and r.get("same_domain") is True
    ]
    print()
    print_source_info(SHODAN_METADATA)
    shodan_results = enrich_ips(target_ips)
    all_results.extend(shodan_results)

    if not all_results:
        print("[!] No results collected from any source.")
        return

    # Example: defang the target domain for a shareable report line
    print(f"\n[*] Defanged target for reporting: {defang(f'https://{domain}')}")

    # Save raw results to a JSON file
    output_file = f"output/{domain.replace('.', '_')}.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)
    print(f"[*] Results saved to {output_file}")

    # --- AI correlation layer: two-model debate ---
    print("\n[*] Starting AI correlation (two-model debate)...\n")
    debate_result = run_debate(all_results)

    if debate_result["final_report"]:
        print("\n[*] Final AI report:\n")
        print(debate_result["final_report"])

        report_file = f"output/{domain.replace('.', '_')}_ai_report.json"
        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(debate_result, f, indent=2, ensure_ascii=False)
        print(f"\n[*] Full debate + report saved to {report_file}")


if __name__ == "__main__":
    main()
