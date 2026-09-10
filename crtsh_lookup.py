"""
crtsh_lookup.py

Script base per interrogare crt.sh (Certificate Transparency logs)
e trovare i subdomain associati a un dominio, tramite la loro API.

Uso:
    python crtsh_lookup.py example.com
"""

import sys
import json
import time
import requests


def search_subdomains(domain: str) -> list[dict]:
    """
    Interroga crt.sh e restituisce una lista di entità trovate,
    nel formato {"tipo": ..., "valore": ..., "fonte": ...}.
    """
    url = "https://crt.sh/"
    params = {
        "q": f"%.{domain}",  # % = wildcard, cerca tutti i sottodomini
        "output": "json",
    }

    print(f"[*] Interrogo crt.sh per: {domain}")

    try:
        # crt.sh a volte è lento o instabile, diamo un timeout generoso
        answer = requests.get(url, params=params, timeout=30)
        answer.raise_for_status()  # solleva errore se status != 200
    except requests.exceptions.RequestException as e:
        print(f"[!] Error in the request: {e}")
        return []

    try:
        raw_data = answer.json()
    except json.JSONDecodeError:
        print("[!] crt.sh did not return valid JSON (may be overloaded, try again).")
        return []

    # Ogni "certificato" trovato può contenere più nomi (name_value),
    # separati da newline. Li estraiamo e deduplichiamo.
    subdomains_unique = set()
    for certificate in raw_data:
        names = certificate.get("name_value", "")
        for name in names.split("\n"):
            name = name.strip().lower()
            if name and not name.startswith("*."):  # ignoriamo i wildcard puri
                subdomains_unique.add(name)

    # Convertiamo nel formato "comune" che useremo per tutti i moduli futuri
    results = [
        {"type": "domain", "value": sub, "source": "crt.sh"}
        for sub in sorted(subdomains_unique)
    ]

    return results


def save_results(results: list[dict], name_file: str) -> None:
    with open(name_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)
    print(f"[*] Saved {len(results)} results in {name_file}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Use: python crtsh_lookup.py <domain>")
        print("Example: python crtsh_lookup.py example.com")
        sys.exit(1)

    target = sys.argv[1]

    start = time.time()
    results = search_subdomains(target)
    duration = time.time() - start

    print(f"[*] Found {len(results)} subdomain in {duration:.1f}s")
    
    for r in results:
        print(f"    - {r['value']}")

    if results:
        name_file = f"crtsh_{target.replace('.', '_')}.json"
        save_results(results, name_file)
