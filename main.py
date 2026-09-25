"""
main.py

Punto di ingresso del tool. Per ora è solo una demo che mostra come
i pezzi si collegano: importa il modulo crt.sh e le utility, ed esegue
una ricerca su un dominio passato da riga di comando.
"""

import sys
import json

from modules.crtsh import cerca_subdomains, METADATA as CRTSH_METADATA
from utils.ip_validator import is_valid_ip
from utils.url_defanger import defang


def main():
    if len(sys.argv) != 2:
        print("Uso: python main.py <dominio>")
        sys.exit(1)

    dominio = sys.argv[1]

    # Mostriamo i metadati della fonte prima di interrogarla:
    # è il pezzo ispirato ad ARGUS di cui parlavamo — sapere PRIMA
    # cosa aspettarsi da questa fonte, non solo dopo.
    print(f"[*] Fonte: {CRTSH_METADATA['nome']}")
    print(f"    Affidabilità per subdomain enumeration: "
          f"{CRTSH_METADATA['affidabilità_stimata']['subdomain_enumeration']}")
    print(f"    Costo per query: {CRTSH_METADATA['costo_per_query']}")
    print()

    # Raccolta dati vera e propria
    risultati = cerca_subdomains(dominio)

    if not risultati:
        print("[!] Nessun risultato trovato.")
        return

    print(f"[*] Trovati {len(risultati)} risultati:\n")

    for r in risultati:
        valore = r["valore"]

        # Esempio di uso di is_valid_ip: quasi tutti i risultati di crt.sh
        # sono domini, non IP, quindi questo sarà quasi sempre False —
        # ma dimostra come un modulo può usare l'utility per instradare
        # il dato in modo diverso a seconda del tipo (IP vs dominio).
        if is_valid_ip(valore):
            print(f"    [IP]     {valore}")
        else:
            print(f"    [DOMAIN] {valore}")

    # Esempio di uso di defang: prendiamo il primo risultato e mostriamo
    # come apparirebbe "disinnescato" in un report condivisibile
    primo = risultati[0]["valore"]
    url_finto = f"https://{primo}"
    print(f"\n[*] Esempio di URL defanged per report: {defang(url_finto)}")

    # Salvataggio risultati
    nome_file = f"output/crtsh_{dominio.replace('.', '_')}.json"
    with open(nome_file, "w", encoding="utf-8") as f:
        json.dump(risultati, f, indent=2, ensure_ascii=False)
    print(f"[*] Risultati salvati in {nome_file}")


if __name__ == "__main__":
    main()
