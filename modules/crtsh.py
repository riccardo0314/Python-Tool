"""
modules/crtsh.py

Modulo di raccolta dati da crt.sh (Certificate Transparency logs).
Trova i subdomain associati a un dominio.

Ogni modulo di questo progetto espone:
  - METADATA: un dizionario che descrive la fonte (cosa accetta in input,
    cosa produce in output, costo, affidabilità stimata) — così il resto
    del sistema può decidere QUANDO conviene usare questa fonte, invece
    di trattarla come una black box intercambiabile con le altre.
  - una funzione principale che fa il lavoro vero e proprio.
"""

import json
import time
import requests


# ---------------------------------------------------------------------------
# METADATA: descrive la fonte stessa, non i dati che restituisce.
# Idea presa dal concetto di "wrapper standardizzato" di ARGUS (Task 1):
# invece di trattare ogni fonte come una scatola nera intercambiabile,
# dichiariamo esplicitamente per cosa è brava e a quali condizioni.
# ---------------------------------------------------------------------------
METADATA = {
    "nome": "crt.sh",
    "descrizione": "Certificate Transparency logs — trova subdomain a partire dai certificati SSL emessi",
    "input_accettati": ["domain"],
    "output_prodotti": ["domain", "subdomain"],
    "richiede_api_key": False,
    "costo_per_query": 0,          # gratuita
    "rate_limit_noto": True,       # crt.sh va spesso in timeout se martellato
    "affidabilità_stimata": {
        # affidabilità non è un numero assoluto: dipende dal contesto,
        # esattamente come sottolineava ARGUS. Per ora è una stima
        # qualitativa scritta a mano; in futuro potrà essere calcolata
        # automaticamente da un micro-benchmark (vedi DEVLOG).
        "subdomain_enumeration": "alta",
        "domini_appena_registrati": "bassa",  # i certificati impiegano tempo ad apparire nei log
    },
}


def cerca_subdomains(dominio: str, tentativi: int = 3, attesa_secondi: int = 5) -> list[dict]:
    """
    Interroga crt.sh e restituisce una lista di entità trovate,
    nel formato {"tipo": ..., "valore": ..., "fonte": ...}.

    crt.sh è noto per essere instabile (502/503 frequenti sotto carico),
    quindi riprova automaticamente prima di arrendersi.
    """
    url = "https://crt.sh/"
    params = {
        "q": f"%.{dominio}",
        "output": "json",
    }

    print(f"[*] Interrogo crt.sh per: {dominio}")

    dati_grezzi = None

    for tentativo in range(1, tentativi + 1):
        try:
            risposta = requests.get(url, params=params, timeout=30)
            risposta.raise_for_status()
            dati_grezzi = risposta.json()
            break  # richiesta riuscita, usciamo dal ciclo di retry

        except requests.exceptions.HTTPError as e:
            # Errori tipo 502/503: probabilmente crt.sh è sovraccarico,
            # ha senso riprovare dopo una pausa.
            print(f"[!] Tentativo {tentativo}/{tentativi} fallito: {e}")
            if tentativo < tentativi:
                print(f"    Riprovo tra {attesa_secondi}s...")
                time.sleep(attesa_secondi)

        except requests.exceptions.RequestException as e:
            # Errori di rete generici (no connessione, timeout, ecc.):
            # non ha molto senso riprovare all'infinito, ma un retry
            # comunque non fa male.
            print(f"[!] Tentativo {tentativo}/{tentativi} fallito: {e}")
            if tentativo < tentativi:
                time.sleep(attesa_secondi)

        except json.JSONDecodeError:
            print(f"[!] Tentativo {tentativo}/{tentativi}: risposta non è JSON valido.")
            if tentativo < tentativi:
                time.sleep(attesa_secondi)

    if dati_grezzi is None:
        print(f"[!] crt.sh non ha risposto correttamente dopo {tentativi} tentativi. Riprova più tardi.")
        return []

    subdomains_unici = set()
    for certificato in dati_grezzi:
        nomi_grezzi = certificato.get("name_value", "")
        for singolo_nome in nomi_grezzi.split("\n"):
            singolo_nome = singolo_nome.strip().lower()
            if singolo_nome and not singolo_nome.startswith("*."):
                subdomains_unici.add(singolo_nome)

    risultati = [
        {"tipo": "domain", "valore": sub, "fonte": METADATA["nome"]}
        for sub in sorted(subdomains_unici)
    ]

    return risultati


if __name__ == "__main__":
    # Modalità standalone: comportamento equivalente allo script originale
    import sys
    import time

    if len(sys.argv) != 2:
        print("Uso: python modules/crtsh.py <dominio>")
        sys.exit(1)

    target = sys.argv[1]
    inizio = time.time()
    risultati = cerca_subdomains(target)
    durata = time.time() - inizio

    print(f"[*] Trovati {len(risultati)} subdomain in {durata:.1f}s")
    for r in risultati:
        print(f"    - {r['valore']}")
