"""
utils/url_defanger.py

"Disinnesca" un URL sospetto sostituendo http(s) e i punti, così può
essere condiviso o mostrato in un report senza rischio di click
accidentale o di attivare link automatici.
"""


def defang(url: str) -> str:
    """Rende un URL 'sicuro' da condividere sostituendo http(s) e i punti."""
    return url.replace("https", "hxxps").replace("http", "hxxp").replace(".", "[.]")


if __name__ == "__main__":
    # Modalità standalone: comportamento invariato rispetto allo script originale
    while True:
        link = input("type ESC to quit\nInsert malicious link:   ")
        if link.upper() == "ESC":
            print('Programme closed')
            break
        print(defang(link))
