# utils/url_defanger.py
def defang(url: str) -> str:
    return url.replace("https", "hxxps").replace("http", "hxxp").replace(".", "[.]")


if __name__ == "__main__":
    # Modalità standalone
    while True:
        link = input("type ESC to quit\nInsert malicious link:   ")
        if link.upper() == "ESC":
            print('Programme closed')
            break
        print(defang(link))
    
