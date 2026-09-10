import ipaddress

def is_valid_ip(ip_input: str) -> bool:
    """Restituisce True se la stringa è un IP valido (v4 o v6)."""
    try:
        ipaddress.ip_address(ip_input)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    # Modalità standalone
    print("To kill the program, type ESC anytime")
    while True:
        ip_input = input('Insert IP to validate:   ')
        if ip_input.upper() == 'ESC':
            break
        if is_valid_ip(ip_input):
            print('IP Validated')
        else:
            print('IP Not Validated, retry...')
