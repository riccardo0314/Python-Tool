import ipaddress
print("""To kill the programm, type ESC anytime
...""")
while True:
    try:
        ip_input = input('Insert IP to validate:   ')
        if ip_input == 'ESC' or ip_input == 'esc':
            break
        elif ip_input != 'ESC' or ip_input != 'esc':
            ipaddress.ip_address(ip_input)
            print('IP Validated')
    except ValueError:
        print('IP Not Validated, retry...')
    
