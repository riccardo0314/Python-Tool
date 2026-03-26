while True:
    link = input("""type ESC to quit
Insert malicious link:   """)
    if link == "ESC" or link == "esc":
        print ('Programme closed')
        break
    else:
        print(link.replace("http", "hxxp").replace (".", "[.]" ). replace("https" , "hxxps"))
    
    
