import socket
import os,sys
import socket
from googlesearch import search
import vulners
import json
import time
import socket
import base64
import requests

def main():
	os.system("clear")
	print("""
 _____         _                 
/  __ \       | |                
| /  \/ _   _ | |__    ___  _ __ 
| |    | | | || '_ \  / _ \| '__|
| \__/\| |_| || |_) ||  __/| |   
 \____/ \__, ||_.__/  \___||_|   
         __/ |Security UP                   
        |___/                    

[#] Blog: https://goo.gl/CsGj8Q
[#] Página: https://goo.gl/gaHCY2 
[#] YouTube: https://goo.gl/Moqtd9
[#] Autor: Felipe Santos - (Tr4yfx)

		""")
main()

def ps():
	shell2 = str(input("[*] Entre com o IP: "))
	s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
	proto = { 
			  21: '21 - FTP',
              22: '22 - SSH',
              23: '23 - TELNET',
              25: '25 - SMTP',
              26: '26 - RSFTP',
              53: '53 - DOMAIN',
              80: '80 - HTTP',
              106: '106 - POP3PW',
              110: '110 - POP3',
              113: '113 - IDENT',
              139: '139 - NETBIOS-SSN',
              143: '143 - IMAP',
              256: '256 - FW1-SECUREREMOTE',
              443: '443 - HTTPS',
              465: '465 - SMTPS',
              554: '554 - RTSP',
              587: '587 - SMTP',
              993: '993 - IMAPS',
              995: '995 - POP3S',
              1720: '1720 - H323Q931',
              1723: '1723 - PPTP',
              2022: '2022 - DOWN',
              2525: '2525 - MS-V-WORLDS',
              3306: '3306 - MYSQL',
              5222: '5222 - XMPP-CLIENT',
              8080: '8080 - HTTP-PROXY',
              9090: '9090 - ZEUS-ADMIN',
              8443: '8443 - HTTPS-ALT',
              9102: '9102 - JETDIRECT'
}

	for x in proto:
		c = s.connect_ex((shell2,x))
		if(c==0):
			time.sleep(1)
			print("\n[*] STATUS: {} [OPEN]".format(proto[x]))
		else:
			print("\n[*] STATUS: {} [CLOSE]".format(proto[x]))

def cms():
    shell2 = str(input("[*] Entre com o site: "))
    cmss = {
    "/user/login/":"Drupal!",
    "/administrator/index.php":"Joomla!",
    "/wp-login.php":"WordPress!",
    "/admin/login.php":"OpenCart!"
}

    time.sleep(1)
    try:
        print("[*] Site: {}".format(shell2))
        test = requests.get(shell2)
        if(test.status_code==200):
	        print("[*] Status: 200 OK")
	        print("[*] Procurando CMS...")
	        for x in cmss:
	    	    r = requests.get(shell2+x)
	    	    if(r.status_code==200):
	    	        print("[*] CMS Encontrado!\n[*] CMS: "+cmss[x])
        else:
           time.sleep(1)
           print("[*] Problemas com a conexão, talvez o site esteja OFF")
    except:
    	print("[*] Problemas com a conexão, talvez o site esteja OFF")
def ds():
	shell2 = str(input("[*] Entre com a dork: "))
	time.sleep(1)
	print("[*] Iniciando busca...")
	time.sleep(1)
	for x in search(shell2,stop=20):
		print(">> {}".format(x))

def vuln():
    shell2 = str(input("[*] Entre com sua busca: "))
    api = vulners.Vulners()
    print("[*] Iniciando busca...")
    busca = api.search(shell2,limit=10)
    for x in busca:
        time.sleep(1)
        print("\n[*] Title: {}".format(x['title']))
        print("[*] ID: {}".format(x['id']))
        print("[*] Href: {}".format(x['href']))


def wp():
    global json
    shell2 = str(input("[*] Entre com o site: "))
    time.sleep(1)
    print("[*] Certificando o WordPress...")
    test = requests.get(shell2+"/wp-login.php")
    if(test.status_code==200):
        var_json = "/wp-json/wp/v2/users"
        r = requests.get(shell2+var_json)
        if(r.status_code==200):
            print("[*] Campo jSON válido, procurando usúarios...")
            time.sleep(1)
            code = r.content.decode("utf-8")
            json = json.loads(code)
            for x in json[0:20]:
                time.sleep(1)
                print("\n[*] User: {}\n[*] ID: {}".format(x['name'],x['id']))
        else:
        	print("[*] Não foi possivel enumerar os usúarios.")
        	sys.exit(0)
    else:
    	print("[*] Problemas com a conexão, talvez o site esteja OFF")
    	sys.exit(0)


def b64deco():
	shell2 = str(input("[*] Entre com a hash: "))
	var_base64 = base64.b64decode(shell2.encode("utf-8"))
	print("[*] Decrypt: {}".format(var_base64.decode("utf-8")))
def b64enco():
	shell2 = str(input("[*] Entre com o texto: "))
	var_base64 = base64.b64encode(shell2.encode("utf-8"))
	print("[*] Encrypt: {}".format(var_base64.decode("utf-8")))

def media():
	shell2 = str(input("[*] Entre com o site: "))
	url = "/index.php?option=com_media&view=images&tmpl=component&e_name=jform_articletext&asset=com_content&author="
	r = requests.get(shell2+url)
	if(r.status_code==200):
		print("\n[*] Site: {}\n[*] Status: {}".format(shell2,"Vulnerável."))
	else:
		print("\n[*] Site: {}\n[*] Status: {}".format(shell2,"Não vulnerável."))

def fabrik():
	shell2 = str(input("[*] Entre com o site: "))
	url = "/index.php?option=com_fabrik&view=import&f iletype=csv&table=1"
	r = requests.get(shell2+url)
	if(r.status_code==200):
		print("\n[*] Site: {}\n[*] Status: {}".format(shell2,"Vulnerável."))
	else:
		print("\n[*] Site: {}\n[*] Status: {}".format(shell2,"Não vulnerável."))

def href():
    shell2 = str(input("[*] Entre com o site: "))
    var_ok = requests.get(shell2)
    if(var_ok.status_code==200):
	    r = requests.get("https://api.hackertarget.com/pagelinks/?q={}".format(shell2))
	    time.sleep(1)
	    print("Iniciando...")
	    print(r.text)
    else:
        print("[*] Site inválido.")
        sys.exit(0)

def dns():
	shell2 = str(input("[*] Entre com o site [SEM HTTP/HTTPS]: "))
	r = requests.get("https://api.hackertarget.com/dnslookup?q={}".format(shell2))
	print(r.text)

menu = """
[1] - Port Scan
[2] - CMS Detect
[3] - Dork Scanner
[4] - Exploit Search
[5] - WordPress Enum
[6] - Base64 Encode
[7] - Base64 Decode
[8] - Joomla Scanner COM_MEDIA
[9] - Joomla Scanner COM_FABRIK
[10] - Extract Page Links
[11] - DNS Lookup
"""
print(menu)
shell = int(input("cybersec>>"))
if(shell==1):
	ps()
if(shell==2):
	cms()
if(shell==3):
	ds()
if(shell==4):
	vuln()
if(shell==5):
	wp()
if(shell==6):
	b64enco()
if(shell==7):
	b64deco()
if(shell==8):
	media()
if(shell==9):
	fabrik()
if(shell==10):
	href()
if(shell==11):
	dns()
