# securecode1
PoC for VulnHub machine Securecode1

Vulnerable machine author: sud0root
Link to vulernable VM: https://www.vulnhub.com/entry/securecode-1,651/

start a NetCat listener with:
 nc -nlvp <IP> <port>

usage: python3 poc.py -t <target> -p <password to set> -i <attacker IP> -pt <attacker port>
 
 Explaination of script below contains spoilers, read/use only if stuck.
  
This script leverages boolean based blind SQL Injection to enumerate the adminstrative user on the "HackShop" web application on the VulnHub machine Securecode1. It then requests a password reset token for the adminstrative user. 
  
The blind SQLi is then used again to enumerate the token. The token is then passed to reset the administrative user account's password with the password passed with the -p flag.
  
The script then logs in and pulls the first flag.
 
A php reverse shell is then uploaded and executed connecting to the IP and port suppled by the -i and -pt options.
  

